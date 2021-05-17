package subscriber

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"intel/isecl/go-trust-agent/v3/config"
	"intel/isecl/go-trust-agent/v3/constants"
	"intel/isecl/go-trust-agent/v3/resource"

	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type HVSSubscriber interface {
	Start() error
	Stop() error
	HandleQuoteRequest(quoteRequest *taModel.TpmQuoteRequest) (*taModel.TpmQuoteResponse, error)
	HandleHostInfoRequest() (*taModel.HostInfo, error)
	HandleAikRequest() ([]byte, error)
	// TODO: other handlers (like asset tags) here...
}

func NewHVSSubsriber(cfg *config.TrustAgentConfiguration, hardwareUUID uuid.UUID) HVSSubscriber {

	return &hvsSubscriberImpl{
		cfg:          cfg,
		hardwareUUID: hardwareUUID,
	}

}

type hvsSubscriberImpl struct {
	natsConnection *nats.EncodedConn
	hardwareUUID   uuid.UUID
	cfg            *config.TrustAgentConfiguration
}

func (subscriber *hvsSubscriberImpl) Start() error {

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Read in the cert file
	log.Printf("Loading ca.pem")
	certs, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", "ca.pem", err)
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("No certs appended, using system certs only")
	}

	// Trust the augmented cert pool in our client
	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            rootCAs,
	}

	conn, err := nats.Connect(subscriber.cfg.Nats.URL,
		//nats.RootCAs("ca.pem"),
		nats.Secure(&tlsConfig),
		nats.UserCredentials("trust-agent.creds"),
		nats.ErrorHandler(func(nc *nats.Conn, s *nats.Subscription, err error) {
			if s != nil {
				log.Printf("ERROR: NATS: Could not process subscription for subject %q: %v", s.Subject, err)
			} else {
				log.Printf("ERROR: NATS: %v", err)
			}
		}))

	if err != nil {
		return fmt.Errorf("Failed to connect to url %q: %+v", subscriber.cfg.Nats.URL, err)
	}

	subscriber.natsConnection, err = nats.NewEncodedConn(conn, "json")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Successfully connected to %q", subscriber.cfg.Nats.URL)

	defer subscriber.natsConnection.Close()

	// test user permissions...
	// 2021/05/01 07:49:38 Loading ca.pem
	// 2021/05/01 07:49:38 Successfully connected to "nats://10.80.245.183:4222"
	// 2021/05/01 07:49:38 Subscribing to "trust-agent.8032632b-8fa4-e811-906e-00163566263e.quote-request"
	// 2021/05/01 07:49:38 Subscribing to "trust-agent.8032632b-8fa4-e811-906e-00163566263e.host-info-request"
	// 2021/05/01 07:49:38 Subscribing to "trust-agent.8032632b-8fa4-e811-906e-00163566263e.aik-request"
	// 2021/05/01 07:49:38 Running Trust-Agent 8032632b-8fa4-e811-906e-00163566263e...
	// 2021/05/01 07:49:38 ERROR: NATS: nats: Permissions Violation for Subscription to "trust-agent.other-host.quote-request" using queue "quote-request-queue"
	// 2021/05/01 07:49:48 Running Trust-Agent 8032632b-8fa4-e811-906e-00163566263e...
	//
	// nats-server...
	// [24538] 2021/05/01 07:52:22.155962 [ERR] 10.105.167.153:57284 - cid:4 - "v1.10.0:go" - Subscription Violation - JWT User "UDHN62YHQ2H6MWTBRIGWRFHDRYORHHNQX54FBO724GUACRJCZLUVQJKR", Subject "trust-agent.other-host.quote-request", Queue: "quote-request-queue", SID 1
	//
	// subscriber.natsConnection.QueueSubscribe("trust-agent.other-host.quote-request", "quote-request-queue", func(subject string, reply string, quoteRequest *taModel.TpmQuoteRequest) {
	// 	log.Printf("Received other-host request: %+v", quoteRequest)
	// })

	// subscribe to quote-request messages
	subscriber.natsConnection.QueueSubscribe(subscriber.createSubject("quote-request"), "quote-request-queue", func(subject string, reply string, quoteRequest *taModel.TpmQuoteRequest) {
		quoteResponse, err := subscriber.HandleQuoteRequest(quoteRequest)
		if err != nil {
			log.Printf("Failed to handle quote-request: %+v", err)
		}

		subscriber.natsConnection.Publish(reply, quoteResponse)
	})

	// subscribe to host-info request messages
	subscriber.natsConnection.Subscribe(subscriber.createSubject("host-info-request"), func(m *nats.Msg) {
		hostInfo, err := subscriber.HandleHostInfoRequest()
		if err != nil {
			log.Printf("Failed to handle quote-request: %+v", err)
		}

		subscriber.natsConnection.Publish(m.Reply, hostInfo)
	})

	// subscribe to host-info request messages
	subscriber.natsConnection.Subscribe(subscriber.createSubject("aik-request"), func(m *nats.Msg) {
		hostInfo, err := subscriber.HandleAikRequest()
		if err != nil {
			log.Printf("Failed to handle aik-request: %+v", err)
		}

		subscriber.natsConnection.Publish(m.Reply, hostInfo)
	})

	for {
		log.Printf("Running Trust-Agent %s...", subscriber.hardwareUUID.String())
		time.Sleep(10 * time.Second)
	}

	return nil
}

func (subscriber *hvsSubscriberImpl) Stop() error {
	return fmt.Errorf("Not Implemented")
}

func (subscriber *hvsSubscriberImpl) HandleQuoteRequest(quoteRequest *taModel.TpmQuoteRequest) (*taModel.TpmQuoteResponse, error) {
	log.Printf("Received quote-request: %+v", quoteRequest)

	ctx, err := resource.NewTpmQuoteContext(subscriber.cfg)
	if err != nil {
		return nil, fmt.Errorf("Error creating quote context: %+v", err)
	}

	defer ctx.Close()

	tpmQuoteResponse, err := ctx.CreateTpmQuoteResponse(quoteRequest)
	if err != nil {
		return nil, fmt.Errorf("Error collecting tpm quote: %+v", err)
	}

	return tpmQuoteResponse, nil
}

func (subscriber *hvsSubscriberImpl) HandleHostInfoRequest() (*taModel.HostInfo, error) {
	log.Printf("Received host-info-request")
	var hostInfo taModel.HostInfo

	hostInfoJSON, err := ioutil.ReadFile(constants.PlatformInfoFilePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(hostInfoJSON, &hostInfo)
	if err != nil {
		return nil, err
	}

	return &hostInfo, nil
}

func (subscriber *hvsSubscriberImpl) HandleAikRequest() ([]byte, error) {
	log.Printf("Received aik-request")
	var aik []byte

	aik, err := ioutil.ReadFile(constants.AikCert)
	if err != nil {
		return nil, err
	}

	aikDer, _ := pem.Decode(aik)
	_, err = x509.ParseCertificate(aikDer.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error parsing AIK certificate file: %+v", err)
	}

	return aikDer.Bytes, nil
}

// returns a subject in the format "trust-agent.<hardware uuid>.<cmd>"
func (subscriber *hvsSubscriberImpl) createSubject(request string) string {
	subject := fmt.Sprintf("trust-agent.%s.%s", subscriber.hardwareUUID.String(), request)
	log.Printf("Subscribing to %q", subject)
	return subject
}
