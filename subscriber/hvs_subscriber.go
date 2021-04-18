package subscriber

import (
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

	conn, err := nats.Connect(subscriber.cfg.Nats.URL, nats.ErrorHandler(func(nc *nats.Conn, s *nats.Subscription, err error) {
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
func (subscriber *hvsSubscriberImpl) createSubject(cmd string) string {
	subject := fmt.Sprintf("trust-agent.%s.%s", cmd, subscriber.hardwareUUID.String())
	log.Printf("Subscribing to %q", subject)
	return subject
}
