/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"context"
	"crypto/tls"
	"fmt"
	"intel/isecl/go-trust-agent/v3/config"
	"intel/isecl/go-trust-agent/v3/constants"
	"intel/isecl/lib/tpmprovider/v3"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/auth"
	commContext "github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/middleware"
	ct "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/pkg/errors"
)

const (
	getAIKPerm             = "aik:retrieve"
	getAIKCAPerm           = "aik_ca:retrieve"
	getBindingKeyPerm      = "binding_key:retrieve"
	getDAAPerm             = "daa:retrieve"
	getHostInfoPerm        = "host_info:retrieve"
	postDeployManifestPerm = "deploy_manifest:create"
	postAppMeasurementPerm = "application_measurement:create"
	postDeployTagPerm      = "deploy_tag:create"
	postQuotePerm          = "quote:create"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type TrustAgentService struct {
	port   int
	router *mux.Router
}

type endpointError struct {
	Message    string
	StatusCode int
}

type privilegeError struct {
	StatusCode int
	Message    string
}

func (e privilegeError) Error() string {
	log.Trace("resource/service:Error() Entering")
	defer log.Trace("resource/service:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func (e endpointError) Error() string {
	log.Trace("resource/service:Error() Entering")
	defer log.Trace("resource/service:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

var cacheTime, _ = time.ParseDuration(constants.JWTCertsCacheTime)
var seclog = commLog.GetSecurityLogger()

func CreateTrustAgentService(config *config.TrustAgentConfiguration, tpmFactory tpmprovider.TpmFactory) (*TrustAgentService, error) {
	log.Trace("resource/service:CreateTrustAgentService() Entering")
	defer log.Trace("resource/service:CreateTrustAgentService() Leaving")

	if config.WebService.Port == 0 {
		return nil, errors.New("Port cannot be zero")
	}

	trustAgentService := TrustAgentService{
		port: config.WebService.Port,
	}

	// Register routes...
	trustAgentService.router = mux.NewRouter()
	// ISECL-8715 - Prevent potential open redirects to external URLs
	trustAgentService.router.SkipClean(true)

	noAuthRouter := trustAgentService.router.PathPrefix("/v2/").Subrouter()
	noAuthRouter.HandleFunc("/version", errorHandler(getVersion())).Methods("GET")
	authRouter := trustAgentService.router.PathPrefix("/v2/").Subrouter()
	authRouter.Use(middleware.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.TrustedCaCertsDir, fnGetJwtCerts, cacheTime))

	// use permission-based access control for webservices
	authRouter.HandleFunc("/aik", errorHandler(requiresPermission(getAik(), []string{getAIKPerm}))).Methods("GET")
	authRouter.HandleFunc("/host", errorHandler(requiresPermission(getPlatformInfo(), []string{getHostInfoPerm}))).Methods("GET")
	authRouter.HandleFunc("/tpm/quote", errorHandler(requiresPermission(getTpmQuote(config, tpmFactory), []string{postQuotePerm}))).Methods("POST")
	authRouter.HandleFunc("/binding-key-certificate", errorHandler(requiresPermission(getBindingKeyCertificate(), []string{getBindingKeyPerm}))).Methods("GET")
	authRouter.HandleFunc("/tag", errorHandler(requiresPermission(setAssetTag(config, tpmFactory), []string{postDeployTagPerm}))).Methods("POST")
	authRouter.HandleFunc("/host/application-measurement", errorHandler(requiresPermission(getApplicationMeasurement(), []string{postAppMeasurementPerm}))).Methods("POST")
	authRouter.HandleFunc("/deploy/manifest", errorHandler(requiresPermission(deployManifest(), []string{postDeployManifestPerm}))).Methods("POST")

	return &trustAgentService, nil
}

func (service *TrustAgentService) Start() error {
	log.Trace("resource/service:Start() Entering")
	defer log.Trace("resource/service:Start() Leaving")

	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGKILL)

	httpWriter := os.Stderr
	if httpLogFile, err := os.OpenFile(constants.HttpLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
		secLog.WithError(err).Errorf("resource/service:Start() %s Failed to open http log file: %s\n", message.AppRuntimeErr, err.Error())
		log.Tracef("resource/service:Start() %+v", err)
	} else {
		defer func() {
			derr := httpLogFile.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing file")
			}
		}()
		httpWriter = httpLogFile
	}

	cfg, err := config.NewConfigFromYaml(constants.ConfigFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing configuration file %v \n", err)
		os.Exit(1)
	}

	httpLog := stdlog.New(httpWriter, "", 0)
	h := &http.Server{
		Addr:              fmt.Sprintf(":%d", service.port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(os.Stderr, service.router)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsconfig,
		ReadTimeout:       cfg.WebService.ReadTimeout,
		ReadHeaderTimeout: cfg.WebService.ReadHeaderTimeout,
		WriteTimeout:      cfg.WebService.WriteTimeout,
		IdleTimeout:       cfg.WebService.IdleTimeout,
		MaxHeaderBytes:    cfg.WebService.MaxHeaderBytes,
	}

	// dispatch web server go routine
	go func() {
		if err := h.ListenAndServeTLS(constants.TLSCertFilePath, constants.TLSKeyFilePath); err != nil {
			secLog.Errorf("tasks/service:Start() %s", message.TLSConnectFailed)
			secLog.WithError(err).Fatalf("server:startServer() Failed to start HTTPS server: %s\n", err.Error())
			log.Tracef("%+v", err)
			stop <- syscall.SIGTERM
		}
	}()
	secLog.Info(message.ServiceStart)
	secLog.Infof("TrustAgent service is running: %d", service.port)

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to gracefully shutdown webserver: %v\n", err)
		log.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	secLog.Info(message.ServiceStop)
	return nil
}

// requiresPermission checks the JWT in the request for the required access permissions
func requiresPermission(eh endpointHandler, permissionNames []string) endpointHandler {
	log.Trace("resource/service:requiresPermission() Entering")
	defer log.Trace("resource/service:requiresPermission() Leaving")
	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := commContext.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			_, writeErr := w.Write([]byte("Could not get user roles from http context"))
			if writeErr != nil {
				log.WithError(writeErr).Error("resource/service:requiresPermission() Error while writing response")
			}
			secLog.Errorf("resource/service:requiresPermission() %s Roles: %v | Context: %v", message.AuthenticationFailed, permissionNames, r.Context())
			return errors.Wrap(err, "resource/service:requiresPermission() Could not get user roles from http context")
		}
		reqPermissions := ct.PermissionInfo{Service: constants.AASServiceName, Rules: permissionNames}

		_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
			true)
		if !foundMatchingPermission {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Errorf("resource/service:requiresPermission() %s Insufficient privileges to access %s", message.UnauthorizedAccess, r.RequestURI)
			return &privilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		secLog.Infof("resource/service:requiresPermission() %s - %s", message.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}

// endpointHandler is the same as http.ResponseHandler, but returns an error that can be handled by a generic
// middleware handler
type endpointHandler func(w http.ResponseWriter, r *http.Request) error

func errorHandler(eh endpointHandler) http.HandlerFunc {
	log.Trace("resource/service:errorHandler() Entering")
	defer log.Trace("resource/service:errorHandler() Leaving")
	return func(w http.ResponseWriter, r *http.Request) {
		if err := eh(w, r); err != nil {
			if strings.TrimSpace(strings.ToLower(err.Error())) == "record not found" {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			switch t := err.(type) {
			case *endpointError:
				http.Error(w, t.Message, t.StatusCode)
			case privilegeError:
				http.Error(w, t.Message, t.StatusCode)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func fnGetJwtCerts() error {
	log.Trace("resource/service:fnGetJwtCerts() Entering")
	defer log.Trace("resource/service:fnGetJwtCerts() Leaving")

	cfg, err := config.NewConfigFromYaml(constants.ConfigFilePath)
	if err != nil {
		fmt.Printf("ERROR: %+v\n", err)
		return nil
	}

	aasURL := cfg.AAS.BaseURL

	url := aasURL + "jwt-certificates"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/x-pem-file")
	secLog.Debugf("resource/service::fnGetJwtCerts() Connecting to AAS Endpoint %s", url)

	caCerts, err := crypt.GetCertsFromDir(constants.TrustedCaCertsDir)
	if err != nil {
		log.WithError(err).Errorf("resource/service::fnGetJwtCerts() Error while getting certs from %s", constants.TrustedCaCertsDir)
		return errors.Wrap(err, "resource/service::fnGetJwtCerts() Error while getting certs from %s")
	}

	hc, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		return errors.Wrap(err, "resource/service:fnGetJwtCerts() Error setting up HTTP client")
	}

	res, err := hc.Do(req)
	if err != nil {
		return errors.Wrap(err, "resource/service:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "resource/service:fnGetJwtCerts() Error while reading response body")
	}

	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "resource/service:fnGetJwtCerts() Error while saving certificate")
	}

	return nil
}
