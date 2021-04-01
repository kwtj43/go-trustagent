/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"intel/isecl/go-trust-agent/v3/constants"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
)

//
// Reads the provision aik certificate from /opt/trustagent/configuration/aik.cert
//
// Ex. curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/aik -k --noproxy "*"
func getAik() endpointHandler {

	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/aik:getAik() Entering")
		defer log.Trace("resource/aik:getAik() Leaving")

		log.Debugf("resource/aik:getAik() Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type to /aik, so only allow the empty string...
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("resource/aik:getAik() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &endpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
			log.Errorf("resource/aik:getAik() %s - %s does not exist", message.AppRuntimeErr, constants.AikCert)
			return &endpointError{Message: "AIK certificate does not exist", StatusCode: http.StatusNotFound}
		}

		aikBytes, err := ioutil.ReadFile(constants.AikCert)
		if err != nil {
			log.Errorf("resource/aik:getAik() %s - There was an error reading %s", message.AppRuntimeErr, constants.AikCert)
			return &endpointError{Message: "Unable to fetch AIK certificate", StatusCode: http.StatusInternalServerError}
		}

		aikDer, _ := pem.Decode(aikBytes)
		_, err = x509.ParseCertificate(aikDer.Bytes)
		if err != nil {
			return &endpointError{Message: "Error parsing AIK certificate file.", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(aikDer.Bytes).WriteTo(httpWriter)
		return nil
	}
}
