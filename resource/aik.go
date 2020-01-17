/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"intel/isecl/go-trust-agent/constants"
	commLog "intel/isecl/lib/common/log"
	"io/ioutil"
	"net/http"
	"os"
	)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

//
// Reads the provision aik certificate from /opt/trustagent/configuration/aik.cert
//
// Ex. curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/aik -k --noproxy "*"
func getAik() endpointHandler {

	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/aik:getAik() Entering")
		defer log.Trace("resource/aik:getAik() Leaving")

		log.Debugf("resource/aik:getAik() Request: %s", httpRequest.URL.Path)

		if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
			log.Errorf("resource/aik:getAik() %s does not exist", constants.AikCert)
			return &endpointError{Message: "AIK certificate does not exist", StatusCode: http.StatusNotFound}
		}

		aikBytes, err := ioutil.ReadFile(constants.AikCert)
		if err != nil {
			log.Errorf("resource/aik:getAik() There was an error reading %s", constants.AikCert)
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
