/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"intel/isecl/go-trust-agent/v3/constants"
)

// Returns the WLA provisioned binding key certificate from /etc/workload-agent/bindingkey.pem
//
// Ex. curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/binding-key-certificate -k --noproxy "*"
func getBindingKeyCertificate() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/binding_key_certificate:getBindingKeyCertificate() Entering")
		defer log.Trace("resource/binding_key_certificate:getBindingKeyCertificate() Leaving")

		log.Debugf("resource/binding_key_certificate:getBindingKeyCertificate() Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type, exlude other values
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("resource/binding_key_certificate:getBindingKeyCertificate() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &endpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		if _, err := os.Stat(constants.BindingKeyCertificatePath); os.IsNotExist(err) {
			log.WithError(err).Errorf("resource/binding_key_certificate:getBindingKeyCertificate() %s - %s does not exist", message.AppRuntimeErr, constants.BindingKeyCertificatePath)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		bindingKeyBytes, err := ioutil.ReadFile(constants.BindingKeyCertificatePath)
		if err != nil {
			log.Errorf("resource/binding_key_certificate:getBindingKeyCertificate() %s - Error reading %s", message.AppRuntimeErr, constants.BindingKeyCertificatePath)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}

		}

		httpWriter.Header().Set("Content-Type", "application/x-pem-file")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(bindingKeyBytes).WriteTo(httpWriter)
		return nil
	}
}
