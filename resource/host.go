/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"intel/isecl/go-trust-agent/v3/constants"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
)

// Assuming that the /opt/trustagent/var/system-info/platform-info file has been create
// during startup, this function reads the contents of the json file and return it to the http
// writer.
//
// EX. curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/host -k --noproxy "*"
//
// {
// 	"errrCode":0,
// 	"os_name":"Fedora",
// 	"os_version":"29",
// 	"bios_version":"-1",
// 	"vmm_name":"",
// 	"VMMVersion":"",
// 	"processor_info":"-1",
// 	"host_name":"63a5dc91a4e4",
// 	"hardware_uuid":"-1",
// 	"process_flags":"",
// 	"tpm_version":"0",
// 	"pcr_banks":[
// 	   "SHA1",
// 	   "SHA256"
// 	],
// 	"no_of_sockets":"2",
// 	"tpm_enabled":"false",
// 	"txt_enabled":"false",
// 	"tboot_installed":"true",
// 	"is_docker_env":"false",
// 	"hardware_features":{
// 	   "TXT":{
// 		  "enabled":"false"
// 	   },
// 	   "TPM":{
// 		  "enabled":"false",
// 		  "Meta":{
// 			 "tpm_version":"0",
// 			 "pcr_banks":"SHA1_SHA256"
// 		  }
// 	   }
// 	},
// 	"installed_components":[
// 	   "trustagent"
// 	]
//  }
//
func getPlatformInfo() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/host:getPlatformInfo() Entering")
		defer log.Trace("resource/host:getPlatformInfo() Leaving")

		log.Debugf("resource/host:getPlatformInfo() Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type when calling /host
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("resource/host:getPlatformInfo() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &endpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		if _, err := os.Stat(constants.PlatformInfoFilePath); os.IsNotExist(err) {
			log.WithError(err).Errorf("resource/host:getPlatformInfo() %s - %s does not exist", message.AppRuntimeErr, constants.PlatformInfoFilePath)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		b, err := ioutil.ReadFile(constants.PlatformInfoFilePath)
		if err != nil {
			log.Errorf("resource/host:getPlatformInfo() %s - There was an error reading %s", message.AppRuntimeErr, constants.PlatformInfoFilePath)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.Header().Set("Content-Type", "application/json")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(b).WriteTo(httpWriter)
		return nil
	}
}
