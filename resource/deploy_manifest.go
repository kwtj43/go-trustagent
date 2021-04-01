/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/xml"
	"intel/isecl/go-trust-agent/v3/constants"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	flavorConsts "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
)

// Writes the manifest xml received to /opt/trustagent/var/manifest_{UUID}.xml.
func deployManifest() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/deploy_manifest:deployManifest() Entering")
		defer log.Trace("resource/deploy_manifest:deployManifest() Leaving")

		log.Debugf("resource/deploy_manifest:deployManifest() Request: %s", httpRequest.URL.Path)

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/xml" {
			log.Errorf("resource/deploy_manifest:deployManifest() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &endpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		// receive a manifest from hvs in the request body
		manifestXml, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.Errorf("resource/deploy_manifest:deployManifest() Error reading manifest xml: %s", err)
			return &endpointError{Message: "Error reading manifest xml", StatusCode: http.StatusBadRequest}
		}

		// make sure the xml is well formed
		manifest := hvsclient.Manifest{}
		err = xml.Unmarshal(manifestXml, &manifest)
		if err != nil {
			log.Errorf("resource/deploy_manifest:deployManifest() Invalid xml format: %s", err)
			return &endpointError{Message: "Error: Invalid xml format", StatusCode: http.StatusBadRequest}
		}

		err = validation.ValidateUUIDv4(manifest.UUID)
		if err != nil {
			secLog.Errorf("%s resource/deploy_manifest:deployManifest() Invalid uuid %s", message.InvalidInputBadParam, err.Error())
			return &endpointError{Message: "Error: Invalid uuid", StatusCode: http.StatusBadRequest}
		}

		if len(manifest.Label) == 0 {
			log.Errorf("%s: The manifest did not contain a label", httpRequest.URL.Path)
			return &endpointError{Message: "Error: The manifest did not contain a label", StatusCode: http.StatusBadRequest}
		}

		var manifestlabels []string
		manifestlabels = append(manifestlabels, manifest.Label)
		err = validation.ValidateStrings(manifestlabels)
		if err != nil {
			secLog.Errorf("%s resource/deploy_manifest:deployManifest() Invalid manifest labels %s", message.InvalidInputBadParam, err.Error())
			return &endpointError{Message: "Error: Invalid manifest labels", StatusCode: http.StatusBadRequest}
		}

		if strings.Contains(manifest.Label, flavorConsts.DefaultSoftwareFlavorPrefix) ||
			strings.Contains(manifest.Label, flavorConsts.DefaultWorkloadFlavorPrefix) {
			log.Infof("%s: Default flavor's manifest (%s) is part of installation, no need to deploy default flavor's manifest", httpRequest.URL.Path, manifest.Label)
			return &endpointError{Message: " Default flavor's manifest (%s) is part of installation", StatusCode: http.StatusBadRequest}
		}

		// establish the name of the manifest file and write the file
		manifestFile := constants.VarDir + "manifest_" + manifest.UUID + ".xml"
		err = ioutil.WriteFile(manifestFile, manifestXml, 0600)
		if err != nil {
			log.Errorf("%s: Could not write manifest: %s", httpRequest.URL.Path, err)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.WriteHeader(http.StatusOK)
		return nil
	}
}
