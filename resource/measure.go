/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/xml"
	"intel/isecl/go-trust-agent/v3/constants"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
)

const WML_LOG_FILE = constants.LogDir + "wml.log"

// Uses /opt/tbootxml/bin/measure to measure the supplied manifest
func getApplicationMeasurement() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/measure:getApplicationMeasurement() Entering")
		defer log.Trace("resource/measure:getApplicationMeasurement() Leaving")

		log.Debugf("resource/measure:getApplicationMeasurement() Request: %s", httpRequest.URL.Path)

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/xml" {
			log.Errorf("resource/measure:getApplicationMeasurement() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &endpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		// receive a manifest from hvs in the request body
		manifestXml, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			seclog.WithError(err).Errorf("resource/measure:getApplicationMeasurement() %s - Error reading manifest xml", message.InvalidInputBadParam)
			return &endpointError{Message: "Error reading manifest xml", StatusCode: http.StatusBadRequest}
		}

		// make sure the xml is well formed, all other validation will be
		// peformed by 'measure' cmd line below
		err = xml.Unmarshal(manifestXml, new(interface{}))
		if err != nil {
			secLog.WithError(err).Errorf("resource/measure:getApplicationMeasurement() %s - Invalid xml format", message.InvalidInputBadParam)
			return &endpointError{Message: "Error: Invalid XML format", StatusCode: http.StatusBadRequest}
		}

		// this should probably be done in wml --> if the wml log file is not yet created,
		// 'measure' will fail.  for now, create the file before calling 'measure'.
		if _, err := os.Stat(WML_LOG_FILE); os.IsNotExist(err) {
			_, err = os.OpenFile(WML_LOG_FILE, os.O_RDONLY|os.O_CREATE, 0600)
			if err != nil {
				log.WithError(err).Errorf("resource/measure:getApplicationMeasurement() - Unable to open file")
				return &endpointError{Message: "Error: Unable to open log file", StatusCode: http.StatusInternalServerError}
			}
		}

		// make sure 'measure' is not a symbolic link before executing it
		measureExecutable, err := os.Lstat(constants.TBootXmMeasurePath)
		if err != nil {
			log.WithError(err).Errorf("resource/measure:getApplicationMeasurement() - Unable to stat tboot path")
			return &endpointError{Message: "Error: Unable to stat tboot path", StatusCode: http.StatusInternalServerError}
		}
		if measureExecutable.Mode()&os.ModeSymlink == os.ModeSymlink {
			secLog.WithError(err).Errorf("resource/measure:getApplicationMeasurement() %s - 'measure' is a symbolic link", message.InvalidInputBadParam)
			return &endpointError{Message: "Error: Invalid 'measure' file", StatusCode: http.StatusInternalServerError}
		}

		// call /opt/tbootxml/bin/measure and return the xml from stdout
		// 'measure <manifestxml> /'
		cmd := exec.Command(constants.TBootXmMeasurePath, string(manifestXml), "/")
		cmd.Env = append(os.Environ(), "WML_LOG_FILE="+WML_LOG_FILE)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.WithError(err).Errorf("resource/measure:getApplicationMeasurement() %s - Error getting measure output", message.AppRuntimeErr)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		err = cmd.Start()
		if err != nil {
			log.WithError(err).Errorf("resource/measure:getApplicationMeasurement() %s - Failed to run: %s", message.AppRuntimeErr, constants.TBootXmMeasurePath)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}

		}

		measureBytes, _ := ioutil.ReadAll(stdout)
		err = cmd.Wait()
		if err != nil {
			log.WithError(err).Errorf("resource/measure:getApplicationMeasurement() %s - %s returned '%s'", message.AppRuntimeErr, constants.TBootXmMeasurePath, string(measureBytes))
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		// make sure we got valid xml from measure
		err = xml.Unmarshal(measureBytes, new(interface{}))
		if err != nil {
			seclog.WithError(err).Errorf("resource/measure:getApplicationMeasurement() %s - Invalid measurement xml %s: %s", message.AppRuntimeErr, httpRequest.URL.Path, string(measureBytes))
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(measureBytes).WriteTo(httpWriter)
		return nil
	}
}
