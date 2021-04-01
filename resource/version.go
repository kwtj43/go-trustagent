/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"intel/isecl/go-trust-agent/v3/util"
	"net/http"
)

// GetVersion handles GET /version
func getVersion() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/version:getVersion() Entering")
		defer log.Trace("resource/version:getVersion() Leaving")

		httpWriter.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		log.Debugf("resource/version:getVersion() Trust Agent Version:\n %s", util.GetVersion())
		httpWriter.Header().Set("Content-Type", "text/plain")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer([]byte(util.GetVersion())).WriteTo(httpWriter)
		return nil
	}
}
