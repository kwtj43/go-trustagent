/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/lib/tpmprovider"
	"io/ioutil"
	"net/http"
)

// json request format sent from HVS...
// {
//		"tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
//		"hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262"
//  }
type TagWriteRequest struct {
	Tag           []byte `json:"tag"`
	hardware_uuid string `json:"hardware_uuid"`
}

//
// Provided the TagWriteRequest from, delete any existing tags, define/write
// tag to the TPM's nvram.  The receiving side of this equation is in 'quote.go'
// where the asset tag is used to hash the nonce and is also appended to the
// quote xml.
//
func setAssetTag(cfg *config.TrustAgentConfiguration, tpmFactory tpmprovider.TpmFactory) http.HandlerFunc {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) {

		log.Debugf("Request: %s", httpRequest.URL.Path)

		var tagWriteRequest TagWriteRequest
		tpmSecretKey := cfg.Tpm.OwnerSecretKey

		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.Errorf("%s: Error reading request body: %s", httpRequest.URL.Path, err)
			httpWriter.WriteHeader(http.StatusBadRequest)
			return
		}

		err = json.Unmarshal(data, &tagWriteRequest)
		if err != nil {
			log.Errorf("%s:  Error marshaling json data: %s...\n%s", httpRequest.URL.Path, err, string(data))
			httpWriter.WriteHeader(http.StatusBadRequest)
			return
		}

		tpm, err := tpmFactory.NewTpmProvider()
		if err != nil {
			log.Errorf("%s: Error creating tpm provider: %s", httpRequest.URL.Path, err)
			return
		}

		defer tpm.Close()

		// check if an asset tag already exists and delete it if needed
		nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			log.Errorf("%s: Error checking if asset tag exists: %s", httpRequest.URL.Path, err)
			httpWriter.WriteHeader(http.StatusInternalServerError)
			return
		}

		if nvExists {
			err = tpm.NvRelease(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG)
			if err != nil {
				log.Errorf("%s: Could not release asset tag nvram: %s", httpRequest.URL.Path, err)
				httpWriter.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// create an index for the data
		err = tpm.NvDefine(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG, uint16(len(tagWriteRequest.Tag)))
		if err != nil {
			log.Errorf("%s: Could not define tag nvram: %s", httpRequest.URL.Path, err)
			httpWriter.WriteHeader(http.StatusInternalServerError)
			return
		}

		// write the data
		err = tpm.NvWrite(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tagWriteRequest.Tag)
		if err != nil {
			log.Errorf("%s: Error writing asset tag: %s", httpRequest.URL.Path, err)
			return
		}

		httpWriter.WriteHeader(http.StatusOK)
		return
	}
}