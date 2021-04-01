/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"intel/isecl/go-trust-agent/v3/config"
	"intel/isecl/go-trust-agent/v3/constants"
	"intel/isecl/lib/tpmprovider/v3"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/pkg/errors"
)

// HVS expects...
// <tpm_quote_response>
//     <timestamp>1569264156635</timestamp>
//     <clientIp>fe80:0:0:0:a236:9fff:fef8:7229%enp134s0f1</clientIp>
//     <errorCode>0</errorCode>
//     <errorMessage>OK</errorMessage>
//     <aik>MIIDSjCCAbKgAwIBAgIGAWz...</aik>
//     <quote>AIv/VENHgBgAIgALUiWzd9...=</quote>
//     <eventLog>PG1lYXN1cmVMb2c+PHR4dD48dHh0U3RhdH...=</eventLog>
//     <tcbMeasurements>
//         <tcbMeasurements>&lt;?xml version="1.0" encoding="UTF-8" standalone="yes"?>&lt;Measurement xmlns="lib:wml:measurements:1.0" Label="ISecL_Default_Workload_Flavor_v2.0" Uuid="b13b405b-97a7-4480-a2e7-eea01f9799ce" DigestAlg="SHA384">&lt;CumulativeHash>000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000&lt;/CumulativeHash>&lt;/Measurement></tcbMeasurements>
// 			<...>
//     </tcbMeasurements>
//     <selectedPcrBanks>
//         <selectedPcrBanks>SHA1</selectedPcrBanks>
//         <selectedPcrBanks>SHA256</selectedPcrBanks>
//     </selectedPcrBanks>
//     <isTagProvisioned>false</isTagProvisioned>
// </tpm_quote_response>
type TpmQuoteResponse struct {
	XMLName         xml.Name `xml:"tpm_quote_response"`
	TimeStamp       int64    `xml:"timestamp"`
	ErrorCode       int      `xml:"errorCode"`
	ErrorMessage    string   `xml:"errorMessage"`
	Aik             string   `xml:"aik"`
	Quote           string   `xml:"quote"`
	EventLog        *string  `xml:"eventLog,omitempty"`
	TcbMeasurements struct {
		XMLName         xml.Name `xml:"tcbMeasurements"`
		TcbMeasurements []string `xml:"tcbMeasurements"`
	}
	SelectedPcrBanks struct {
		XMLName          xml.Name `xml:"selectedPcrBanks"`
		SelectedPcrBanks []string `xml:"selectedPcrBanks"`
	}
	IsTagProvisioned bool   `xml:"isTagProvisioned"`
	AssetTag         string `xml:"assetTag,omitempty"`
}

// HVS will provide json like...
// {
//		"nonce":"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=",
//		"pcrs": [0,1,2,3,18,19,22],
//		"pcrbanks" : ["SHA1", "SHA256"]
// }
type TpmQuoteRequest struct {
	Nonce    []byte   `json:"nonce"`
	Pcrs     []int    `json:"pcrs"`
	PcrBanks []string `json:"pcrbanks"`
}

type TpmQuoteContext struct {
	tpmQuoteResponse TpmQuoteResponse
	tpm              tpmprovider.TpmProvider
	cfg              *config.TrustAgentConfiguration
}

// HVS generates a 20 byte random nonce that is sent in the tpmQuoteRequest.  However,
// HVS expects the response nonce (in the TpmQuoteResponse.Quote binary) to be hashed with the bytes
// of local ip address.  If this isn't performed, HVS will throw an error when the
// response is received.
//
// Also, HVS takes into account the asset tag in the nonce -- it takes the ip hashed nonce
// and 'extends' it with value of asset tag (i.e. when tags have been set on the trust agent).
func (ctx *TpmQuoteContext) getNonce(hvsNonce []byte) ([]byte, error) {
	log.Trace("resource/quote:getNonce() Entering")
	defer log.Trace("resource/quote:getNonce() Leaving")

	log.Debugf("resource/quote:getNonce() Received HVS nonce '%s', raw[%s]", base64.StdEncoding.EncodeToString(hvsNonce), hex.EncodeToString(hvsNonce))

	// similar to HVS' SHA1.digestOf(hvsNonce).extend(ipBytes)
	hash := sha1.New()
	_, err := hash.Write(hvsNonce)
	if err != nil {
		return nil, err
	}
	taNonce := hash.Sum(nil)

	if ctx.tpmQuoteResponse.IsTagProvisioned {

		if ctx.tpmQuoteResponse.AssetTag == "" {
			return nil, errors.New("resource/quote:getNonce() The quote is 'tag provisioned', but the tag was not provided")
		}

		// TpmQuoteResponse is used to share data with HVS and stores the asset tag
		// as base64 -- apply the raw bytes to the hash similar to HVS.
		tagBytes, err := base64.StdEncoding.DecodeString(ctx.tpmQuoteResponse.AssetTag)
		if err != nil {
			return nil, err
		}

		// similar to HVS' SHA1.digestOf(taNonce).extend(tagBytes)
		hash = sha1.New()
		_, err = hash.Write(taNonce)
		if err != nil {
			return nil, err
		}
		_, err = hash.Write(tagBytes)
		if err != nil {
			return nil, err
		}
		taNonce = hash.Sum(nil)

		log.Debugf("resource/quote:getNonce() Used tag bytes '%s' to extend nonce to '%s', raw[%s]", hex.EncodeToString(tagBytes), base64.StdEncoding.EncodeToString(taNonce), hex.EncodeToString(taNonce))
	}

	return taNonce, nil
}

func (ctx *TpmQuoteContext) readAikAsBase64() error {
	log.Trace("resource/quote:readAikAsBase64() Entering")
	defer log.Trace("resource/quote:readAikAsBase64() Leaving")

	if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
		return err
	}

	aikBytes, err := ioutil.ReadFile(constants.AikCert)
	if err != nil {
		return errors.Wrapf(err, "resource/quote:readAikAsBase64() Error reading file %s", constants.AikCert)
	}

	ctx.tpmQuoteResponse.Aik = base64.StdEncoding.EncodeToString(aikBytes)
	return nil
}

func (ctx *TpmQuoteContext) readEventLog() error {
	log.Trace("resource/quote:readEventLog() Entering")
	defer log.Trace("resource/quote:readEventLog() Leaving")

	if _, err := os.Stat(constants.MeasureLogFilePath); os.IsNotExist(err) {
		log.Debugf("esource/quote:readEventLog() Event log file '%s' was not present", constants.MeasureLogFilePath)
		return nil // If the file does not exist, do not include in the quote
	}

	eventLogBytes, err := ioutil.ReadFile(constants.MeasureLogFilePath)
	if err != nil {
		return errors.Wrapf(err, "resource/quote:readEventLog() Error reading file: %s", constants.MeasureLogFilePath)
	}

	// Make sure the bytes are valid json
	err = json.Unmarshal(eventLogBytes, new(interface{}))
	if err != nil {
		return errors.Wrap(err, "resource/quote:readEventLog() Error while unmarshalling event log")
	}

	eventLog := string(eventLogBytes)
	ctx.tpmQuoteResponse.EventLog = &eventLog
	return nil
}

func (ctx *TpmQuoteContext) getQuote(tpmQuoteRequest *TpmQuoteRequest) error {

	nonce, err := ctx.getNonce(tpmQuoteRequest.Nonce)
	if err != nil {
		return err
	}

	log.Debugf("resource/quote:getQuote() Providing tpm nonce value '%s', raw[%s]", base64.StdEncoding.EncodeToString(nonce), hex.EncodeToString(nonce))
	quoteBytes, err := ctx.tpm.GetTpmQuote(ctx.cfg.Tpm.AikSecretKey, nonce, tpmQuoteRequest.PcrBanks, tpmQuoteRequest.Pcrs)
	if err != nil {
		return err
	}

	ctx.tpmQuoteResponse.Quote = base64.StdEncoding.EncodeToString(quoteBytes)

	return nil
}

// create an array of "tcbMeasurments", each from the  xml escaped string
// of the files located in /opt/trustagent/var/ramfs
func (ctx *TpmQuoteContext) getTcbMeasurements() error {
	log.Trace("resource/quote:getTcbMeasurements() Entering")
	defer log.Trace("resource/quote:getTcbMeasurements() Leaving")

	fileInfo, err := ioutil.ReadDir(constants.RamfsDir)
	if err != nil {
		return err
	}

	for _, file := range fileInfo {
		if filepath.Ext(file.Name()) == ".xml" {
			log.Debugf("resource/quote:getTcbMeasurements() Including measurement file '%s/%s'", constants.RamfsDir, file.Name())
			xml, err := ioutil.ReadFile(constants.RamfsDir + file.Name())
			if err != nil {
				return errors.Wrapf(err, "resource/quote:getTcbMeasurements() Error reading manifest file %s", file.Name())
			}

			ctx.tpmQuoteResponse.TcbMeasurements.TcbMeasurements = append(ctx.tpmQuoteResponse.TcbMeasurements.TcbMeasurements, string(xml))
		}
	}

	return nil
}

func (ctx *TpmQuoteContext) getAssetTags() error {
	log.Trace("resource/quote:getAssetTags() Entering")
	defer log.Trace("resource/quote:getAssetTags() Leaving")

	tagExists, err := ctx.tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return errors.Wrap(err, "resource/quote:getAssetTags() Error while checking existence of Nv Index")
	}

	if tagExists {

		ctx.tpmQuoteResponse.IsTagProvisioned = true

		tagBytes, err := ctx.tpm.NvRead(ctx.cfg.Tpm.OwnerSecretKey, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			return errors.Wrap(err, "resource/quote:getAssetTags() Error while performing tpm nv read operation")
		}

		ctx.tpmQuoteResponse.AssetTag = base64.StdEncoding.EncodeToString(tagBytes) // this data will be evaluated in 'getNonce'

	} else {
		ctx.tpmQuoteResponse.IsTagProvisioned = false
	}

	return nil
}

func (ctx *TpmQuoteContext) createTpmQuote(tpmQuoteRequest *TpmQuoteRequest) error {
	log.Trace("resource/quote:createTpmQuote() Entering")
	defer log.Trace("resource/quote:createTpmQuote() Leaving")

	var err error

	ctx.tpmQuoteResponse.TimeStamp = time.Now().Unix()

	// getAssetTags must be called before getQuote so that the nonce is created correctly - see comments for getNonce()
	err = ctx.getAssetTags()
	if err != nil {
		return errors.Wrap(err, "resource/quote:createTpmQuote() Error while retrieving asset tags")
	}

	// get the quote from tpmprovider
	err = ctx.getQuote(tpmQuoteRequest)
	if err != nil {
		return errors.Wrap(err, "resource/quote:createTpmQuote() Error while retrieving tpm quote request")
	}

	// aik --> read from disk and convert to PEM string
	err = ctx.readAikAsBase64()
	if err != nil {
		return errors.Wrap(err, "resource/quote:createTpmQuote() Error while reading Aik as Base64")
	}

	// eventlog: read /opt/trustagent/var/measure-log.json
	err = ctx.readEventLog()
	if err != nil {
		return errors.Wrap(err, "resource/quote:createTpmQuote() Error while reading event log")
	}

	err = ctx.getTcbMeasurements()
	if err != nil {
		return errors.Wrap(err, "resource/quote:createTpmQuote() Error while retrieving TCB measurements")
	}

	// selected pcr banks (just return what was requested similar to java implementation)
	ctx.tpmQuoteResponse.SelectedPcrBanks.SelectedPcrBanks = tpmQuoteRequest.PcrBanks

	ctx.tpmQuoteResponse.ErrorCode = 0 // Question: does HVS handle specific error codes or is just a pass through?
	ctx.tpmQuoteResponse.ErrorMessage = "OK"
	return nil
}

// Returns 'quote' json provided parameters such as a nonce, pcr banks and pcrs
// Ex. curl --user tagentadmin:TAgentAdminPassword -d '{ "nonce":"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=", "pcrs": [0,1,2,3,18,19,22] }' -H "Content-Type: application/json" -X POST https://localhost:1443/v2/tpm/quote -k --noproxy "*"
func getTpmQuote(cfg *config.TrustAgentConfiguration, tpmFactory tpmprovider.TpmFactory) endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/quote:getTpmQuote() Entering")
		defer log.Trace("resource/quote:getTpmQuote() Leaving")

		log.Debugf("resource/quote:getTpmQuote() Request: %s", httpRequest.URL.Path)

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/json" {
			log.Errorf("resource/quote:getTpmQuote() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &endpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		tpm, err := tpmFactory.NewTpmProvider()
		if err != nil {
			log.WithError(err).Errorf("resource/quote:getTpmQuote() %s - Error creating tpm provider", message.AppRuntimeErr)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		defer tpm.Close()

		ctx := TpmQuoteContext{
			cfg: cfg,
			tpm: tpm,
		}

		var tpmQuoteRequest TpmQuoteRequest

		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.Errorf("resource/quote:getTpmQuote() %s - Error reading request body: %s for request %s", message.AppRuntimeErr, string(data), httpRequest.URL.Path)
			return &endpointError{Message: "Error reading request body", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&tpmQuoteRequest)
		if err != nil {
			seclog.WithError(err).Errorf("resource/quote:getTpmQuote() %s - Error marshaling json data: %s", message.InvalidInputProtocolViolation, string(data))
			return &endpointError{Message: "Error marshaling json data", StatusCode: http.StatusBadRequest}

		}

		if len(tpmQuoteRequest.Nonce) == 0 {
			seclog.Errorf("resource/quote:getTpmQuote() %s - The TpmQuoteRequest does not contain a nonce", message.InvalidInputProtocolViolation)
			return &endpointError{Message: "The TpmQuoteRequest does not contain a nonce", StatusCode: http.StatusBadRequest}
		}

		// ISECL-12121: strip inactive PCR Banks from the request
		for i, pcrBank := range tpmQuoteRequest.PcrBanks {
			isActive, err := tpm.IsPcrBankActive(pcrBank)
			if !isActive {
				log.Infof("resource/quote:getQuote() %s PCR bank is inactive. Dropping from quote request. %s",
					pcrBank, err.Error())
				tpmQuoteRequest.PcrBanks = append(tpmQuoteRequest.PcrBanks[:i], tpmQuoteRequest.PcrBanks[i+1:]...)
			} else if err != nil {
				log.WithError(err).Errorf("resource/quote:getQuote() Error while determining PCR bank "+
					"%s state: %s", pcrBank, err.Error())
			}
		}

		err = ctx.createTpmQuote(&tpmQuoteRequest)
		if err != nil {
			log.WithError(err).Errorf("resource/quote:getTpmQuote() %s - Error while creating the tpm quote", message.AppRuntimeErr)
			return &endpointError{Message: "Error reading request body", StatusCode: http.StatusInternalServerError}
		}

		xmlOutput, err := xml.MarshalIndent(&ctx.tpmQuoteResponse, "  ", "    ")
		if err != nil {
			log.WithError(err).Errorf("resource/quote:getTpmQuote() %s - There was an error serializing the tpm quote", message.AppRuntimeErr)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.Header().Set("Content-Type", "application/xml")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(xmlOutput).WriteTo(httpWriter)
		return nil
	}
}
