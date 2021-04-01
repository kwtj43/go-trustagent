/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package util

import (
	"intel/isecl/lib/tpmprovider/v3"

	"github.com/pkg/errors"
)

func GetEndorsementKeyCertificateBytes(ownerSecretKey string) ([]byte, error) {
	log.Trace("util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Entering")
	defer log.Trace("util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Leaving")

	tpmFactory, err := tpmprovider.NewTpmFactory()
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Could not create tpm factory")
	}

	//---------------------------------------------------------------------------------------------
	// Get the endorsement key certificate from the tpm
	//---------------------------------------------------------------------------------------------
	tpm, err := tpmFactory.NewTpmProvider()
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	// check to see if the EK Certificate exists...
	ekCertificateExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		return nil, errors.Wrap(err, "Error checking if the EK Certificate is present")
	}

	if !ekCertificateExists {
		return nil, errors.Errorf("The TPM does not have an RSA EK Certificate at the default index 0x%x", tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	}

	ekCertBytes, err := tpm.NvRead(ownerSecretKey, tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Error while performing tpm Nv read operation for getting endorsement certificate in bytes")
	}

	return ekCertBytes, nil
}
