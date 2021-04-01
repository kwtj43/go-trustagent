/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/lib/tpmprovider/v3"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/pkg/errors"
)

type TakeOwnership struct {
	tpmFactory     tpmprovider.TpmFactory
	ownerSecretKey *string // this is an 'out' variable that can be set by the task
}

// Retrieves the 'OwnerSecretKey' value from configuration.  If it is not there, it generates a
// new random key (or used TPM_OWNER_SECRET env var) and saves it in the configuration.  It
// then passes the new secret key to TpmProvider.TakeOwnership.
func (task *TakeOwnership) Run(c setup.Context) error {
	log.Trace("tasks/take_ownership:Run() Entering")
	defer log.Trace("tasks/take_ownership:Run() Leaving")
	fmt.Println("Running setup task: take-ownership")

	if task.ownerSecretKey == nil {
		return errors.New("The ownerSecretKey cannot be nil")
	}

	// The OwnerSecretKey is either set via trustagent.env (env var) and trustagent_config.go,
	// or is empty.  If it is empty, generate a new random key.  Note:  It could also be
	// present from the config.yml, but we assume this task is only called when taking
	// ownership of a cleared tpm.
	if *task.ownerSecretKey == "" {
		newSecretKey, err := crypt.GetHexRandomString(20)
		if err != nil {
			return errors.Wrap(err, "Error while generating a random key")
		}

		*task.ownerSecretKey = newSecretKey
	}

	// validate the secret key...
	if len(*task.ownerSecretKey) == 0 || len(*task.ownerSecretKey) > 40 {
		return errors.New("Invalid secret key length")
	}

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	// check if the tpm is already owned with the current secret key (and return)
	alreadyOwned, err := tpm.IsOwnedWithAuth(*task.ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, "Error while checking if the tpm is already owned with the current secret key")
	}

	if alreadyOwned {
		log.Info("tasks/take_ownership:Run() TPM ownership has already been established.")
		return nil
	}

	// tpm is not owned by current secret, take ownership
	err = tpm.TakeOwnership(*task.ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, "Error while performing tpm takeownership operation")
	}

	return nil
}

//
// Uses the current 'OwnerSecetKey' from configuration and checks its validity using
// TpmProvider.IsOwnedWithAuth.
//
func (task *TakeOwnership) Validate(c setup.Context) error {
	log.Trace("tasks/take_ownership:Validate() Entering")
	defer log.Trace("tasks/take_ownership:Validate() Leaving")

	if *task.ownerSecretKey == "" {
		return errors.New("The configuration does not contain the tpm secret key")
	}

	tpmProvider, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpmProvider.Close()

	ok, err := tpmProvider.IsOwnedWithAuth(*task.ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, "Error while checking if the tpm is already owned with the current secret key")
	}

	if !ok {
		return errors.New("The tpm is not owned with the current secret key")
	}

	log.Info("tasks/take_ownership:Validate() Take ownership was successful.")
	return nil
}
