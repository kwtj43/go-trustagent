/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/go-trust-agent/v3/util"
	"intel/isecl/lib/common/v3/setup"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type CreateHost struct {
	clientFactory  hvsclient.HVSClientFactory
	trustAgentPort int
}

//
// Registers (or updates) HVS with information about the current compute
// node (providing the connection string, hostname (ip addr) and tls policy).
//
// If the host already exists, create-host will return an error.
//
func (task *CreateHost) Run(c setup.Context) error {
	log.Trace("tasks/create_host:Run() Entering")
	defer log.Trace("tasks/create_host:Run() Leaving")

	var err error
	fmt.Println("Running setup task: create-host")

	hostsClient, err := task.clientFactory.HostsClient()
	if err != nil {
		return errors.Wrap(err, "Could not create host client")
	}

	currentIP, err := util.GetCurrentIP()
	if err != nil {
		return errors.Wrap(err, "The create-host task requires the CURRENT_IP environment variable")
	}

	hostCollection, err := hostsClient.SearchHosts(&models.HostFilterCriteria{NameEqualTo: currentIP.String()})
	if err != nil {
		return errors.Wrap(err, "Error while retrieving host collection")
	}

	if len(hostCollection.Hosts) == 0 {
		// no host present, create a new one

		hostCreateReq := hvs.HostCreateRequest{
			HostName:         currentIP.String(),
			ConnectionString: util.GetConnectionString(currentIP, task.trustAgentPort),
		}

		host, err := hostsClient.CreateHost(&hostCreateReq)
		if err != nil {
			return err
		}

		log.Debugf("tasks/create_host:Run() Successfully created host, host id %s", host.Id)
	} else {
		return errors.Errorf("Host with IP address %s already exists", currentIP.String())
	}

	return nil
}

// Using the ip address, query VS to verify if this host is registered
func (task *CreateHost) Validate(c setup.Context) error {
	log.Trace("tasks/create_host:Validate() Entering")
	defer log.Trace("tasks/create_host:Validate() Leaving")

	// Initialize the PrivacyCA client using the factory - this will be reused in Run
	hostsClient, err := task.clientFactory.HostsClient()
	if err != nil {
		return errors.Wrap(err, "Could not create host client")
	}

	currentIP, err := util.GetCurrentIP()
	if err != nil {
		return errors.Wrap(err, "The create-host task requires the CURRENT_IP environment variable")
	}

	hostCollection, err := hostsClient.SearchHosts(&models.HostFilterCriteria{NameEqualTo: currentIP.String()})
	if err != nil {
		return errors.Wrap(err, "Error searching for host collection")
	}

	if len(hostCollection.Hosts) == 0 {
		return errors.Errorf("Host with ip '%s' was not created", currentIP.String())
	}

	log.Info("tasks/create_host:Validate() Create host setup task was successful.")
	return nil
}
