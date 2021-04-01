// Trust Agent
//
// The Trust Agent acts as a primary interface between the Host, TPM and the Host Verification Service.
// It maintains the ownership of the server’s Trusted Platform Module and allows the secure attestation quotes
// to be sent to the Host Verification Service.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 2.2
//  Host: trustagent.server.com:1443
//  BasePath: /v2
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token>**
//
// swagger:meta
package docs

// swagger:operation GET /version Version getVersion
// ---
// description: Retrieves the version of trust agent.
//
// produces:
// - application/json
// responses:
//   "200":
//     description: Successfully retrieved the version of trust agent.
//
// x-sample-call-endpoint: https://trustagent.server.com:1443/version
// x-sample-call-output: |
//    Service Name: Trust Agent
//    Version: v3.4.0-1ebcfcd
//    Build Date: 2021-03-01T17:39:16+0000
// ---
