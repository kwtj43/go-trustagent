/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"fmt"
	"intel/isecl/go-trust-agent/v3/config"
	"intel/isecl/lib/tpmprovider/v3"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	TpmSecretKey          = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	TestPort              = 8450
	TestJWTVerifyCertPath = "jwtsigncert.pem"
	TestJWTAuthToken      = "eyJhbGciOiJSUzM4NCIsImtpZCI6Ijc0NjAzNTcxMjQ1ZGY1YjMxMTliOWE1YTcyODgwZTIyZGI4MTM0YWIiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IlRBIiwibmFtZSI6IkFkbWluaXN0cmF0b3IifV0sInBlcm1pc3Npb25zIjpbeyJzZXJ2aWNlIjoiVEEiLCJydWxlcyI6WyIqOio6KiJdfV0sImV4cCI6MTkyNTE5MjEwNywiaWF0IjoxNjA5ODMyMDc3LCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6ImFkbWluQHZzIn0.VYG9yUtxK5HB68xfjOeG2n-tHCm-SuNH0K8siuU21fIOPPVTATri2SGbWMP3Nxh6L-Q_pdyKYe3QcjQBh0vhLkP9mtYcH2258Xqm0kXIF1J9RcJ5IvQwGOvkDQ1uWkcEd4EDx5jqlCvTagZDDxOeCeaee0hHBSH_8KuHox29BtLX7rchq5PjM0E7L5PmqEBMwrYZvtGQHRD98yFXHFUtpmwrW9iZcC6XUDh5r4Q5muUGzPGUHNdrsAdZvUG2KaXJrD6nDVglY0f7wWO6qH3owKYBAvmGCWnShgVsZ7turfj7AZWp3T2-PgMysAWVLHxiumCaeluzkYjY19go4RbYa3fLHrIJKOcaaUQXqlVlvDWgffjEe_pUwxVduJDOdw0Dshd7yCrlAiL_ZZobAlPugDjatNNInOe7CuQkhk2ZXiy9xD5FaNQNRUU6V_9c7FZA-A1aguvvpR2-QwQX4u4nPmec1bjbJ4EmInl4rqkrUJmSkewiQ0RVVZJdOvuVtS-H"
	TestBadJWTAuthToken   = "eyJhbGciOiJSUzM4NCIsImtpZCI6IjRhZTYyNmQyMWU4NTg2YmYzNTJlZDQ3NTQwMDY5YjU0ZjA3MGFjNjIiLCJ0eXAiOiJKV1QifQ.eXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxyJyb2xlcyI6W3sic2VydmljZSI6IlRBIiwibmFtZSI6IkhWU1VzZXJQZXJtIn1dLCJwZXJtaXNzaW9ucyI6W3sic2VydmljZSI6IlRBIiwicnVsZXMiOlsiYWlrX2NhOnJldHJpZXZlOioiLCJhaWs6cmV0cmlldmU6KiIsImFwcGxpY2F0aW9uX21lYXN1cmVtZW50OmNyZWF0ZToqIiwiYmluZGluZ19rZXk6cmV0cmlldmU6KiIsImRhYTpyZXRyaWV2ZToqIiwiZGVwbG95X21hbmlmZXN0OmNyZWF0ZToqIiwiZGVwbG95X3RhZzpjcmVhdGU6KiIsImhvc3RfaW5mbzpyZXRyaWV2ZToqIiwicXVvdGU6Y3JlYXRlOioiXX1dLCJleHAiOjE4OTM5MTE4NzEsImlhdCI6MTU3ODU1MTg3MSwiaXNzIjoiQUFTIEpXVCBJc3N1ZXIiLCJzdWIiOiJ0YUhWU1VzZXJQZXJtIn0.Bq94ZzHTa3SUW5W76DQk1SNBrgS9uxINqhfYe--c0jS5F8Gd6PJeTM-HcV4w7sqGqIEhC73khqXQ4O9G7uiB8eMS-HI4pczdyV8zwZtgda8EoDUj9EYjByXktpQTZsEcZwh5NEATAylhqev2ZyeESQNwCAO2o9hWDJmLeYZovHygggOaly5zgWElfAkIvLZnvVyfy2M3aoNWtugpY4V7QZME8kAadwuOgTPAHv87x-nElfb4qIBcOzmuVm9Ktm5cnFD_j9QTMDgLnPtipFVQGsGyUz1OglCojEUGbXUNo2wADHyt3D7T3hgmGQustsiWZamjHdjysS2v4N4ZuKAKIZCuNpDWKdU5DwkY5dFTkdB9D_WA0P5Ot9MdkAiJu_eC9Vg6oI3uoH3uPn1uUGKNo1RGtbmpV4QJASA04UHBY_BTIg0Tu86Aol7ctpbjJZkwxhTkVi4mgOi69dq1N1xmekr_Z3M88P4tZezfm6eeUAfUBQ2r52Up3_RvrhFbOIwm"
	EmptyJWTToken         = ""
)

func CreateTestConfig() *config.TrustAgentConfiguration {

	cfg := config.TrustAgentConfiguration{}
	cfg.Logging.LogLevel = "trace"
	cfg.WebService.Port = TestPort
	cfg.Tpm.OwnerSecretKey = TpmSecretKey

	return &cfg
}

// func TestAik(t *testing.T) {
// 	assert := assert.New(t)

// 	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
// 	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
// 	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider : mockedTpmProvider}

// 	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
// 	assert.NoError(err)

// 	request, err := http.NewRequest("GET", "/v2/aik", nil)
// 	assert.NoError(err)

// 	request.SetBasicAuth(TestUser, TestPassword)

// 	recorder := httptest.NewRecorder()
// 	trustAgentService.router.ServeHTTP(recorder, request)
// 	response := recorder.Result()
// 	fmt.Printf("StatusCode: %d\n", response.StatusCode)
// 	assert.Equal(response.StatusCode, http.StatusOK)
// }

// func TestQuoteService(t *testing.T) {
// 	assert := assert.New(t)

// 	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
// 	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
// 	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider : mockedTpmProvider}

// 	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
// 	assert.NoError(err)

// 	jsonString := "{ \"nonce\":\"VfZ5QjqFfD2yajuuxLcKrzKa7IE=\", \"pcrs\": [0,1,2,3,18,19,22] , \"pcrbanks\" : [\"SHA1\", \"SHA256\"]}"

// 	request, err := http.NewRequest("POST", "/v2/tpm/quote", bytes.NewBuffer([]byte(jsonString)))
// 	assert.NoError(err)

// 	request.Header.Set("Content-Type", "application/json")
// 	request.SetBasicAuth(TestUser, TestPassword)

// 	recorder := httptest.NewRecorder()
// 	trustAgentService.router.ServeHTTP(recorder, request)
// 	response := recorder.Result()
// 	fmt.Printf("StatusCode: %d\n", response.StatusCode)
// 	assert.Equal(response.StatusCode, http.StatusOK)
// }

func mockRetrieveJWTSigningCerts() error {
	log.Trace("resource/service_test:mockRetrieveJWTSigningCerts() Entering")
	defer log.Trace("resource/service_test:mockRetrieveJWTSigningCerts() Leaving")
	return nil
}

// TestAssetTagServiceNoExistingTags validates asset tag service without any tags - expect 200 OK
func TestAssetTagServiceNoExistingTags(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(false, nil)
	mockedTpmProvider.On("NvRelease", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvDefine", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvWrite", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
	assert.NoError(err)

	// setup TA service to use JWT-based authentication
	trustAgentService.router = mux.NewRouter()
	trustAgentService.router.Use(middleware.NewTokenAuth("../test/mockJWTDir", "../test/mockCACertsDir", mockRetrieveJWTSigningCerts, cacheTime))
	trustAgentService.router.HandleFunc("/v2/tag", errorHandler(requiresPermission(setAssetTag(CreateTestConfig(), mockedTpmFactory), []string{postDeployTagPerm}))).Methods("POST")

	jsonString := `{"tag" : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", "hardware_uuid" : "7a569dad-2d82-49e4-9156-069b0065b262"}`

	request, err := http.NewRequest("POST", "/v2/tag", bytes.NewBuffer([]byte(jsonString)))
	assert.NoError(err)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+TestJWTAuthToken)

	recorder := httptest.NewRecorder()
	trustAgentService.router.ServeHTTP(recorder, request)
	response := recorder.Result()
	fmt.Printf("StatusCode: %d\n", response.StatusCode)
	assert.Equal(http.StatusOK, response.StatusCode)
}

// TestAssetTagServiceExistingTags validates asset tag service with existing tags - expect 200 OK
func TestAssetTagServiceExistingTags(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvRelease", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvDefine", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvWrite", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
	assert.NoError(err)

	// setup TA service to use JWT-based authentication
	trustAgentService.router = mux.NewRouter()
	trustAgentService.router.Use(middleware.NewTokenAuth("../test/mockJWTDir", "../test/mockCACertsDir", mockRetrieveJWTSigningCerts, cacheTime))
	trustAgentService.router.HandleFunc("/v2/tag", errorHandler(requiresPermission(setAssetTag(CreateTestConfig(), mockedTpmFactory), []string{postDeployTagPerm}))).Methods("POST")

	jsonString := `{"tag" : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", "hardware_uuid" : "7a569dad-2d82-49e4-9156-069b0065b262"}`

	request, err := http.NewRequest("POST", "/v2/tag", bytes.NewBuffer([]byte(jsonString)))
	assert.NoError(err)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+TestJWTAuthToken)

	recorder := httptest.NewRecorder()
	trustAgentService.router.ServeHTTP(recorder, request)
	response := recorder.Result()
	fmt.Printf("StatusCode: %d\n", response.StatusCode)
	assert.Equal(http.StatusOK, response.StatusCode)
}

// TestBadToken - invalid JWT-tokens in request result - expect HTTP 401 Unauthorized response
func TestBadToken(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvRelease", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvDefine", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvWrite", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
	assert.NoError(err)

	// setup TA service to use JWT-based authentication
	trustAgentService.router = mux.NewRouter()
	trustAgentService.router.Use(middleware.NewTokenAuth("../test/mockJWTDir", "../test/mockCACertsDir", mockRetrieveJWTSigningCerts, cacheTime))
	trustAgentService.router.HandleFunc("/v2/tag", errorHandler(requiresPermission(setAssetTag(CreateTestConfig(), mockedTpmFactory), []string{postDeployTagPerm}))).Methods("POST")

	jsonString := `{"tag" : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", "hardware_uuid" : "7a569dad-2d82-49e4-9156-069b0065b262"}`

	request, err := http.NewRequest("POST", "/v2/tag", bytes.NewBuffer([]byte(jsonString)))
	assert.NoError(err)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+TestBadJWTAuthToken)

	recorder := httptest.NewRecorder()
	trustAgentService.router.ServeHTTP(recorder, request)
	response := recorder.Result()
	fmt.Printf("StatusCode: %d\n", response.StatusCode)
	assert.Equal(http.StatusUnauthorized, response.StatusCode)
}

// TestEmptyToken - empty JWT-tokens in request - expect HTTP 401 Unauthorized response
func TestEmptyToken(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvRelease", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvDefine", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvWrite", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
	assert.NoError(err)

	// setup TA service to use JWT-based authentication
	trustAgentService.router = mux.NewRouter()
	trustAgentService.router.Use(middleware.NewTokenAuth("../test/mockJWTDir", "../test/mockCACertsDir", mockRetrieveJWTSigningCerts, cacheTime))
	trustAgentService.router.HandleFunc("/v2/tag", errorHandler(requiresPermission(setAssetTag(CreateTestConfig(), mockedTpmFactory), []string{postDeployTagPerm}))).Methods("POST")

	jsonString := `{"tag" : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", "hardware_uuid" : "7a569dad-2d82-49e4-9156-069b0065b262"}`

	request, err := http.NewRequest("POST", "/v2/tag", bytes.NewBuffer([]byte(jsonString)))
	assert.NoError(err)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+EmptyJWTToken)

	recorder := httptest.NewRecorder()
	trustAgentService.router.ServeHTTP(recorder, request)
	response := recorder.Result()
	fmt.Printf("StatusCode: %d\n", response.StatusCode)
	assert.Equal(http.StatusUnauthorized, response.StatusCode)
}

// TestGetVersion - fetch version information from endpoint
func TestGetVersion(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(false, nil)
	mockedTpmProvider.On("NvRelease", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvDefine", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvWrite", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)

	trustAgentService.router.HandleFunc("/version", errorHandler(getVersion())).Methods("GET")

	// test request
	request, err := http.NewRequest("GET", "/version", nil)
	assert.NoError(err)

	recorder := httptest.NewRecorder()
	response := recorder.Result()
	trustAgentService.router.ServeHTTP(recorder, request)
	assert.Equal(http.StatusOK, response.StatusCode)
	fmt.Printf("Version: %s\n", recorder.Body.String())
	assert.NotEmpty(recorder.Body.String())
}

// func TestLocalIpAddress(t *testing.T) {
// 	assert := assert.New(t)

// 	ipString,err := util.GetLocalIpAsString()
// 	assert.NoError(err)

// 	// not local ip address or private address
// 	assert.False(strings.HasPrefix(ipString, "127"))
// 	assert.False(strings.HasPrefix(ipString, "192"))
// 	assert.Equal(strings.Index(ipString, "/"), -1)	// does not have /24 or /16

// 	fmt.Printf("Local ip string %s\n", ipString)

// 	ipBytes,err := util.GetLocalIpAsBytes()
// 	assert.NoError(err)
// 	assert.Equal(len(ipBytes), 4)

// 	fmt.Printf("Local ip bytes: %s\n", hex.EncodeToString(ipBytes))
// }

// func TestApplicationMeasurement(t *testing.T) {
// 	assert := assert.New(t)

// 	config.InitConfiguration()
// 	config.GetConfiguration().TrustAgentService.Username = TestUser
// 	config.GetConfiguration().TrustAgentService.Password = TestPassword
// 	config.GetConfiguration().Tpm.OwnerSecretKey = TpmSecretKey
// 	trustAgentService, err := CreateTrustAgentService(8450)
// 	assert.NoError(err)

// 	manifestXml := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// 	<Manifest xmlns="lib:wml:measurements:1.0" Label="ISecL_Default_Workload_Flavor_v1.0" Uuid="7a9ac586-40f9-43b2-976b-26667431efca" DigestAlg="SHA384">
// 	   <Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/workload-agent/bin"/>
// 	   <Symlink Path="/opt/workload-agent/bin/wlagent"/>
// 	   <File Path="/opt/workload-agent/bin/.*" SearchType="regex"/>
// 	</Manifest>`

// 	request, err := http.NewRequest("POST", "/v2/host/application-measurement", bytes.NewBuffer([]byte(manifestXml)))
// 	assert.NoError(err)

// 	request.Header.Set("Content-Type", "application/xml")
// 	request.SetBasicAuth(TestUser, TestPassword)

// 	recorder := httptest.NewRecorder()
// 	trustAgentService.router.ServeHTTP(recorder, request)
// 	response := recorder.Result()
// 	fmt.Printf("StatusCode: %d\n", response.StatusCode)
// 	assert.Equal(response.StatusCode, http.StatusOK)
// }

// func TestDeployManifest(t *testing.T) {
// 	assert := assert.New(t)

// 	config.InitConfiguration()
// 	config.GetConfiguration().TrustAgentService.Username = TestUser
// 	config.GetConfiguration().TrustAgentService.Password = TestPassword
// 	config.GetConfiguration().Tpm.OwnerSecretKey = TpmSecretKey
// 	trustAgentService, err := CreateTrustAgentService(8450)
// 	assert.NoError(err)

// 	manifestXml := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// 	<Manifest xmlns="lib:wml:manifests:1.0" Label="New_Software_Flavor" Uuid="1fe1b7fc-99e6-4e7e-ba3d-d9aeeb03d227" DigestAlg="SHA384">
// 	<File Path="/opt/trustagent/.*" SearchType="regex"/>
// 	</Manifest>`

// 	request, err := http.NewRequest("POST", "/v2/deploy/manifest", bytes.NewBuffer([]byte(manifestXml)))
// 	assert.NoError(err)

// 	request.Header.Set("Content-Type", "application/xml")
// 	request.SetBasicAuth(TestUser, TestPassword)

// 	recorder := httptest.NewRecorder()
// 	trustAgentService.router.ServeHTTP(recorder, request)
// 	response := recorder.Result()
// 	fmt.Printf("StatusCode: %d\n", response.StatusCode)
// 	assert.Equal(response.StatusCode, http.StatusOK)
// }
