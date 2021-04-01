/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/setup"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"intel/isecl/go-trust-agent/v3/constants"
	"intel/isecl/lib/common/v3/setup"
)

const (
	AIK_SECRET_KEY = "aik.secret"
)

//
//  Adapted from certificate-management-service/config/config.go
//

type TrustAgentConfiguration struct {
	configFile string
	Logging    struct {
		LogLevel          string // TRUSTAGENT_LOG_LEVEL
		LogEnableStdout   bool   // TA_ENABLE_CONSOLE_LOG
		LogEntryMaxLength int    // LOG_ENTRY_MAXLENGTH (NEEDS TO BE IN LLD)
	}
	WebService struct {
		Port              int           // TRUSTAGENT_PORT
		ReadTimeout       time.Duration // TA_SERVER_READ_TIMEOUT
		ReadHeaderTimeout time.Duration // TA_SERVER_READ_HEADER_TIMEOUT
		WriteTimeout      time.Duration // TA_SERVER_WRITE_TIMEOUT
		IdleTimeout       time.Duration // TA_SERVER_IDLE_TIMEOUT
		MaxHeaderBytes    int           // TA_SERVER_MAX_HEADER_BYTES
	}
	HVS struct {
		Url string // HVS_URL
	}
	Tpm struct {
		OwnerSecretKey string // TPM_OWNER_SECRET (generated if not provided during take-ownership)
		AikSecretKey   string // Generated in provision-aik
	}
	AAS struct {
		BaseURL string // AAS_API_URL
	}
	CMS struct {
		BaseURL       string // CMS_BASE_URL
		TLSCertDigest string // CMS_TLS_CERT_SHA384
	}
	TLS struct {
		CertSAN string // SAN_LIST
		CertCN  string // TA_TLS_CERT_CN
	}
}

var mu sync.Mutex
var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func NewConfigFromYaml(pathToYaml string) (*TrustAgentConfiguration, error) {

	var c TrustAgentConfiguration
	file, err := os.Open(pathToYaml)
	if err == nil {
		defer func() {
			derr := file.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing file")
			}
		}()
		err = yaml.NewDecoder(file).Decode(&c)
		if err != nil {
			return nil, err
		}
	} else {
		// file doesnt exist, create a new blank one
		c.Logging.LogLevel = logrus.InfoLevel.String()
	}

	c.configFile = pathToYaml
	return &c, nil
}

var ErrNoConfigFile = errors.New("no config file")

func (cfg *TrustAgentConfiguration) Save() error {
	if cfg.configFile == "" {
		return ErrNoConfigFile
	}

	file, err := os.OpenFile(cfg.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.OpenFile(cfg.configFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			err = os.Chmod(cfg.configFile, 0660)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()
	secLog.Info(message.ConfigChanged)
	err = yaml.NewEncoder(file).Encode(cfg)
	if err != nil {
		return err
	}

	log.Debug("Successfully updated config.yaml")
	return nil
}

// This function will load environment variables into the TrustAgentConfiguration
// structure.  It does not validate the presence of env/config values since that
// is handled 'lazily' by setup tasks.
func (cfg *TrustAgentConfiguration) LoadEnvironmentVariables() error {
	var err error
	dirty := false
	var context setup.Context

	//---------------------------------------------------------------------------------------------
	// TPM_OWNER_SECRET
	//---------------------------------------------------------------------------------------------
	environmentVariable, err := context.GetenvSecret(constants.EnvTPMOwnerSecret, "TPM Owner Secret")
	if environmentVariable != "" && cfg.Tpm.OwnerSecretKey != environmentVariable {
		cfg.Tpm.OwnerSecretKey = environmentVariable
		dirty = true
	} // else := ok (This field may be generated in tasks/take-ownership when not present.)

	//---------------------------------------------------------------------------------------------
	// HVS_URL
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvMtwilsonAPIURL, "Verification Service API URL")
	if environmentVariable != "" && cfg.HVS.Url != environmentVariable {
		cfg.HVS.Url = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_PORT
	//---------------------------------------------------------------------------------------------
	port := 0
	port, err = context.GetenvInt(constants.EnvTAPort, "Trust Agent Listener Port")
	if port == 0 { // zero indicates the env was not present
		port = constants.DefaultPort
	}

	if cfg.WebService.Port != port {
		cfg.WebService.Port = port
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// AAS_API_URL
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvAASBaseURL, "AAS API Base URL")
	if environmentVariable != "" && cfg.AAS.BaseURL != environmentVariable {
		if strings.HasSuffix(environmentVariable, "/") {
			cfg.AAS.BaseURL = environmentVariable
		} else {
			cfg.AAS.BaseURL = environmentVariable + "/"
		}
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// CMS_BASE_URL
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvCMSBaseURL, "CMS Base URL")
	if environmentVariable != "" && cfg.CMS.BaseURL != environmentVariable {
		cfg.CMS.BaseURL = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// LOG_ENTRY_MAXLENGTH
	//---------------------------------------------------------------------------------------------
	logEntryMaxLength, err := context.GetenvInt(constants.LogEntryMaxlengthEnv, "Maximum length of each entry in a log")
	if err == nil && logEntryMaxLength >= 300 {
		cfg.Logging.LogEntryMaxLength = logEntryMaxLength
	} else {
		fmt.Println("Invalid Log Entry Max Length defined (should be >= ", constants.DefaultLogEntryMaxlength, "), using default value:", constants.DefaultLogEntryMaxlength)
		cfg.Logging.LogEntryMaxLength = constants.DefaultLogEntryMaxlength
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_LOG_LEVEL
	//---------------------------------------------------------------------------------------------
	ll, err := context.GetenvString("TRUSTAGENT_LOG_LEVEL", "Logging Level")
	if err != nil {
		llp, err := logrus.ParseLevel(ll)
		if err == nil {
			cfg.Logging.LogLevel = llp.String()
			fmt.Printf("Log level set %s\n", ll)
			dirty = true
		}
	} else {
		fmt.Println("There was an error retreiving the log level from TRUSTAGENT_LOG_LEVEL")
	}

	if cfg.Logging.LogLevel == "" {
		fmt.Println("TRUSTAGENT_LOG_LEVEL not defined, using default log level: Info")
		cfg.Logging.LogLevel = logrus.InfoLevel.String()
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// CMS_TLS_CERT_SHA384
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvCMSTLSCertDigest, "CMS TLS SHA384 Digest")
	if environmentVariable != "" {
		if len(environmentVariable) != 96 {
			return errors.Errorf("config/config:LoadEnvironmentVariables()  Invalid length %s: %d", constants.EnvCMSTLSCertDigest, len(environmentVariable))
		}

		if err = validation.ValidateHexString(environmentVariable); err != nil {
			return errors.Errorf("config/config:LoadEnvironmentVariables()  %s is not a valid hex string: %s", constants.EnvCMSTLSCertDigest, environmentVariable)
		}

		if cfg.CMS.TLSCertDigest != environmentVariable {
			cfg.CMS.TLSCertDigest = environmentVariable
			dirty = true
		}
	}

	//---------------------------------------------------------------------------------------------
	// TA_TLS_CERT_CN
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvTLSCertCommonName, "Trustagent TLS Certificate Common Name")
	if err == nil && environmentVariable != "" {
		cfg.TLS.CertCN = environmentVariable
	} else if strings.TrimSpace(cfg.TLS.CertCN) == "" {
		fmt.Printf("TA_TLS_CERT_CN not defined, using default value %s\n", constants.DefaultTaTlsCn)
		cfg.TLS.CertCN = constants.DefaultTaTlsCn
	}

	//---------------------------------------------------------------------------------------------
	// SAN_LIST
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvCertSanList, "Trustagent TLS Certificate SAN LIST")
	if err == nil && environmentVariable != "" {
		cfg.TLS.CertSAN = environmentVariable
	} else if strings.TrimSpace(cfg.TLS.CertSAN) == "" {
		fmt.Printf("SAN_LIST not defined, using default value %s\n", constants.DefaultTaTlsSan)
		cfg.TLS.CertSAN = constants.DefaultTaTlsSan
	}

	//---------------------------------------------------------------------------------------------
	// TA_ENABLE_CONSOLE_LOG
	//---------------------------------------------------------------------------------------------
	cfg.Logging.LogEnableStdout = false
	logEnableStdout, err := context.GetenvString("TA_ENABLE_CONSOLE_LOG", "Trustagent Enable standard output")
	if err == nil && logEnableStdout != "" {
		cfg.Logging.LogEnableStdout, err = strconv.ParseBool(logEnableStdout)
		if err != nil {
			fmt.Println("Error while parsing the variable TA_ENABLE_CONSOLE_LOG, setting to default value false")
		}
	}

	//---------------------------------------------------------------------------------------------
	// HTTP Server Settings
	//---------------------------------------------------------------------------------------------
	readTimeout, err := context.GetenvInt("TA_SERVER_READ_TIMEOUT", "Trustagent Read Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable TA_SERVER_READ_TIMEOUT, setting default value 30s")
		cfg.WebService.ReadTimeout = constants.DefaultReadTimeout
	} else {
		cfg.WebService.ReadTimeout = time.Duration(readTimeout) * time.Second
	}

	readHeaderTimeout, err := context.GetenvInt("TA_SERVER_READ_HEADER_TIMEOUT", "Trustagent Read Header Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable TA_SERVER_READ_HEADER_TIMEOUT, setting default value 10s")
		cfg.WebService.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		cfg.WebService.ReadHeaderTimeout = time.Duration(readHeaderTimeout) * time.Second
	}

	writeTimeout, err := context.GetenvInt("TA_SERVER_WRITE_TIMEOUT", "Trustagent Write Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable TA_SERVER_WRITE_TIMEOUT, setting default value 10s")
		cfg.WebService.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		cfg.WebService.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}

	idleTimeout, err := context.GetenvInt("TA_SERVER_IDLE_TIMEOUT", "Trustagent Idle Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable TA_SERVER_IDLE_TIMEOUT, setting default value 10s")
		cfg.WebService.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		cfg.WebService.IdleTimeout = time.Duration(idleTimeout) * time.Second
	}

	maxHeaderBytes, err := context.GetenvInt("TA_SERVER_MAX_HEADER_BYTES", "Trustagent Max Header Bytes Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable TA_SERVER_MAX_HEADER_BYTES, setting default value 10s")
		cfg.WebService.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		cfg.WebService.MaxHeaderBytes = maxHeaderBytes
	}

	//---------------------------------------------------------------------------------------------
	// Save config if 'dirty'
	//---------------------------------------------------------------------------------------------
	if dirty {
		err = cfg.Save()
		if err != nil {
			return errors.Wrap(err, "Error saving configuration")
		}
	}

	return nil
}

// This function validates whether or not the configuration has enough information to start the http
// service.  It requires the TPM owner/aik secret, port and AAS URL to run (all other configuration is
// required during setup).
func (cfg *TrustAgentConfiguration) Validate() error {

	if cfg.Tpm.OwnerSecretKey == "" {
		return errors.New("The Trust-Agent service requires that the configuration contains a TPM 'owner' secret.")
	}

	if cfg.Tpm.AikSecretKey == "" {
		return errors.New("The Trust-Agent service requires that the configuration contains a TPM 'aik' secret.")
	}

	if cfg.WebService.Port == 0 || cfg.WebService.Port > 65535 {
		return errors.Errorf("The Trust-Agent service requires that the configuration contains a valid port number: '%d'", cfg.WebService.Port)
	}

	if cfg.AAS.BaseURL == "" {
		return errors.New("The Trust-Agent service requires that the configuration contains an AAS url.")
	}

	return nil
}

func (cfg *TrustAgentConfiguration) PrintConfigSetting(settingKey string) {

	switch settingKey {
	case AIK_SECRET_KEY:
		fmt.Printf("%s\n", cfg.Tpm.AikSecretKey)
	default:
		fmt.Printf("Unknown config parameter: %s\n", settingKey)
	}
}

func (cfg *TrustAgentConfiguration) LogConfiguration(stdOut bool) {
	log.Trace("config/config:LogConfiguration() Entering")
	defer log.Trace("config/config:LogConfiguration() Leaving")

	// creating the log file if not preset
	var ioWriterDefault io.Writer
	defaultLogFile, _ := os.OpenFile(constants.DefaultLogFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
	secLogFile, _ := os.OpenFile(constants.SecurityLogFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)

	ioWriterDefault = defaultLogFile
	if stdOut {
		ioWriterDefault = io.MultiWriter(os.Stdout, defaultLogFile)
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, secLogFile)

	if cfg.Logging.LogLevel == "" {
		cfg.Logging.LogLevel = logrus.InfoLevel.String()
	}

	llp, err := logrus.ParseLevel(cfg.Logging.LogLevel)
	if err != nil {
		cfg.Logging.LogLevel = logrus.InfoLevel.String()
		llp, _ = logrus.ParseLevel(cfg.Logging.LogLevel)
	}
	commLogInt.SetLogger(commLog.DefaultLoggerName, llp, &commLog.LogFormatter{MaxLength: cfg.Logging.LogEntryMaxLength}, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, llp, &commLog.LogFormatter{MaxLength: cfg.Logging.LogEntryMaxLength}, ioWriterSecurity, false)

	secLog.Infof("config/config:LogConfiguration() %s", message.LogInit)
	log.Infof("config/config:LogConfiguration() %s", message.LogInit)
}
