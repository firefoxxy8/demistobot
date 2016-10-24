// Package conf provides basic configuration handling from a file exposing a single global struct with all configuration.
package conf

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/Sirupsen/logrus"
)

// Options anonymous struct holds the global configuration options for the server
var Options struct {
	// The address to listen on
	Address string
	// The HTTP address to listen on if the main address is HTTPS
	HTTPAddress string
	// ExternalAddress to our web tier
	ExternalAddress string
	// SSL configuration
	SSL struct {
		// The certificate file
		Cert string
		// The private key file
		Key string
	}
	// User details
	User struct {
		// Username for log retrieval
		Username string
		// Password for log retrieval
		Password string
	}
	// DB properties
	DB struct {
		// Path is DB file location
		Path string
	}
	// Log location and level
	Log struct {
		// Where to write the log to
		Path string
		// Level of the log
		Level string
	}
	// Slack application credentials
	Slack struct {
		// ClientID is passed to the OAuth request
		ClientID string
		// ClientSecret is used to verify Slack reply
		ClientSecret string
	}
	// Location of the static resources
	Static string
}

// The pipe writer to wrap around standard logger. It is configured in main.
var LogWriter *io.PipeWriter

// Load loads configuration from a file.
func Load(filename string) error {
	options, err := ioutil.ReadFile(filename)
	if err != nil {
		logrus.WithField("error", err).Warn("Could not open config file")
		return err
	} else {
		err = json.Unmarshal(options, &Options)
		if err != nil {
			return err
		}
	}
	return nil
}

func Default() {
	Options.Address = ":9090"
	Options.DB.Path = "demistobot.db"
	Options.Static = "static"
	Options.User.Username = "admin"
	Options.User.Password = "password"
	Options.Log.Level = "debug"
}
