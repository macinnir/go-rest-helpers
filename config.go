package util

import (
	"log"

	"github.com/Tkanos/gonfig"
)

var (
	// Config represents a collection of the global config values
	Config IConfig
)

// IConfig is an interface for basic config functionality
type IConfig interface {
	IsHttps() bool
	PublicDomain() string
	Port() string
	URLVersionPrefix() string
}

// LoadConfig the global configuration values from json
func LoadConfig(path string, configObj IConfig) {
	// Load loads the config
	// Config = ConfigObj{}
	Config = configObj
	configErr := gonfig.GetConf(path, configObj)
	if configErr != nil {
		log.Fatal("Config Error:", configErr)
	}
}
