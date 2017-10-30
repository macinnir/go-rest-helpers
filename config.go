package util

import (
	"log"

	"github.com/Tkanos/gonfig"
)

// Config represents the application configuration options
// @model Config
type ConfigObj struct {
	DBName            string `json:"dbName"`
	DBHost            string `json:"dbHost"`
	DBUser            string `json:"dbUser"`
	DBPass            string `json:"dbPass"`
	Domain            string `json:"domain"`
	Port              string `json:"port"`
	HTTPS             bool   `json:"https"`
	URLVersionPrefix  string `json:"urlVersionPrefix"`
	TokenExpiryMinute int    `json:"tokenExpiryMinute"`
	TokenIssuerName   string `json:"tokenIssuerName"`
	PublicDomain      string `json:"publicDomain"`
}

var (
	// Config represents a collection of the global config values
	Config ConfigObj
)

// LoadConfig the global configuration values from json
func LoadConfig(path string) {
	// Load loads the config
	Config = ConfigObj{}
	configErr := gonfig.GetConf(path, &Config)
	if configErr != nil {
		log.Fatal("Config Error:", configErr)
	}
}
