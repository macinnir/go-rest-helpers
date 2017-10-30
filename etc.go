package util

import (
	"fmt"
	"os"
	"time"
)

// CheckErr checks if an error is nil, and panics if it isn't
func CheckErr(err error) {
	if err != nil {
		fmt.Printf("Err was not nil %s", err.Error())
		panic(err)
	}
}

// RequireFile checks if a file exists and exits the application if it doesn't
func RequireFile(fileName string) {
	fmt.Printf("Checking if file %s exists\n", fileName)
	if _, err := os.Stat(fileName); err != nil {
		fmt.Printf("Required file %s does not exist. Quitting...\n", fileName)
		os.Exit(1)
	}
}

// DateString returns an ISO 8601 string (for mysql datetime)
func DateString(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// DateStringNow returns an ISO 8601 string representation of the current time
func DateStringNow() string {
	return DateString(time.Now())
}

func BuildSelf(path string) string {
	self := "http"

	if Config.HTTPS {
		self = self + "s"
	}

	self = self + "://" + Config.PublicDomain

	if Config.Port != "80" {
		self = self + ":" + Config.Port
	}

	self = self + "/" + Config.URLVersionPrefix + "/" + path
	return self
}
