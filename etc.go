package util

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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

// BuildSelf builds a url for the current object
func BuildSelf(path string) string {
	self := "http"

	if Config.IsHttps() == true {
		self = self + "s"
	}

	self = self + "://" + Config.PublicDomain()

	if Config.Port() != "80" {
		self = self + ":" + Config.Port()
	}

	self = self + "/" + Config.URLVersionPrefix() + "/" + path
	return self
}

// WaitForShutdown waits for shutdown from the http server
func WaitForShutdown(srv *http.Server) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive our signal.
	<-interruptChan

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	srv.Shutdown(ctx)

	log.Println("Shutting down")
	os.Exit(0)
}

// GetEnv gets an environment variable
func GetEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
