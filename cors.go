package util

import (
	"net/http"
)

// HandleCors handles all OPTIONS requests
var HandleCors = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
	w.Header().Set("content-type", "text/plain")
})

// CORSHandler is middleware to handle cors requests
func CORSHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")

		if r.Method == "OPTIONS" {
			w.Header().Set("content-type", "text/plain")
			return
		}

		h.ServeHTTP(w, r)
	}
}
