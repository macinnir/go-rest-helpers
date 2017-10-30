package util

import (
	"net/http"

	"github.com/gorilla/mux"
)

func testResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain")
	w.Write([]byte("hello?"))
}

// AddRoutes adds utility routes for documentation etc.
func AddRoutes(r *mux.Router) {
	r.PathPrefix("/docs/").Handler(http.StripPrefix("/docs/", http.FileServer(http.Dir("./docs/"))))
}
