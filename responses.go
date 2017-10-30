package util

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
)

// NotImplemented shows a text response for not implemented method (501)
func NotImplemented(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Header().Set("content-type", "text/plain")
	return
}

func NotImplementedHandler(w http.ResponseWriter, r *http.Request) {
	NotImplemented(w)
}

// ErrorResponse is the structure of a response that is an error
// @model ErrorResponse
type ErrorResponse struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// NotFound returns a not-found status
func NotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	w.Header().Set("content-type", "text/plain")
	log.Println("NOT FOUND")
	return
}

// BadRequest returns a bad request status (400)
func BadRequest(w http.ResponseWriter, err string) {
	w.WriteHeader(http.StatusBadRequest)
	errorResponse := ErrorResponse{}
	errorResponse.Status = "400"
	errorResponse.Detail = err

	JSON(w, errorResponse)
	return
}

// Unauthorized returns an unauthorized status (401)
func Unauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("content-type", "text/plain")
}

// Forbidden returns a forbidden status (403)
func Forbidden(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("content-type", "text/plain")
}

// NoContent returns a noContent status (204)
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
	w.Header().Set("content-type", "text/plain")
}

// Created returns a created status (201)
func Created(w http.ResponseWriter) {
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("content-type", "text/plain")
}

// JSON Returns an ok status with json-encoded body
func JSON(w http.ResponseWriter, body interface{}) {
	payload, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(payload))
}

// OK Returns an ok status
func OK(w http.ResponseWriter) {
	w.Header().Set("content-type", "text/plain")
}

// GetBodyJSON extracts the json from the body of a post or put request
func GetBodyJSON(r *http.Request, obj interface{}) (e error) {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	e = decoder.Decode(obj)
	return
}

// QueryArgInt checks the incoming request `r` for a query argument named `name`
// and if it exists, attempts to parse it to an integer
// If the argument does not exist, the value `defaultVal` is returned
func QueryArgInt(r *http.Request, name string, defaultVal int) (val int, e error) {

	val = 0
	stringVal := r.URL.Query().Get(name)

	if len(stringVal) > 0 {

		val, e = strconv.Atoi(stringVal)

		if e != nil {
			return
		}

		return
	}

	val = defaultVal

	return
}

// QueryArgString checks the incoming request `r` for a query argument named `name`
// and if it exists, returns it
// Else, it returns `defaultVal`
func QueryArgString(r *http.Request, name string, defaultVal string) (val string) {

	stringVal := r.URL.Query().Get(name)

	if len(stringVal) > 0 {
		val = stringVal
		return
	}

	val = defaultVal
	return
}
