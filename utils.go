package oauth2

import (
	"encoding/json"
	"net/http"
)

func writerJSON(w http.ResponseWriter, statusCode int, value interface{}) (err error) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(statusCode)
	jsonEncoder := json.NewEncoder(w)
	err = jsonEncoder.Encode(value)
	return
}

// WriterJSON 写入Json
func WriterJSON(w http.ResponseWriter, value interface{}) (err error) {
	err = writerJSON(w, http.StatusOK, value)
	return
}

// WriterError 写入Error
func WriterError(w http.ResponseWriter, err error) {
	if werr := writerJSON(w, http.StatusBadRequest, map[string]string{
		"error": err.Error(),
	}); werr != nil {
		panic(werr)
	}
}
