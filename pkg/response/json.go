package response

import (
	"encoding/json"
	"net/http"
)

func JsonNoCache(w http.ResponseWriter, data interface{}, statusCode int) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(data)
}
