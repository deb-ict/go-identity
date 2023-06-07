package test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func dummyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "TOKEN")
}

func Test_Token_ClientCredentials(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/token", nil)

	dummyHandler(rec, req)

	res := rec.Result()
	exp := http.StatusOK

	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("Call failed: Expected error to be nil, got %v", err)
	}
	if string(data) != "TOKEN" {
		t.Errorf("Call failed: Invalid body: got %v, expected TOKEN", err)
	}
	if res.StatusCode != exp {
		t.Errorf("Call failed: Invalid status code: got %v, expected %v", res.StatusCode, exp)
	}
}
