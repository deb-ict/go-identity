package http

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func Test_GetScopesParam_ValidData(t *testing.T) {
	data := url.Values{}
	data.Set("scope", "api.read api.write")

	req := httptest.NewRequest(http.MethodPost, "/dummy", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	scopes, err := GetScopesParam(req)
	if err != nil {
		t.Errorf("GetScopesParam failed: got error %v, expected nil", err)
	}
	if len(scopes) != 2 {
		t.Errorf("GetScopesParam failed: got %v scopes, expected 2", len(scopes))
	}
}

func Test_GetScopesParam_MultiData(t *testing.T) {
	data := url.Values{}
	data.Add("scope", "api.read api.write")
	data.Add("scope", "api.delete")

	req := httptest.NewRequest(http.MethodPost, "/dummy", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	scopes, err := GetScopesParam(req)
	if err == nil || err.Error() != "invalid_request" {
		t.Error("GetScopesParam failed: got error nil, expected invalid_request")
	}
	if len(scopes) != 0 {
		t.Errorf("GetScopesParam failed: got %v scopes, expected 0", len(scopes))
	}
}

func Test_GetScopesParam_NoParam(t *testing.T) {
	data := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/dummy", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	scopes, err := GetScopesParam(req)
	if err != nil {
		t.Errorf("GetScopesParam failed: got error %v, expected nil", err)
	}
	if len(scopes) != 0 {
		t.Errorf("GetScopesParam failed: got %v scopes, expected 0", len(scopes))
	}
}

func Test_GetScopesParam_FormParsingError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/dummy", nil)
	req.Header.Set("Content-Type", "/invalid")

	scopes, err := GetScopesParam(req)
	if err == nil || err.Error() != "invalid_request" {
		t.Error("GetScopesParam failed: got error nil, expected invalid_request")
	}
	if len(scopes) != 0 {
		t.Errorf("GetScopesParam failed: got %v scopes, expected 0", len(scopes))
	}
}

func Test_GetStringParam_ValidData(t *testing.T) {
	data := url.Values{}
	data.Set("test", "value")

	req := httptest.NewRequest(http.MethodPost, "/dummy", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	value, err := GetStringParam(req, "test")
	if err != nil {
		t.Errorf("GetStringParam failed: got error %v, expected nil", err)
	}
	if value != "value" {
		t.Errorf("GetStringParam failed: got value %v, expected value", value)
	}
}

func Test_GetStringParam_MultiData(t *testing.T) {
	data := url.Values{}
	data.Add("test", "value a")
	data.Add("test", "value b")

	req := httptest.NewRequest(http.MethodPost, "/dummy", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	value, err := GetStringParam(req, "test")
	if err == nil || err.Error() != "invalid_request" {
		t.Error("GetStringParam failed: got error nil, expected invalid_request")
	}
	if value != "" {
		t.Errorf("GetStringParam failed: got value %v, expected empty string", value)
	}
}

func Test_GetStringParam_NoData(t *testing.T) {
	data := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/dummy", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	value, err := GetStringParam(req, "test")
	if err == nil || err.Error() != "invalid_request" {
		t.Error("GetStringParam failed: got error nil, expected invalid_request")
	}
	if value != "" {
		t.Errorf("GetStringParam failed: got value %v, expected empty string", value)
	}
}

func Test_GetStringParam_FormParsingError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/dummy", nil)
	req.Header.Set("Content-Type", "/invalid")

	value, err := GetStringParam(req, "test")
	if err == nil || err.Error() != "invalid_request" {
		t.Error("GetStringParam failed: got error nil, expected invalid_request")
	}
	if value != "" {
		t.Errorf("GetStringParam failed: got value %v, expected empty string", value)
	}
}
