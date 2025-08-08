package veryunsafedemo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	secureservemux "github.com/beegentoo/SecureServeMux"
)

func Test_Authorize_Fail(t *testing.T) {
	mux := secureservemux.NewSecureServeMux(VeryUnsaveDevAuthenticator{})
	mux.AuthHandleFunc("GET /test", func(w http.ResponseWriter, r *http.Request) {
		// Nothing happens here
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Error("no token provided -- it should fail")
	}
}

func Test_Authorize_Succeed(t *testing.T) {
	mux := secureservemux.NewSecureServeMux(VeryUnsaveDevAuthenticator{})
	mux.AuthHandleFunc("GET /test", func(w http.ResponseWriter, r *http.Request) {
		// Nothing happens here
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("AUThORiZATion", "this is unsave!")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Error("auth should have succeeded")
	}

}
