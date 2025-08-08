package jwtauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	secureservemux "github.com/beegentoo/SecureServeMux"
	"github.com/golang-jwt/jwt/v5"
)

func Test_DemonstrateUsage(t *testing.T) {
	//t.SkipNow()

	// We authenticate using a JWT issued by Keycloak
	cut, err := NewKeycloakJWTAuth(
		"http://localhost:8090",
		"DemoRealm",
		NewRoleBasedAccess("DemoRole"),
	)

	if err != nil {
		t.Fatal(err)
	}
	// Create a new secured handler for /test
	mux := secureservemux.NewSecureServeMux(cut)
	mux.AuthHandleFunc("GET /test", func(w http.ResponseWriter, r *http.Request) {
		var mapClaims jwt.MapClaims = r.Context().Value("jwtClaims").(jwt.MapClaims)
		fvVal, isSet := mapClaims["fixedValue"]
		if !isSet {
			t.Fatal("Special Value in Token should be there")
		}

		if fvVal != "2223" {
			t.Fatal("wrong value in token")
		}
	})

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	demoToken, err := obtainDemoToken()
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", demoToken))

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
}

// Helper function to obtain a Demo-Token from a keycloak-instance.
// For simplicity we just use the client credentials
func obtainDemoToken() (string, error) {

	tokenEndpointUrl := "http://localhost:8090/realms/DemoRealm/protocol/openid-connect/token"
	grantType := "client_credentials"
	clientId := "TestClient"
	clientSecret := "0JOgagogLtLHCKm9MQEdLxPdqxiLJcUv" // When testing, place the client-secret here

	requestPayload := fmt.Sprintf("grant_type=%s&client_id=%s&client_secret=%s", grantType, clientId, clientSecret)

	req, err := http.NewRequest(
		http.MethodPost,
		tokenEndpointUrl,
		strings.NewReader(requestPayload),
	)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	respBuf, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// Keycloak's response is a JSON-Container:
	// {
	//   "access_token" : " ... ",  // this is wat we want
	//   "expires_in" : ...
	//   "refresh_expires_in": ...
	//   "token_type": ...
	//   "not-before-policy": ...
	//   "scope": ...
	// }

	var respMap map[string]json.RawMessage
	json.Unmarshal(respBuf, &respMap)

	var accessToken string
	json.Unmarshal(respMap["access_token"], &accessToken)

	return accessToken, nil
}
