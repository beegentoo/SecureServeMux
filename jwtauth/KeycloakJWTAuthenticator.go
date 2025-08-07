package jwtauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// Creates a new KeycloakJWT-Authenticator
func NewKeycloakJWTAuth(url string, realm string, strategy AuthorizationStrategy) (*KeycloakJWTAuthenticator, error) {

	// We retrieve the certificate from the issuing Keycloak-Instance and -realm
	var certRetrieverFunc CertRetrieverFunc = func(token *jwt.Token) (string, error) {
		issuer, err := token.Claims.GetIssuer()
		if err != nil {
			return "", err
		}

		jwks, err := loadJWKS(issuer)
		if err != nil {
			return "", err
		}
		effectiveKs, err := jwks.GetJWKForToken(token)
		if err != nil {
			return "", err
		}

		return effectiveKs.X5c[0], nil
	}

	genAuth, err := NewGenericJWTAuthenticator(
		fmt.Sprintf("%s/realms/%s", url, realm),
		certRetrieverFunc,
		strategy,
	)
	if err != nil {
		return nil, err
	}

	kka := &KeycloakJWTAuthenticator{
		Url:                     url,
		Realm:                   realm,
		GenericJWTAuthenticator: genAuth,
	}
	return kka, nil
}

// Authenticates a JWT issued by a Keycloak Instance
type KeycloakJWTAuthenticator struct {
	*GenericJWTAuthenticator
	Url   string // Base URL of the keycloak instance to use
	Realm string // Realm that managed the authentication
}

// Load keycloak's JSON Web Key Set
func loadJWKS(issuerUrl string) (*JWKS, error) {
	certUrl := fmt.Sprintf("%s/protocol/openid-connect/certs", issuerUrl)
	request, _ := http.NewRequest(http.MethodGet, certUrl, nil)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}

	respBuf, _ := io.ReadAll(response.Body)

	var jwks JWKS
	json.Unmarshal(respBuf, &jwks)

	return &jwks, nil
}

// Structs representing the structure of
// Keycloak's cert-page (at /protocol/openid-connect/certs below the realm url)
type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid     string   `json:"kid"`
	Kty     string   `json:"kty"`
	Alg     string   `json:"alg"`
	Use     string   `json:"use"`
	N       string   `json:"n"`
	E       string   `json:"e"`
	X5c     []string `json:"x5c"`
	X5t     string   `json:"x5t"`
	X5tS256 string   `json:"x5t#S256"`
}

// Retrieve the proper JWK for the provided token. The Key-Id (kid)
// is part of a JWT-Header. This Key-ID is used to identify the certificate
// and subsequently the appropriate Public-Key
func (j JWKS) GetJWKForToken(token *jwt.Token) (JWK, error) {
	var kid string = token.Header["kid"].(string)
	for _, currKey := range j.Keys {
		if currKey.Kid == kid {
			return currKey, nil
		}
	}
	return JWK{}, fmt.Errorf("no Key for kid %s", kid)
}
