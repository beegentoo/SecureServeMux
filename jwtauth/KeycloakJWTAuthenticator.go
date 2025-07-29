package jwtauth

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func NewKeycloakJWTAuth(url string, realm string, strategy AuthorizationStrategy) KeycloakJWTAuthenticator {
	return KeycloakJWTAuthenticator{
		Url:      url,
		Realm:    realm,
		Strategy: strategy,
		logger:   log.New(os.Stdout, "KeycloakJWT: ", log.LstdFlags),
	}
}

// Authenticate a JWT issued by a Keycloak Instance
type KeycloakJWTAuthenticator struct {
	Url      string                // Base URL of the keycloak instance to use
	Realm    string                // Realm that managed the authentication
	Strategy AuthorizationStrategy // Which strategy should be used when the JWT is validated
	logger   *log.Logger
}

func (k KeycloakJWTAuthenticator) Authorize(w http.ResponseWriter, r *http.Request) (bool, error) {
	tokenHead, err := k.extractAuthHeader(r)
	if err != nil {
		return false, err
	}

	token, err := k.verifyToken(tokenHead)
	if err != nil {
		k.logger.Print(err.Error())
		return false, err
	}

	var isValid bool = false
	isValid, err = k.Strategy.Validate(token)
	if err != nil || !isValid {
		k.logger.Print(err.Error())
		return false, err
	}

	return true, nil
}

// Validate the provided token. On successful validation, the token is returned. An Error otherwise
func (k KeycloakJWTAuthenticator) verifyToken(token string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(token, k.keyfunc, jwt.WithIssuer(fmt.Sprintf("%s/realms/%s", k.Url, k.Realm)))
	if err != nil {
		return nil, err
	}
	return parsedToken, nil
}

func (k KeycloakJWTAuthenticator) extractAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" || !strings.HasPrefix(strings.ToUpper(authHeader), "BEARER ") {
		return "", fmt.Errorf("no authorization header or bearer token provided")
	}

	return authHeader[7:], nil
}

func (k KeycloakJWTAuthenticator) keyfunc(token *jwt.Token) (any, error) {
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		return nil, err
	}

	jwks, err := k.loadJWKS(issuer)
	if err != nil {
		return nil, err
	}
	effectiveKs, err := jwks.GetJWKForToken(token)

	if err != nil {
		return nil, err
	}

	certPem := k.toPem(effectiveKs.X5c[0])

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey, nil
}

func (k KeycloakJWTAuthenticator) loadJWKS(issuerUrl string) (*JWKS, error) {
	certUrl := fmt.Sprintf("%s/protocol/openid-connect/certs", issuerUrl)
	k.logger.Printf("Reading certs from %s", certUrl)
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

func (k KeycloakJWTAuthenticator) toPem(rawPem string) *pem.Block {
	pemStr := strings.Builder{}
	pemStr.WriteString("-----BEGIN CERTIFICATE-----\n")
	pemStr.WriteString(rawPem)
	pemStr.WriteString("\n-----END CERTIFICATE-----")

	block, _ := pem.Decode([]byte(pemStr.String()))

	return block
}

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

// Retrieve the proper JWK for the provided token
func (j JWKS) GetJWKForToken(token *jwt.Token) (JWK, error) {
	var kid string = token.Header["kid"].(string)
	for _, currKey := range j.Keys {
		if currKey.Kid == kid {
			return currKey, nil
		}
	}
	return JWK{}, fmt.Errorf("no Key for kid %s", kid)
}
