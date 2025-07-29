package jwtauth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const pemPrefix = "-----BEGIN CERTIFICATE-----"
const pemPostfix = "-----END CERTIFICATE-----"

// Function used to retrieve the Issuer-Certificate from... somewhere...
type CertRetrieverFunc func(token *jwt.Token) (string, error)

func NewGenericJWTAuthenticator(issuer string, certRetrieverFunc CertRetrieverFunc, strategy AuthorizationStrategy) GenericJWTAuthenticator {
	return GenericJWTAuthenticator{
		Logger:            log.New(os.Stdout, "GenericJWTAuthenticator: ", log.LstdFlags),
		Issuer:            issuer,
		CertRetrieverFunc: certRetrieverFunc,
		Strategy:          strategy,
	}
}

// A Generic JWT Authenticator extracts a JWT from the Authorization-Header (Bearer Token).
// It verifies the token's signature and also issues a validation by the assigned Authorization
// strategy
//
// The CertRetrieverFunc should return a string-representation of a Certificate (with or without
// header- and footer-line)
type GenericJWTAuthenticator struct {
	Issuer            string            // Issuer to expect
	CertRetrieverFunc CertRetrieverFunc // Function to retrieve the issuer certificate
	Logger            *log.Logger
	Strategy          AuthorizationStrategy // Authorization strategy to be used
}

// Performs authorization of a request.
//
// Returns true and no error if autorization succeeded, false and error otherwise
func (g GenericJWTAuthenticator) Authorize(w http.ResponseWriter, r *http.Request) (bool, error) {
	tokenHead, err := g.extractAuthHeader(r)
	if err != nil {
		return false, err
	}

	token, err := g.verifyToken(tokenHead)
	if err != nil {
		g.Logger.Print(err.Error())
		return false, err
	}

	var isValid bool = false
	isValid, err = g.Strategy.Validate(token)
	if err != nil || !isValid {
		g.Logger.Print(err.Error())
		return false, err
	}

	return true, nil
}

// Exctracts the JWT from the Authorization header
func (g GenericJWTAuthenticator) extractAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" || !strings.HasPrefix(strings.ToUpper(authHeader), "BEARER ") {
		return "", fmt.Errorf("no authorization header or bearer token provided")
	}

	return authHeader[7:], nil
}

// Verifies the integrity of the token (issuer, signature, expiration-time etc.)
func (g GenericJWTAuthenticator) verifyToken(token string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(token, g.keyfunc, jwt.WithIssuer(g.Issuer))
	if err != nil {
		return nil, err
	}
	return parsedToken, nil
}

// Retrieves the public-key of the key-pair which was used to sign the JWT
func (g GenericJWTAuthenticator) keyfunc(token *jwt.Token) (any, error) {
	rawCert, err := g.CertRetrieverFunc(token)
	if err != nil {
		return "", err
	}

	certPem := g.certToPem(rawCert)

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey, nil
}

// Converts the ASCII-Representation of a certificate to a pem.Block
func (g GenericJWTAuthenticator) certToPem(rawPem string) *pem.Block {
	var pemStr string
	if !strings.HasPrefix(rawPem, pemPrefix) {
		pemStr = fmt.Sprintf("%s\n%s\n%s", pemPrefix, rawPem, pemPostfix)
	} else {
		pemStr = rawPem
	}

	block, _ := pem.Decode([]byte(pemStr))

	return block
}
