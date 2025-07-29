package veryunsafedemo

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

// This is a very unsafe authenticator which is used
// mainly for development purposes
//
// Authentication will succeed when the Authorization-Header is set to "This is unsave!"
//
// DO NOT USE IN PRODUCTION!
type VeryUnsaveDevAuthenticator struct {
	// No elements
}

func (v VeryUnsaveDevAuthenticator) Authorize(w http.ResponseWriter, r *http.Request) (bool, error) {
	log.Print("!!!WARNING!!! You are using the very unsave development authenticator! THIS IS DISCOURAGED IN PRODUCTION MODE!")
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return false, fmt.Errorf("no valid Authorization header provided")
	}

	return (strings.ToUpper(authHeader) == "THIS IS UNSAVE!"), nil

}
