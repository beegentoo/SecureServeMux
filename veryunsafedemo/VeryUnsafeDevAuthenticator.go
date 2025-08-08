package veryunsafedemo

import (
	"context"
	"fmt"
	"log"
	"net/http"
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

func (v VeryUnsaveDevAuthenticator) Authorize(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	log.Println("==============================================================================================================")
	log.Println("                                           !!! WARNING!!!")
	log.Println("      You are using the very unsave development authenticator! THIS IS DISCOURAGED IN PRODUCTION MODE!")
	log.Println("==============================================================================================================")
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return nil, fmt.Errorf("no valid Authorization header provided")
	}

	ctx := context.WithValue(r.Context(), "authenticated", true)

	newRequest := r.WithContext(ctx)

	return newRequest, nil

}
