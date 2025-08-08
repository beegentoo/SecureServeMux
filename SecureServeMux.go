package secureservemux

import (
	"net/http"
)

// An Authenticator handles authentication for [SecureServeMux] Auth... methods
type Authenticator interface {
	// Perform authorizaion.
	//
	// Implementations may modify the Request and add additional data to the requests Context
	//
	// Returns a (possibly) modified [http.Request] if authorization succeeded, false and an error otherwise
	Authorize(w http.ResponseWriter, r *http.Request) (*http.Request, error)
}

// SecureServeMux offers the possibility to quickly implement authentication
// Handlers get redirected over an internal handler calling an Authenticator
// and then act accordingly
type SecureServeMux struct {
	*http.ServeMux               // The actual Serve Mux in the back
	authenticator  Authenticator // The authenticator
}

// Does the same as [http.HandleFunc] except the request is diverted through the assigned Authenticator
func (s *SecureServeMux) AuthHandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	s.ServeMux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		authorizedRequest, err := s.authenticator.Authorize(w, r)
		if err != nil || authorizedRequest == nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		handler(w, authorizedRequest)
	})
}

// Create a new SecureServeMux whose requests are diverted via the provided [Authenticator]
func NewSecureServeMux(authenticator Authenticator) *SecureServeMux {
	return &SecureServeMux{
		ServeMux:      http.NewServeMux(),
		authenticator: authenticator,
	}
}
