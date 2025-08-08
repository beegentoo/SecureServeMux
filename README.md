# SecureServeMux
SecureServeMux is a lightweight extension to `http.ServeMux` introducing (currently) one new
function `AuthHandleFunc()` which is basically the same as `http.HandleFunc()` but handles authorization.

This project is a byproduct of another (personal) project. I am fully aware of the fact that some parts of the
source code are not written elegantly (I am still collecting experiences and best-practices in Go)
## Usage
Usage of SecureServeMux is easy. The main goal was, that `http.ServeMux` can easily be exchanged.

Example:
```go
var serveMux *http.ServeMux := http.NewServeMux()

serveMux.HandleFunc("/slash_a", func (w http.ResponseWriter, r *http.Request) {
  // Some code
})
```
With SecureServeMux changes to the relevant code are minimal:
```go
var authenticator Authenticator = jwtauth.NewKeycloakJWTAuth(
  "http://keycloakinstance.local.network",
  "MyDemoRealm",
  jwtauth.NewRoleBasedAccess("Can_Slash_A")
)

var serveMux *secureservemux.SecureServeMux = secureservemux.NewSecureServeMux(authenticator)

serveMux.AuthHandleFunc("/slash_a", func (w http.ResponseWriter, r *http.Request) {
  // some Code
})
```
A slightly more complex example can be seen in the (currently) lone [Test-File](./jwtauth/KeycloakJWTAuthenticator_test.go)
## Authenticators
The following Authenticators are included

  - `veryunsafedemo.VeryUnsaveDevAuthenticator`: Guess... ;)
  - `jwtauth.GenericJWTAuthenticator`: A generic Authenticator for JWTs, provided as Bearer-Tokens in the Authorization header
  - `jwtauth.KeycloakJWTAuthenticator`: An authenticator specialized in authenticating using JWTs issued by Keycloak instances

### Using Authenticators standalone
If you want to use the authenticators as a "standalone" Middleware without using SecureSerrveMux, this is possible.

Here is a very simple example for Gorilla [Gorilla Mux](https://github.com/gorilla/mux):
```go
// Define a middleware-function wrapping the Authenticator
func jwtAuthMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authenticator := jwtauth.NewKeycloakJWTAuth(
      "https://keycloak.my.network",
      "MyKeycloakRealm",
      jwtauth.NewRoleBasedAccess("Editor")
    )

    // Call the Authenticate() function
    authorizedRequest, authErr := authenticator.Authorize(w http.ResponseWriter, r *http.Request)
    if authorizedRequest == nil || authErr != nil {
      // Authorization failed. Fail with 403 Forbidden, redirect to a login, etc
      w.WriteHeader(http.StatusForbidden)
      return
    }

    // Authorization succeeded - continue to next handler
    next.ServeHTTP(w, r)
  })
}

// Use the middleware function
router := mux.NewRouter()
router.Use(jwtAuthMiddleware)
router.HandleFunc("/editor", handleEditorRequest).Methods("GET")
```

### Metadata obtained during authorization
Upon successful authorization, an Authenticator may populate the original `http.Request`'s context with additional data. For example, if you use the KeycloakJWTAuthenticator and you have a specific field added to your token's scope which you would like to use in your application you may access this like this:
```go
// ....
// Initialization of a SecureServeMux using KeycloakJWTAuthenticator
// ....

mux.AuthHandleFunc("GET /customerInfo", func(w http.ResponseWriter, r *http.Request) {
  // The JWT send by Keycloak contains an additional field (these have to be added in the appropriate scope)
	var mapClaims jwt.MapClaims = r.Context().Value("jwtClaims").(jwt.MapClaims)
	customerNo, isSet := mapClaims["customerNo"]

  // Some API to an imaginary ERP-Systen
  var erp *SuperERP = NewSuperERP()

  customerInfo := erp.GetCustomerInfo(customerNo)

  // ....
  // function ends, customerInfo is send in the response, whatever
  // ....
})

```
## Authorization Strategies
Authorization Strategies are additional authorizations for JWTs. Currently, there's only one strategy named `RoleBasedAccess`. It keeps a list of Role-Names and checks if a token has all these Roles assigned