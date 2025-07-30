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
  jwtauth.NewRoleBasedAccess()
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

## Authorization Strategies
Authorization Strategies are additional authorizations for JWTs. Currently, there's only one strategy named `RoleBasedAccess`. It keeps a list of Role-Names and checks if a token has all these Roles assigned