package jwtauth

import (
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

// An Authorization strategy checks if the user has appropriate
// permissions depending on some constraint.
type AuthorizationStrategy interface {
	// Validates Authorization. Returns true if authorization is granted,
	// false if authorization was rejected
	Validate(token *jwt.Token) (bool, error)
}

// Authorization based on assigned roles. Authorization is granted
// if the user is in all of the assigned roles
type RoleBasedAccess struct {
	RequiredRoles []string
}

func (rba RoleBasedAccess) Validate(token *jwt.Token) (bool, error) {
	var claims jwt.MapClaims = token.Claims.(jwt.MapClaims)
	realm_access := claims["realm_access"].(map[string]any)
	roles := realm_access["roles"].([]any)
	var strRoles []string

	for _, currRole := range roles {
		strRoles = append(strRoles, currRole.(string))
	}

	for _, currRole := range rba.RequiredRoles {
		if !slices.Contains(strRoles, currRole) {
			return false, nil
		}
	}

	return true, nil
}

// Creates a new RoleBasedAccess strategy based on the given
// Role names
func NewRoleBasedAccess(role ...string) RoleBasedAccess {
	return RoleBasedAccess{
		RequiredRoles: role,
	}
}
