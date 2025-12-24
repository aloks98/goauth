package app

import (
	"github.com/aloks98/goauth"
)

// Claims extends StandardClaims with custom fields.
type Claims struct {
	goauth.StandardClaims
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}
