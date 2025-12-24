// Package users provides user management for the GoAuth fullstack demo.
package users

import (
	"time"
)

// User represents a user in the system.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"-"` // Never expose in JSON
	CreatedAt    time.Time `json:"created_at"`
}
