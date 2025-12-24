package users

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserExists      = errors.New("user already exists")
	ErrInvalidPassword = errors.New("invalid password")
)

// Store is an in-memory user store for demo purposes.
// In production, you would use a database.
type Store struct {
	users   map[string]*User // keyed by ID
	byEmail map[string]*User // keyed by email
	mu      sync.RWMutex
}

// NewStore creates a new user store.
func NewStore() *Store {
	return &Store{
		users:   make(map[string]*User),
		byEmail: make(map[string]*User),
	}
}

// Create creates a new user with the given credentials.
func (s *Store) Create(ctx context.Context, email, password, name string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if email exists
	if _, exists := s.byEmail[email]; exists {
		return nil, ErrUserExists
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Generate ID
	id, err := generateID()
	if err != nil {
		return nil, err
	}

	user := &User{
		ID:           id,
		Email:        email,
		Name:         name,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}

	s.users[id] = user
	s.byEmail[email] = user

	return user, nil
}

// GetByID retrieves a user by ID.
func (s *Store) GetByID(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetByEmail retrieves a user by email.
func (s *Store) GetByEmail(ctx context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.byEmail[email]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// Authenticate validates credentials and returns the user.
func (s *Store) Authenticate(ctx context.Context, email, password string) (*User, error) {
	user, err := s.GetByEmail(ctx, email)
	if err != nil {
		return nil, ErrInvalidPassword // Don't reveal if user exists
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidPassword
	}

	return user, nil
}

// List returns all users.
func (s *Store) List(ctx context.Context) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		result = append(result, user)
	}
	return result, nil
}

// Delete removes a user by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists {
		return ErrUserNotFound
	}

	delete(s.users, id)
	delete(s.byEmail, user.Email)
	return nil
}

// generateID creates a random user ID.
func generateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
