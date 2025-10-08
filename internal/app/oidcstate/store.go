package oidcstate

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// StateTTL is how long an OIDC authentication state remains valid.
const StateTTL = 10 * time.Minute
const MaxStates = 10000

// ErrNotFound is returned when a state does not exist, has expired, or was already consumed.
var ErrNotFound = errors.New("oidc state not found")

// Store persists OIDC authentication states.
type Store interface {
	Create() (string, error)
	Consume(state string) error
}

// InMemory is an in-process Store.
type InMemory struct {
	mu    sync.Mutex
	items map[string]time.Time
}

// NewInMemory returns an empty in-memory store.
func NewInMemory() *InMemory {
	return &InMemory{items: make(map[string]time.Time)}
}

// Create generates and stores a cryptographically random OIDC state.
func (s *InMemory) Create() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	s.removeExpiredLocked(time.Now())
	if len(s.items) >= MaxStates {
		s.mu.Unlock()
		return "", errors.New("oidc state store is full")
	}
	s.items[state] = time.Now().Add(StateTTL)
	s.mu.Unlock()

	return state, nil
}

// Consume validates and removes a state atomically.
func (s *InMemory) Consume(state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expires, ok := s.items[state]
	if !ok {
		return ErrNotFound
	}
	delete(s.items, state)
	if time.Now().After(expires) {
		return ErrNotFound
	}
	return nil
}

func (s *InMemory) removeExpiredLocked(now time.Time) {
	for state, expires := range s.items {
		if now.After(expires) {
			delete(s.items, state)
		}
	}
}
