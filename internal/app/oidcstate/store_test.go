package oidcstate

import (
	"testing"
	"time"
)

func TestCreateAndConsume(t *testing.T) {
	s := NewInMemory()
	state, err := s.Create()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if state == "" {
		t.Fatal("expected a state")
	}
	if err := s.Consume(state); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := s.Consume(state); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound on reuse, got %v", err)
	}
}

func TestConsumeExpiredState(t *testing.T) {
	s := NewInMemory()
	s.items["expired"] = time.Now().Add(-time.Second)
	if err := s.Consume("expired"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestCreateGeneratesUniqueStates(t *testing.T) {
	s := NewInMemory()
	first, err := s.Create()
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	second, err := s.Create()
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if first == second {
		t.Fatal("expected unique states")
	}
}
