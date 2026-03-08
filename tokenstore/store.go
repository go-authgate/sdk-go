package tokenstore

import (
	"errors"
	"time"
)

// ErrNotFound indicates that no token was found for the given client ID.
var ErrNotFound = errors.New("token not found")

// ErrNilToken is returned when a nil Token is passed to Save.
var ErrNilToken = errors.New("token cannot be nil")

// ErrEmptyClientID is returned when a Token with an empty ClientID is passed to Save.
var ErrEmptyClientID = errors.New("client ID cannot be empty")

// Store defines the interface for loading, saving, and deleting OAuth tokens.
type Store interface {
	Load(clientID string) (*Token, error)
	Save(storage *Token) error
	Delete(clientID string) error
	String() string
}

// Token represents saved tokens for a specific client.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	ClientID     string    `json:"client_id"`
}
