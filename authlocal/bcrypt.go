package authlocal

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// hashPassword returns bcrypt(password) at DefaultCost.
func hashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("%w: password must be at least 8 characters", ErrInvalidCreds)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hashed), nil
}

// verifyPassword returns nil when password matches the stored hash.
func verifyPassword(hash, password string) error {
	if hash == "" {
		return ErrInvalidCreds
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCreds
		}
		return fmt.Errorf("verify password: %w", err)
	}
	return nil
}

// generateSecureToken returns base64-url encoded random token of n bytes.
func generateSecureToken(nBytes int) (string, error) {
	if nBytes <= 0 {
		nBytes = 24
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
