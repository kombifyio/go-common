package servicecall

import (
	"errors"
	"os"
)

// Env var names for secret loading.
const (
	EnvSecret = "SERVICE_AUTH_SECRET" // #nosec G101 -- public environment-variable identifier, not a secret value.
	// #nosec G101 -- public rotation environment-variable identifier, not a secret value.
	EnvSecretNext = "SERVICE_AUTH_SECRET_NEXT"
)

// ErrSecretMissing is returned by LoadKeysFromEnv when the primary secret
// is not set.
var ErrSecretMissing = errors.New("servicecall: SERVICE_AUTH_SECRET is not set")

// LoadKeysFromEnv reads SERVICE_AUTH_SECRET (primary, required) and
// SERVICE_AUTH_SECRET_NEXT (optional, during rotation).
func LoadKeysFromEnv() (primary, next string, err error) {
	primary = os.Getenv(EnvSecret)
	next = os.Getenv(EnvSecretNext)
	if primary == "" {
		return "", "", ErrSecretMissing
	}
	return primary, next, nil
}
