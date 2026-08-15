//go:build windows

package toolauth

import (
	"encoding/json"
	"fmt"

	"github.com/danieljoos/wincred"
)

// #nosec G101 -- credentialPrefix is a public vault record namespace, not a credential value.
const credentialPrefix = "kombify:"

// WindowsCredentialStore stores tokens in Windows Credential Manager.
type WindowsCredentialStore struct{}

// Save persists the token pair in Windows Credential Manager.
func (s *WindowsCredentialStore) Save(toolName string, token *TokenPair) error {
	// #nosec G117 -- TokenPair is the payload intentionally stored in Windows
	// Credential Manager; it is not logged or written outside the OS vault.
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("toolauth: marshal token: %w", err)
	}

	cred := wincred.NewGenericCredential(credentialPrefix + toolName)
	cred.CredentialBlob = data
	cred.UserName = token.UserID
	cred.Persist = wincred.PersistLocalMachine

	if err := cred.Write(); err != nil {
		return fmt.Errorf("toolauth: write credential: %w", err)
	}
	return nil
}

// Load retrieves the token pair from Windows Credential Manager.
// Returns nil, nil if no credential is stored.
func (s *WindowsCredentialStore) Load(toolName string) (*TokenPair, error) {
	cred, err := wincred.GetGenericCredential(credentialPrefix + toolName)
	if err != nil {
		// Credential not found is not an error — return nil.
		return nil, nil
	}
	if cred == nil || len(cred.CredentialBlob) == 0 {
		return nil, nil
	}

	var token TokenPair
	if err := json.Unmarshal(cred.CredentialBlob, &token); err != nil {
		return nil, fmt.Errorf("toolauth: unmarshal credential: %w", err)
	}
	return &token, nil
}

// Delete removes the token from Windows Credential Manager.
func (s *WindowsCredentialStore) Delete(toolName string) error {
	cred, err := wincred.GetGenericCredential(credentialPrefix + toolName)
	if err != nil {
		// Already absent — nothing to delete.
		return nil
	}
	if cred == nil {
		return nil
	}
	if err := cred.Delete(); err != nil {
		return fmt.Errorf("toolauth: delete credential: %w", err)
	}
	return nil
}
