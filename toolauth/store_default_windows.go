//go:build windows

package toolauth

// defaultTokenStore returns the platform-preferred token store.
// On Windows, this is the Credential Manager.
func defaultTokenStore() TokenStore {
	return &WindowsCredentialStore{}
}
