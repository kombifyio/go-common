//go:build !windows

package toolauth

// defaultTokenStore returns the platform-preferred token store.
// On non-Windows platforms, this is the encrypted file store.
// macOS Keychain support may be added in a future version.
func defaultTokenStore() TokenStore {
	return &FileStore{}
}
