package toolauth

// TokenStore persists token pairs between tool sessions.
// Implementations must be safe for concurrent use.
type TokenStore interface {
	// Save persists the token pair for the given tool name.
	Save(toolName string, token *TokenPair) error
	// Load retrieves a previously stored token pair.
	// Returns nil, nil if no token is stored.
	Load(toolName string) (*TokenPair, error)
	// Delete removes the stored token pair for the given tool name.
	Delete(toolName string) error
}

// DefaultTokenStore returns the platform-preferred token store: the Windows
// Credential Manager on Windows, the encrypted file store elsewhere. Exported
// for native-client consumers (CLI login flows) that need direct store access
// without the full [Client] device-flow wrapper.
func DefaultTokenStore() TokenStore {
	return defaultTokenStore()
}
