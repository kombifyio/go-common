package toolauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FileStore stores tokens as AES-256-GCM encrypted JSON files.
// This is the fallback when the OS credential store is unavailable.
// Files are stored in ~/.kombify/<toolname>/token.json.
type FileStore struct{}

// Save encrypts and writes the token pair to disk.
func (s *FileStore) Save(toolName string, token *TokenPair) error {
	// #nosec G117 -- TokenPair is serialized only as plaintext input to AES-GCM;
	// only the resulting ciphertext is written to disk.
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("toolauth: marshal token: %w", err)
	}

	key, err := deriveKey()
	if err != nil {
		return fmt.Errorf("toolauth: derive key: %w", err)
	}

	encrypted, err := encryptAESGCM(key, data)
	if err != nil {
		return fmt.Errorf("toolauth: encrypt token: %w", err)
	}

	dir, err := tokenDir(toolName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("toolauth: create token dir: %w", err)
	}

	path := filepath.Join(dir, "token.json")
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		return fmt.Errorf("toolauth: write token file: %w", err)
	}
	return nil
}

// Load reads and decrypts the token pair from disk.
// Returns nil, nil if the file does not exist.
func (s *FileStore) Load(toolName string) (*TokenPair, error) {
	dir, err := tokenDir(toolName)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, "token.json")
	encrypted, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("toolauth: read token file: %w", err)
	}

	key, err := deriveKey()
	if err != nil {
		return nil, fmt.Errorf("toolauth: derive key: %w", err)
	}

	data, err := decryptAESGCM(key, encrypted)
	if err != nil {
		return nil, fmt.Errorf("toolauth: decrypt token: %w", err)
	}

	var token TokenPair
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("toolauth: unmarshal token: %w", err)
	}
	return &token, nil
}

// Delete removes the token file from disk.
func (s *FileStore) Delete(toolName string) error {
	dir, err := tokenDir(toolName)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, "token.json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("toolauth: delete token file: %w", err)
	}
	return nil
}

// tokenDir returns the directory for storing tokens for a given tool.
func tokenDir(toolName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("toolauth: user home dir: %w", err)
	}
	return filepath.Join(home, ".kombify", toolName), nil
}

// deriveKey produces a 32-byte AES key from the machine identity.
// The key is derived via machineID so tokens are bound to the physical machine.
func deriveKey() ([]byte, error) {
	id, err := machineID()
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte("kombify-toolauth:" + id))
	return hash[:], nil
}

// encryptAESGCM encrypts plaintext with AES-256-GCM.
// The nonce is prepended to the ciphertext.
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptAESGCM decrypts AES-256-GCM ciphertext where the nonce is prepended.
func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, data, nil)
}
