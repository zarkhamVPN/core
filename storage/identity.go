package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/libp2p/go-libp2p/core/crypto"
)

const p2pIdentityFile = "p2p_identity.json"

// IdentityStorage handles reading from and writing to the p2p identity file.
type IdentityStorage struct {
	mu       sync.RWMutex
	filePath string
}

// NewIdentityStorage initializes a new IdentityStorage.
func NewIdentityStorage(configDir string) (*IdentityStorage, error) {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	return &IdentityStorage{
		filePath: filepath.Join(configDir, p2pIdentityFile),
	}, nil
}

// readData reads the entire identity file and unmarshals it.
func (is *IdentityStorage) readData() (*P2PIdentityData, error) {
	data := &P2PIdentityData{
		Identities: make(map[string][]byte),
	}

	file, err := os.ReadFile(is.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return nil, fmt.Errorf("failed to read p2p identity file: %w", err)
	}

	if len(file) == 0 {
		return data, nil
	}

	if err := json.Unmarshal(file, data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal p2p identity data: %w", err)
	}

	if data.Identities == nil {
		data.Identities = make(map[string][]byte)
	}

	return data, nil
}

// SaveIdentity saves a marshaled private key under a given name.
func (is *IdentityStorage) SaveIdentity(name string, privateKey crypto.PrivKey) error {
	is.mu.Lock()
	defer is.mu.Unlock()

	data, err := is.readData()
	if err != nil {
		return err
	}

	keyBytes, err := crypto.MarshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal p2p private key: %w", err)
	}

	data.Identities[name] = keyBytes

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal p2p identity data: %w", err)
	}

	if err := os.WriteFile(is.filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write p2p identity file: %w", err)
	}
	return nil
}

// GetIdentity retrieves a private key by its name.
func (is *IdentityStorage) GetIdentity(name string) (crypto.PrivKey, error) {
	is.mu.RLock()
	defer is.mu.RUnlock()

	data, err := is.readData()
	if err != nil {
		return nil, err
	}

	keyBytes, ok := data.Identities[name]
	if !ok {
		return nil, nil // Return nil if not found
	}

	privKey, err := crypto.UnmarshalPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal p2p private key: %w", err)
	}

	return privKey, nil
}
