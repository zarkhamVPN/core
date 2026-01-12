package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/gagliardetto/solana-go"
)

const walletFile = "wallet.json"

// WalletStorage handles reading from and writing to the wallet file.
type WalletStorage struct {
	mu       sync.RWMutex
	filePath string
}

// NewWalletStorage initializes a new WalletStorage.
func NewWalletStorage(configDir string) (*WalletStorage, error) {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	return &WalletStorage{
		filePath: filepath.Join(configDir, walletFile),
	}, nil
}

// readData reads the entire wallet file and unmarshals it.
func (ws *WalletStorage) readData() (*WalletData, error) {
	data := &WalletData{
		Wallets: make(map[string]solana.PrivateKey),
	}

	file, err := os.ReadFile(ws.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return nil, fmt.Errorf("failed to read wallet file: %w", err)
	}

	if len(file) == 0 {
		return data, nil
	}

	if err := json.Unmarshal(file, data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal wallet data: %w", err)
	}

	if data.Wallets == nil {
		data.Wallets = make(map[string]solana.PrivateKey)
	}

	return data, nil
}

// SaveWallet saves a private key under a given name.
func (ws *WalletStorage) SaveWallet(name string, privateKey solana.PrivateKey) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	data, err := ws.readData()
	if err != nil {
		return err
	}

	data.Wallets[name] = privateKey

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal wallet data: %w", err)
	}

	if err := os.WriteFile(ws.filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write wallet file: %w", err)
	}
	return nil
}

// GetWallet retrieves a private key by its name.
func (ws *WalletStorage) GetWallet(name string) (solana.PrivateKey, error) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	data, err := ws.readData()
	if err != nil {
		return nil, err
	}

	privateKey, ok := data.Wallets[name]
	if !ok {
		return nil, fmt.Errorf("wallet '%s' not found", name)
	}

	return privateKey, nil
}

// GetAllWallets returns all wallets.
func (ws *WalletStorage) GetAllWallets() (map[string]solana.PrivateKey, error) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	data, err := ws.readData()
	if err != nil {
		return nil, err
	}
	return data.Wallets, nil
}
