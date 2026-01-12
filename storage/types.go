package storage

import "github.com/gagliardetto/solana-go"

// WalletData holds all the wallets managed by the CLI.
// The key of the map is the wallet's name (e.g., "warden", "seeker").
type WalletData struct {
	Wallets map[string]solana.PrivateKey `json:"wallets"`
}

// P2PIdentityData holds the marshaled private keys for P2P identities.
// The key of the map is the identity's name (e.g., "default").
type P2PIdentityData struct {
	Identities map[string][]byte `json:"identities"`
}
