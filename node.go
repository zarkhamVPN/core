package core

import (
	"context"
	"fmt"
	"log"
	"sync"

	"zarkham/core/p2p"
	"zarkham/core/solana"
	"zarkham/core/storage"
)

type Config struct {
	ConfigDir   string
	RpcEndpoint string
	ListenIP    string
}

type ZarkhamNode struct {
	mu      sync.Mutex
	config  Config
	storage struct {
		wallet   *storage.WalletStorage
		identity *storage.IdentityStorage
	}
	solana *solana.Client
	p2p    *p2p.Manager
}

func NewZarkhamNode(cfg Config) (*ZarkhamNode, error) {
	ws, err := storage.NewWalletStorage(cfg.ConfigDir)
	if err != nil { return nil, err }
	
	is, err := storage.NewIdentityStorage(cfg.ConfigDir)
	if err != nil { return nil, err }

	return &ZarkhamNode{
		config: cfg,
		storage: struct {
			wallet   *storage.WalletStorage
			identity *storage.IdentityStorage
		}{ws, is},
	}, nil
}

func (n *ZarkhamNode) Start(ctx context.Context, profile string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// 1. Load Wallet
	pk, err := n.storage.wallet.GetWallet(profile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", profile, err)
	}

	// 2. Initialize Solana Client
	sc, err := solana.NewClient(n.config.RpcEndpoint, pk)
	if err != nil { return err }
	n.solana = sc

	// 3. Initialize P2P Manager
	pm := p2p.NewManager(n.storage.identity)
	if err := pm.Start(ctx, n.config.ListenIP); err != nil { return err }
	pm.RegisterHandlers(n.solana) // Register handlers with Solana context
	n.p2p = pm

	log.Println("Zarkham Node successfully started.")
	return nil
}

func (n *ZarkhamNode) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.p2p != nil { n.p2p.Stop() }
	return nil
}

func (n *ZarkhamNode) Status() p2p.NodeStatus {
	if n.p2p == nil { return p2p.NodeStatus{IsRunning: false} }
	return n.p2p.Status()
}

// --- GUI API Bridges ---

func (n *ZarkhamNode) GetWardens(ctx context.Context) ([]*solana.Warden, error) {
	if n.solana == nil { return nil, fmt.Errorf("solana client not initialized") }
	return n.solana.FetchAllWardens()
}

func (n *ZarkhamNode) GetWardenStatus(ctx context.Context) (bool, *solana.Warden, error) {
	if n.solana == nil { return false, nil, fmt.Errorf("solana client not initialized") }
	registered, err := n.solana.IsWardenRegistered()
	if err != nil || !registered {
		return false, nil, err
	}
	warden, err := n.solana.FetchWardenAccount()
	return true, warden, err
}

func (n *ZarkhamNode) ManualConnect(ctx context.Context, multiaddr string) error {
	if n.p2p == nil {
		return fmt.Errorf("P2P manager not initialized")
	}
	return n.p2p.Connect(ctx, multiaddr)
}
