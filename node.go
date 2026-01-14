package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"strings"
	"sync"

	"zarkham/core/p2p"
	"zarkham/core/solana"
	"zarkham/core/storage"

	solanago "github.com/gagliardetto/solana-go"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
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
	if err != nil {
		return nil, err
	}

	is, err := storage.NewIdentityStorage(cfg.ConfigDir)
	if err != nil {
		return nil, err
	}

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

	// 1. Load or Create Wallet
	pk, err := n.storage.wallet.GetWallet(profile)
	if err != nil {
		log.Printf("Profile '%s' not found. Creating new wallet...", profile)
		newPk := solanago.NewWallet().PrivateKey
		if err := n.storage.wallet.SaveWallet(profile, newPk); err != nil {
			return fmt.Errorf("failed to save new wallet: %w", err)
		}
		pk = newPk
		log.Printf("Created new wallet for profile '%s'", profile)
	}

	// 2. Initialize Solana Client
	sc, err := solana.NewClient(n.config.RpcEndpoint, pk)
	if err != nil {
		return err
	}
	n.solana = sc

	// 3. Initialize P2P Manager
	pm := p2p.NewManager(n.storage.identity)
	if err := pm.Start(ctx, n.config.ListenIP); err != nil {
		return err
	}
	pm.RegisterHandlers(n.solana) // Register handlers with Solana context
	n.p2p = pm

	log.Println("Zarkham Node successfully started.")
	return nil
}

func (n *ZarkhamNode) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.p2p != nil {
		n.p2p.Stop()
	}
	return nil
}

func (n *ZarkhamNode) Status() p2p.NodeStatus {
	if n.p2p == nil {
		return p2p.NodeStatus{IsRunning: false}
	}
	return n.p2p.Status()
}

// --- GUI API Bridges ---

func (n *ZarkhamNode) GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"version": "1.0.0",
	}
}

func (n *ZarkhamNode) GetTelemetry() map[string]interface{} {
	return map[string]interface{}{
		"bandwidth_served": 0, // TODO: Implement in p2p
		"active_tunnels":   0,
	}
}

func (n *ZarkhamNode) GetWardens(ctx context.Context) ([]*solana.Warden, error) {
	if n.solana == nil {
		return nil, fmt.Errorf("solana client not initialized")
	}
	return n.solana.FetchAllWardens()
}

func (n *ZarkhamNode) GetWardenStatus(ctx context.Context) (bool, *solana.Warden, error) {
	if n.solana == nil {
		return false, nil, fmt.Errorf("solana client not initialized")
	}
	registered, err := n.solana.IsWardenRegistered()
	if err != nil || !registered {
		return false, nil, err
	}
	warden, err := n.solana.FetchWardenAccount()
	return true, warden, err
}

func (n *ZarkhamNode) ManualConnect(ctx context.Context, multiaddrStr string) error {
	if n.p2p == nil {
		return fmt.Errorf("P2P manager not initialized")
	}

	// 1. Parse Multiaddr
	ma, err := multiaddr.NewMultiaddr(multiaddrStr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr: %w", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return fmt.Errorf("failed to get peer info: %w", err)
	}

	// 2. Initialize On-Chain Connection (The "Ticket")
	// We need the Warden's Authority (Solana PubKey), but we only have their Peer ID.
	// We must look it up.
	warden, err := n.solana.FetchWardenByPeerID(info.ID.String())
	if err != nil {
		return fmt.Errorf("failed to resolve warden authority from peer ID: %w", err)
	}

	// Check if connection already exists
	seekerPDA, _, _ := solana.GetSeekerPDA(n.solana.Signer.PublicKey())
	wardenPDA, _, _ := solana.GetWardenPDAForAuthority(warden.Authority)
	connectionPDA, _, _ := solana.GetConnectionPDA(seekerPDA, wardenPDA)

	_, err = n.solana.FetchConnectionAccount(connectionPDA)
	if err == nil {
		log.Printf("Connection account %s already exists. Skipping on-chain initialization.", connectionPDA)
	} else if strings.Contains(err.Error(), "not found") {
		log.Printf("Initializing on-chain connection with Warden %s...", warden.Authority)
		sig, err := n.solana.StartConnection(warden.Authority, 100) // Default 100MB
		if err != nil {
			log.Printf("Warning: Failed to initialize connection account: %v", err)
		} else {
			log.Printf("Connection initialized. Sig: %s", sig)
			log.Println("Waiting for transaction confirmation...")
			if err := n.solana.WaitForConfirmation(ctx, *sig); err != nil {
				return fmt.Errorf("failed to confirm connection transaction: %w", err)
			}
			log.Println("Transaction confirmed. Proceeding with P2P handshake...")
		}
	} else {
		// Real error fetching account
		return fmt.Errorf("failed to check connection account status: %w", err)
	}

	// 3. Libp2p Connect
	if err := n.p2p.Connect(ctx, multiaddrStr); err != nil {
		return fmt.Errorf("libp2p connect failed: %w", err)
	}

	// 4. Request VPN Tunnel
	seekerAuth := n.solana.Signer.PublicKey().String()
	if err := n.p2p.RequestTunnel(ctx, info.ID, seekerAuth); err != nil {
		return fmt.Errorf("vpn tunnel handshake failed: %w", err)
	}

	return nil
}

func (n *ZarkhamNode) GetWalletBalance(ctx context.Context, profile string) (uint64, error) {
	pk, err := n.storage.wallet.GetWallet(profile)
	if err != nil {
		return 0, fmt.Errorf("profile not found")
	}
	if n.solana == nil {
		sc, err := solana.NewReadOnlyClient(n.config.RpcEndpoint)
		if err != nil {
			return 0, err
		}
		return sc.GetBalance(pk.PublicKey())
	}
	return n.solana.GetBalance(pk.PublicKey())
}

func (n *ZarkhamNode) GetAddresses() (map[string]string, error) {
	wallets, err := n.storage.wallet.GetAllWallets()
	if err != nil {
		return nil, err
	}

	res := make(map[string]string)
	for name, pk := range wallets {
		res[name] = pk.PublicKey().String()
	}
	return res, nil
}

func (n *ZarkhamNode) RegisterWarden(ctx context.Context, profile string, stakeTokenStr string, stakeAmount float64) (string, error) {
	// 1. Get Wallet
	pk, err := n.storage.wallet.GetWallet(profile)
	if err != nil {
		return "", err
	}

	// 2. Client
	sc, err := solana.NewClient(n.config.RpcEndpoint, pk)
	if err != nil {
		return "", err
	}

	// 3. Prepare Args
	var token solana.StakeToken
	var lamports uint64

	if stakeTokenStr == "SOL" {
		token = solana.StakeToken_Sol
		lamports = uint64(stakeAmount * 1e9)
	} else if stakeTokenStr == "USDC" {
		token = solana.StakeToken_Usdc
		lamports = uint64(stakeAmount * 1e6)
	} else {
		return "", fmt.Errorf("unsupported token")
	}

	peerID := n.p2p.Host().ID().String()

	// REAL IP Resolution
	var ipStr string
	for _, addr := range n.p2p.Host().Addrs() {
		if manet.IsPublicAddr(addr) {
			val, err := addr.ValueForProtocol(multiaddr.P_IP4)
			if err == nil {
				ipStr = val
				break
			}
		}
	}
	if ipStr == "" {
		ipStr = "0.0.0.0"
		log.Println("WARNING: Could not determine public IP for registration. Using 0.0.0.0")
	}

	ipHash := sha256.Sum256([]byte(ipStr))

	sig, err := sc.InitializeWarden(token, lamports, peerID, 0, ipHash)
	if err != nil {
		return "", err
	}

		return sig.String(), nil

	}

	

	func (n *ZarkhamNode) GetHistory(ctx context.Context, profile string) (*solana.HistoryResult, error) {

		pk, err := n.storage.wallet.GetWallet(profile)

		if err != nil { return nil, fmt.Errorf("profile not found") }

	

		// Use existing client or create temp one

		var sc *solana.Client

		if n.solana != nil {

			sc = n.solana

		} else {

			sc, err = solana.NewReadOnlyClient(n.config.RpcEndpoint)

			if err != nil { return nil, err }

		}

	

		return sc.GetHistory(pk.PublicKey())

	}

	