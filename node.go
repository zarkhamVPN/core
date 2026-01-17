package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"zarkham/core/logger"
	"zarkham/core/p2p"
	"zarkham/core/ryne"
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
	P2PPort     int
	SubmitTC    bool
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
	ryne   *ryne.Service

	seekerCache struct {
		sync.RWMutex
		registered bool
		status     *SeekerStatus
	}
	wardenCache struct {
		sync.RWMutex
		registered bool
		data       *solana.Warden
	}

	isDisconnecting bool
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

	pk, err := n.storage.wallet.GetWallet(profile)
	if err != nil {
		logger.Info("CORE", "Profile '%s' not found. Creating new wallet...", profile)
		newPk := solanago.NewWallet().PrivateKey
		if err := n.storage.wallet.SaveWallet(profile, newPk); err != nil {
			return fmt.Errorf("failed to save new wallet: %w", err)
		}
		pk = newPk
		logger.Success("CORE", "Created new wallet for profile '%s'", profile)
	}

	solana.InitGlobalAuth()
	sc, err := solana.NewClient(n.config.RpcEndpoint, pk)
	if err != nil {
		return err
	}
	n.solana = sc

	pm := p2p.NewManager(n.storage.identity)
	if err := pm.Start(ctx, n.config.ListenIP, n.config.P2PPort); err != nil {
		return err
	}
	pm.RegisterHandlers(n.solana)
	pm.SubmitTC = n.config.SubmitTC
	n.p2p = pm

	n.ryne = ryne.NewService(n.p2p, n.solana, n.config.SubmitTC)
	n.ryne.Start()

	go n.backgroundCacheWorker(ctx, profile)

	logger.Success("CORE", "Zarkham Node successfully started.")
	return nil
}

func (n *ZarkhamNode) backgroundCacheWorker(ctx context.Context, profile string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	n.refreshCache(profile)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.refreshCache(profile)
		}
	}
}

func (n *ZarkhamNode) refreshCache(profile string) {
	if n.solana == nil {
		return
	}

	if profile == "seeker" {
		seeker, err := n.solana.FetchSeekerAccount()
		if err == nil {
			status := &SeekerStatus{Seeker: seeker}
			connections, err := n.solana.FetchMyConnections("seeker")
			if err == nil && len(connections) > 0 {
				active := connections[0]
				status.ConnectedWardenPDA = active.PublicKey.String()
				status.ConnectedWardenAuthority = active.Account.Warden.String()
			}
			isRegistered := seeker.EscrowBalance > 0 || seeker.Authority != solanago.PublicKey{}

			n.seekerCache.Lock()
			n.seekerCache.registered = isRegistered
			n.seekerCache.status = status
			n.seekerCache.Unlock()
		}
	} else {
		registered, err := n.solana.IsWardenRegistered()
		if err == nil {
			warden, err := n.solana.FetchWardenAccount()
			if err == nil {
				n.wardenCache.Lock()
				n.wardenCache.registered = registered
				n.wardenCache.data = warden
				n.wardenCache.Unlock()
			}
		}
	}
}

func (n *ZarkhamNode) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.ryne != nil {
		n.ryne.Stop()
	}
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

func (n *ZarkhamNode) GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"version": "1.0.0",
	}
}

func (n *ZarkhamNode) GetTelemetry() map[string]interface{} {
	return map[string]interface{}{
		"bandwidth_served": 0,
		"active_tunnels":   0,
	}
}

func (n *ZarkhamNode) GetWardens(ctx context.Context) ([]*WardenInfo, error) {
	if n.solana == nil {
		return nil, fmt.Errorf("solana client not initialized")
	}
	rawWardens, err := n.solana.FetchAllWardens()
	if err != nil {
		return nil, err
	}

	var enriched []*WardenInfo
	for _, w := range rawWardens {
		price, _ := n.solana.CalculateWardenRate(w)
		enriched = append(enriched, &WardenInfo{
			Warden: w,
			Price:  price,
		})
	}
	return enriched, nil
}

type WardenInfo struct {
	*solana.Warden
	Price uint64 `json:"price"`
}

func (n *ZarkhamNode) LookupWarden(ctx context.Context, peerID string) (*WardenInfo, error) {
	if n.solana == nil {
		return nil, fmt.Errorf("solana client not initialized")
	}
	w, err := n.solana.FetchWardenByPeerID(peerID)
	if err != nil {
		return nil, err
	}
	
	price, err := n.solana.CalculateWardenRate(w)
	if err != nil {
		return nil, err
	}

	return &WardenInfo{
		Warden: w,
		Price:  price,
	}, nil
}

func (n *ZarkhamNode) DepositEscrow(ctx context.Context, amount uint64) (string, error) {
	if n.solana == nil {
		return "", fmt.Errorf("solana client not initialized")
	}
	sig, err := n.solana.DepositEscrow(amount)
	if err != nil {
		return "", err
	}
	return sig.String(), nil
}

type SeekerStatus struct {
	*solana.Seeker
	ConnectedWardenPDA       string `json:"connectedWardenPDA,omitempty"`
	ConnectedWardenAuthority string `json:"connectedWardenAuthority,omitempty"`
	IsDisconnecting          bool   `json:"isDisconnecting"`
	IsLocalLinkActive        bool   `json:"isLocalLinkActive"`
}

func (n *ZarkhamNode) GetSeekerStatus(ctx context.Context) (bool, *SeekerStatus, error) {
	n.seekerCache.RLock()
	defer n.seekerCache.RUnlock()

	if n.seekerCache.status == nil {
		return false, &SeekerStatus{IsDisconnecting: n.isDisconnecting}, nil
	}

	status := *n.seekerCache.status
	status.IsDisconnecting = n.isDisconnecting
	status.IsLocalLinkActive = n.p2p.IsTunnelInterfaceActive()

	return n.seekerCache.registered, &status, nil
}

func (n *ZarkhamNode) GetLatency(ctx context.Context) (int64, error) {
	if n.p2p == nil || n.p2p.Host() == nil {
		return 0, fmt.Errorf("P2P not initialized")
	}

	conns := n.p2p.Host().Network().Conns()
	if len(conns) == 0 {
		return 0, fmt.Errorf("no active connections")
	}

	peerID := conns[0].RemotePeer()
	lat := n.p2p.Host().Peerstore().LatencyEWMA(peerID)
	
	if lat == 0 {
		return 0, nil
	}
	return lat.Milliseconds(), nil
}

func (n *ZarkhamNode) GetBandwidth(ctx context.Context) (uint64, error) {
	if n.p2p == nil {
		return 0, fmt.Errorf("P2P not initialized")
	}
	return n.p2p.GetTotalBandwidth(), nil
}

func (n *ZarkhamNode) GetWardenStatus(ctx context.Context) (bool, *solana.Warden, error) {
	n.wardenCache.RLock()
	defer n.wardenCache.RUnlock()

	if n.wardenCache.data == nil {
		return false, nil, nil
	}

	return n.wardenCache.registered, n.wardenCache.data, nil
}

func (n *ZarkhamNode) ManualConnect(ctx context.Context, multiaddrStr string, estimatedMb uint64) error {
	if n.p2p == nil {
		return fmt.Errorf("P2P manager not initialized")
	}

	ma, err := multiaddr.NewMultiaddr(multiaddrStr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr: %w", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return fmt.Errorf("failed to get peer info: %w", err)
	}

	warden, err := n.solana.FetchWardenByPeerID(info.ID.String())
	if err != nil {
		return fmt.Errorf("failed to resolve warden authority from peer ID: %w", err)
	}

	seekerPDA, _, _ := solana.GetSeekerPDA(n.solana.Signer.PublicKey())
	wardenPDA, _, _ := solana.GetWardenPDAForAuthority(warden.Authority)
	connectionPDA, _, _ := solana.GetConnectionPDA(seekerPDA, wardenPDA)

	_, err = n.solana.FetchConnectionAccount(connectionPDA)
	if err == nil {
		logger.Solana("Connection account %s already exists. Skipping on-chain initialization.", connectionPDA)
	} else if strings.Contains(err.Error(), "not found") {
		logger.Solana("Initializing on-chain connection with Warden %s...", warden.Authority)
		sig, err := n.solana.StartConnection(warden.Authority, estimatedMb)
		if err != nil {
			return fmt.Errorf("failed to initialize connection account: %w", err)
		}
		
		logger.Solana("Connection initialized. Sig: %s", sig)
		logger.Solana("Waiting for transaction confirmation...")
		if err := n.solana.WaitForConfirmation(ctx, *sig); err != nil {
			return fmt.Errorf("failed to confirm connection transaction: %w", err)
		}
		logger.Solana("Transaction confirmed. Proceeding with P2P handshake...")
	} else {
		return fmt.Errorf("failed to check connection account status: %w", err)
	}

	if err := n.p2p.Connect(ctx, multiaddrStr); err != nil {
		return fmt.Errorf("libp2p connect failed: %w", err)
	}

	seekerAuth := n.solana.Signer.PublicKey().String()
	if err := n.p2p.RequestTunnel(ctx, info.ID, seekerAuth, wardenPDA, warden.Authority); err != nil {
		return fmt.Errorf("vpn tunnel handshake failed: %w", err)
	}

	go n.refreshCache("seeker")

	return nil
}

func (n *ZarkhamNode) DisconnectWarden(ctx context.Context, profile, wardenAuthority string) error {
	logger.Info("CORE", "Requesting disconnect from Warden: %s", wardenAuthority)

	n.mu.Lock()
	n.isDisconnecting = true
	n.mu.Unlock()

	var wardenAuth solanago.PublicKey
	if wardenAuthority != "" {
		wardenAuth, _ = solanago.PublicKeyFromBase58(wardenAuthority)
	}

	if !wardenAuth.IsZero() {
		if err := n.p2p.CloseConnectionByWardenPDA(wardenAuth); err == nil {
			logger.Success("VPN", "Local WireGuard tunnel closed successfully.")
		}
	} else {
		logger.Warn("CORE", "No valid warden authority provided. Entering Cleanup Mode.")
		n.p2p.CloseAllConnections()
	}

	go func() {
		defer func() {
			n.mu.Lock()
			n.isDisconnecting = false
			n.mu.Unlock()
			n.refreshCache(profile)
		}()

		if !wardenAuth.IsZero() {
			logger.Solana("Initiating background on-chain disconnect...")
			sig, err := n.solana.EndConnection(wardenAuth)
			if err != nil {
				logger.Error("SOLANA", "Background: On-chain EndConnection failed (PDA: %s): %v", wardenAuth, err)
				return
			}
			
			logger.Solana("Background: On-chain connection closing. Sig: %s", sig)
			if err := n.solana.WaitForConfirmation(context.Background(), *sig); err != nil {
				logger.Warn("SOLANA", "Background: Disconnect confirmation warning: %v", err)
			} else {
				logger.Success("SOLANA", "Background: Disconnect confirmed on-chain.")
			}
		} else {
			logger.Solana("Scanning for lingering on-chain connections...")
			conns, err := n.solana.FetchMyConnections("seeker")
			if err == nil {
				for _, c := range conns {
					logger.Warn("SOLANA", "Found lingering connection PDA %s. Closing...", c.PublicKey)
					sig, err := n.solana.EndConnection(c.Account.Warden)
					if err == nil {
						logger.Success("SOLANA", "Lingering connection closed. Sig: %s", sig)
					}
				}
			}
		}
	}()

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

func (n *ZarkhamNode) TransferFunds(ctx context.Context, profile, recipientStr string, amount float64) (string, error) {
	pk, err := n.storage.wallet.GetWallet(profile)
	if err != nil {
		return "", err
	}

	recipient, err := solanago.PublicKeyFromBase58(recipientStr)
	if err != nil {
		return "", fmt.Errorf("invalid recipient address: %w", err)
	}

	sc, err := solana.NewClient(n.config.RpcEndpoint, pk)
	if err != nil {
		return "", err
	}

	lamports := uint64(amount * 1e9)
	sig, err := sc.TransferSOL(recipient, lamports)
	if err != nil {
		return "", err
	}

	return sig.String(), nil
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
	pk, err := n.storage.wallet.GetWallet(profile)
	if err != nil {
		return "", err
	}

	sc, err := solana.NewClient(n.config.RpcEndpoint, pk)
	if err != nil {
		return "", err
	}

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
		logger.Warn("CORE", "Could not determine public IP for registration. Using 0.0.0.0")
	}

	ipHash := sha256.Sum256([]byte(ipStr))

	sig, err := sc.InitializeWarden(token, lamports, peerID, 0, ipHash)
	if err != nil {
		return "", err
	}
	
	go n.refreshCache(profile)
	return sig.String(), nil
}

func (n *ZarkhamNode) GetHistory(ctx context.Context, profile string) (*solana.HistoryResult, error) {
	pk, err := n.storage.wallet.GetWallet(profile)
	if err != nil {
		return nil, fmt.Errorf("profile not found")
	}

	var sc *solana.Client
	if n.solana != nil {
		sc = n.solana
	} else {
		sc, err = solana.NewReadOnlyClient(n.config.RpcEndpoint)
		if err != nil {
			return nil, err
		}
	}

	return sc.GetHistory(pk.PublicKey())
}
