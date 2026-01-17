package p2p

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	"zarkham/core/logger"
	"zarkham/core/solana"
	"zarkham/core/storage"
	solanago "github.com/gagliardetto/solana-go"
	"github.com/libp2p/go-libp2p"
	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type Manager struct {
	mu                sync.Mutex
	host              host.Host
	dht               *kaddht.IpfsDHT
	mdns              mdns.Service
	isRunning         bool
	storage           *storage.IdentityStorage
	ipPool            *IPPoolManager
	activeConnections map[peer.ID]*WireGuardConnection
	solanaClient      *solana.Client
	SubmitTC          bool
}

func NewManager(is *storage.IdentityStorage) *Manager {
	return &Manager{
		storage:           is,
		ipPool:            NewIPPoolManager("10.10.10.0"),
		activeConnections: make(map[peer.ID]*WireGuardConnection),
	}
}

func (m *Manager) CloseConnectionByWardenPDA(pda solanago.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for pid, conn := range m.activeConnections {
		if conn.WardenPDA.Equals(pda) {
			logger.P2P("Closing connection to Warden PDA %s (Peer: %s)", pda, pid)
			conn.Close()
			delete(m.activeConnections, pid)
			return nil
		}
	}
	return fmt.Errorf("connection not found for warden PDA %s", pda)
}

func (m *Manager) CloseAllConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for pid, conn := range m.activeConnections {
		logger.P2P("Closing connection to Peer %s", pid)
		conn.Close()
		delete(m.activeConnections, pid)
	}
}

func (m *Manager) Start(ctx context.Context, listenIP string, listenPort int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isRunning {
		return nil
	}

	privKey, err := m.getIdentity()
	if err != nil {
		return err
	}

	relays, _ := peer.AddrInfosFromP2pAddrs(kaddht.DefaultBootstrapPeers...)

	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.EnableNATService(),
		libp2p.EnableAutoRelayWithStaticRelays(relays),
	}

	if listenIP != "" {
		opts = append(opts, libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/%s/tcp/%d", listenIP, listenPort),
			fmt.Sprintf("/ip4/%s/udp/%d/quic-v1", listenIP, listenPort),
		))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return err
	}
	m.host = h

	if err := m.setupDiscovery(); err != nil {
		h.Close()
		return err
	}

	m.isRunning = true
	logger.Success("P2P", "Zarkham P2P Host started: %s", h.ID().String())
	
	// Categorize and Log Multiaddrs for user
	for _, addr := range h.Addrs() {
		fullAddr := fmt.Sprintf("%s/p2p/%s", addr, h.ID())
		label := "[Other]"

		isPublic := manet.IsPublicAddr(addr)
		isIPv6 := strings.Contains(addr.String(), "ip6")

		if isPublic && !isIPv6 {
			label = "[Public IPv4 - RECOMMENDED]"
		} else if isPublic && isIPv6 {
			label = "[Public IPv6]"
		} else if !isPublic && !isIPv6 {
			if strings.Contains(addr.String(), "127.0.0.1") {
				label = "[Localhost]"
			} else {
				label = "[Private LAN IPv4]"
			}
		}

		logger.P2P("%-30s %s", label, fullAddr)
	}

	return nil
}

func (m *Manager) getIdentity() (crypto.PrivKey, error) {
	privKey, err := m.storage.GetIdentity("default")
	if err != nil {
		return nil, err
	}
	if privKey != nil {
		return privKey, nil
	}

	logger.Info("P2P", "Generating new P2P identity...")
	newKey, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := m.storage.SaveIdentity("default", newKey); err != nil {
		return nil, err
	}
	return newKey, nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return nil
	}

	// 1. Cleanup active tunnels
	for pid, conn := range m.activeConnections {
		logger.P2P("Closing connection to %s", pid)
		conn.Close()
	}
	m.activeConnections = make(map[peer.ID]*WireGuardConnection)

	// 2. Stop Services
	if m.mdns != nil { m.mdns.Close() }
	if m.dht != nil { m.dht.Close() }
	if m.host != nil { m.host.Close() }

	m.isRunning = false
	logger.Info("P2P", "Host stopped.")
	return nil
}

func (m *Manager) Status() NodeStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return NodeStatus{IsRunning: false}
	}

	addrs := []string{}
	for _, a := range m.host.Addrs() {
		addrs = append(addrs, a.String())
	}

	return NodeStatus{
		IsRunning: true,
		PeerID:    m.host.ID().String(),
		Addresses: addrs,
	}
}

func (m *Manager) Host() host.Host {
	return m.host
}

func (m *Manager) GetActiveTunnels() []peer.ID {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	ids := make([]peer.ID, 0, len(m.activeConnections))
	for id := range m.activeConnections {
		ids = append(ids, id)
	}
	return ids
}

func (m *Manager) GetTotalBandwidth() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	total := uint64(0)
	for _, conn := range m.activeConnections {
		rx, tx := conn.GetStats()
		total += (rx + tx)
	}
	return total
}

func (m *Manager) IsTunnelInterfaceActive() bool {
	client, err := wgctrl.New()
	if err != nil {
		return false
	}
	defer client.Close()

	_, err = client.Device("arkhamwg0")
	return err == nil
}

func (m *Manager) GetConnection(id peer.ID) *WireGuardConnection {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeConnections[id]
}

func (m *Manager) Connect(ctx context.Context, addr string) error {
	ma, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr: %w", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return fmt.Errorf("failed to get addr info: %w", err)
	}

	logger.P2P("Attempting to connect to %s (ID: %s)...", addr, info.ID)
	
	// Add local timeout to prevent hanging if parent ctx is too long
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := m.host.Connect(connectCtx, *info); err != nil {
		return err
	}
	logger.Success("P2P", "Successfully connected to %s", info.ID)
	return nil
}
