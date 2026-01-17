package p2p

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"zarkham/core/logger"
	"zarkham/core/solana"
	"zarkham/core/vpn"

	solanago "github.com/gagliardetto/solana-go"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (m *Manager) RequestTunnel(ctx context.Context, remotePID peer.ID, seekerAuthority string, wardenPDA solanago.PublicKey, wardenAuthority solanago.PublicKey) error {
	logger.P2P("Opening stream to Warden %s for handshake...", remotePID)
	
	privKey, pubKey, err := vpn.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate wg keys: %w", err)
	}

	stream, err := m.host.NewStream(ctx, remotePID, ProtocolKeyExchange)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	logger.P2P("Handshake stream opened. Sending keys...")

	req := KeyExchangeRequest{
		WireGuardPublicKey: pubKey.String(),
		SeekerAuthority:    seekerAuthority,
	}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		return fmt.Errorf("failed to send handshake request: %w", err)
	}

	logger.P2P("Keys sent. Waiting for Warden response...")

	var resp KeyExchangeResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		return fmt.Errorf("failed to read handshake response: %w", err)
	}

	logger.Success("VPN", "Handshake successful! Warden Endpoint: %s, AllowedIP: %s", resp.Endpoint, resp.SeekerAllowedIP)

	now := time.Now().Unix()
	clockOffset := resp.Timestamp - now
	
	if clockOffset != 0 {
		logger.P2P("Clock Drift Detected: %ds. Syncing timestamps...", clockOffset)
	}

	ifaceName := fmt.Sprintf("arkhamwg%d", len(m.activeConnections))
	listenPort := 51820 + len(m.activeConnections) 

	wgClient, err := vpn.SetupInterface(ifaceName, privKey, listenPort)
	if err != nil {
		return fmt.Errorf("failed to setup local interface: %w", err)
	}

	wardenWgKey, err := wgtypes.ParseKey(resp.WireGuardPublicKey)
	if err != nil {
		return fmt.Errorf("invalid warden wg key: %w", err)
	}

	err = vpn.AddPeer(wgClient, ifaceName, wardenWgKey, []string{"0.0.0.0/0"}, resp.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to add warden peer: %w", err)
	}

	if err := vpn.SetupSeekerRouting(ifaceName, resp.SeekerAllowedIP); err != nil {
		return fmt.Errorf("failed to setup system routing: %w", err)
	}

	seekerAuthorityPK := solanago.MustPublicKeyFromBase58(seekerAuthority)
	seekerPDA, _, _ := solana.GetSeekerPDA(seekerAuthorityPK)
	connectionPDA, _, _ := solana.GetConnectionPDA(seekerPDA, wardenPDA)

	conn := &WireGuardConnection{
		SeekerPeerID:    m.host.ID(),
		WardenPeerID:    remotePID,
		SeekerAuthority: seekerAuthorityPK,
		WardenAuthority: wardenAuthority,
		WardenPDA:       wardenPDA,
		ConnectionPDA:   connectionPDA,
		Interface:       wgClient,
		InterfaceName:   ifaceName,
		LocalKey:        privKey,
		RemoteKey:       wardenWgKey,
		StopChan:        make(chan struct{}),
		IsWarden:        false,
		ClockOffset:     clockOffset,
	}

	m.mu.Lock()
	m.activeConnections[remotePID] = conn
	m.mu.Unlock()

	logger.Success("VPN", "Tunnel established on %s", ifaceName)
	return nil
}