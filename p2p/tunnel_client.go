package p2p

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"zarkham/core/solana"
	"zarkham/core/vpn"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"golang.zx2c4.com/wireguard/wgtypes"
)

// RequestTunnel initiates the VPN handshake with a remote Warden.
func (m *Manager) RequestTunnel(ctx context.Context, remotePID peer.ID, seekerAuthority string) error {
	// 1. Generate Local WireGuard Keys
	privKey, pubKey, err := vpn.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate wg keys: %w", err)
	}

	// 2. Open Stream to Warden
	stream, err := m.host.NewStream(ctx, remotePID, ProtocolKeyExchange)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// 3. Send Handshake Request
	req := KeyExchangeRequest{
		WireGuardPublicKey: pubKey.String(),
		SeekerAuthority:    seekerAuthority,
	}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		return fmt.Errorf("failed to send handshake request: %w", err)
	}

	log.Printf("VPN: Sent tunnel request to %s (My PubKey: %s)", remotePID, pubKey.String())

	// 4. Receive Handshake Response
	var resp KeyExchangeResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		return fmt.Errorf("failed to read handshake response: %w", err)
	}

	log.Printf("VPN: Handshake successful! Warden Endpoint: %s, AllowedIP: %s", resp.Endpoint, resp.SeekerAllowedIP)

	// 5. Configure Local Interface
	ifaceName := fmt.Sprintf("arkhamwg%d", len(m.activeConnections))
	// Seekers don't need a specific listening port usually, but we assign one to be safe
	listenPort := 51820 + len(m.activeConnections) 

	wgClient, err := vpn.SetupInterface(ifaceName, privKey, listenPort)
	if err != nil {
		return fmt.Errorf("failed to setup local interface: %w", err)
	}

	wardenWgKey, err := wgtypes.ParseKey(resp.WireGuardPublicKey)
	if err != nil {
		return fmt.Errorf("invalid warden wg key: %w", err)
	}

	// 6. Add Warden Peer & Route Traffic
	// We route 0.0.0.0/0 through the Warden
	err = vpn.AddPeer(wgClient, ifaceName, wardenWgKey, []string{"0.0.0.0/0"}, resp.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to add warden peer: %w", err)
	}

	// 7. Setup System Routing
	// The Seeker's "Gateway" is the Warden's tunnel IP (usually x.x.x.1 in a /24, but here P2P)
	// We use the IP assigned to us by the warden as the source hint
	if err := vpn.SetupSeekerRouting(ifaceName, resp.SeekerAllowedIP); err != nil {
		return fmt.Errorf("failed to setup system routing: %w", err)
	}

	log.Printf("VPN: Tunnel established on %s", ifaceName)
	return nil
}
