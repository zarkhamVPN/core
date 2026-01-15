package p2p

import (
	"encoding/json"
	"fmt"
	"log"

	"zarkham/core/solana"
	"zarkham/core/vpn"

	solanago "github.com/gagliardetto/solana-go"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (m *Manager) RegisterHandlers(sc *solana.Client) {
	m.host.SetStreamHandler(ProtocolKeyExchange, m.wrapHandler(m.handleKeyExchange, sc))
	m.host.SetStreamHandler(ProtocolBandwidth, m.wrapHandler(m.handleBandwidth, sc))
	m.host.SetStreamHandler(ProtocolPing, pingHandler)
}

func (m *Manager) wrapHandler(handler func(network.Stream, *solana.Client), sc *solana.Client) network.StreamHandler {
	return func(s network.Stream) {
		defer s.Close()
		handler(s, sc)
	}
}

func (m *Manager) handleKeyExchange(s network.Stream, sc *solana.Client) {
	remotePeer := s.Conn().RemotePeer()
	log.Printf("VPN: Key exchange request from %s", remotePeer)

	var req KeyExchangeRequest
	if err := json.NewDecoder(s).Decode(&req); err != nil {
		log.Printf("VPN: Failed to decode request: %v", err)
		return
	}

	seekerWgKey, err := wgtypes.ParseKey(req.WireGuardPublicKey)
	if err != nil {
		log.Printf("VPN: Invalid WG key: %v", err)
		return
	}

	seekerAuthority, err := solanago.PublicKeyFromBase58(req.SeekerAuthority)
	if err != nil {
		log.Printf("VPN: Invalid authority: %v", err)
		return
	}

	// 1. Verify On-Chain Connection
	seekerPDA, _, _ := solana.GetSeekerPDA(seekerAuthority)
	wardenPDA, _, _ := sc.GetWardenPDA()
	connPDA, _, _ := solana.GetConnectionPDA(seekerPDA, wardenPDA)

	connAccount, err := sc.FetchConnectionAccount(connPDA)
	if err != nil {
		log.Printf("VPN: Failed to fetch connection account %s: %v", connPDA, err)
		return
	}

	if connAccount.AmountEscrowed == 0 {
		log.Printf("VPN: Connection account has zero escrow")
		return
	}

	// 2. Allocate Resources
	seekerTunnelIP, err := m.ipPool.AllocateIP(remotePeer.String())
	if err != nil {
		log.Printf("VPN: IP allocation failed: %v", err)
		return
	}

	// 3. Generate Warden Keys
	privKey, pubKey, err := vpn.GenerateKeyPair()
	if err != nil {
		log.Printf("VPN: Key generation failed: %v", err)
		m.ipPool.ReleaseIP(remotePeer.String())
		return
	}

	// 4. Setup Interface
	m.mu.Lock()
	ifaceName := fmt.Sprintf("arkhamwg%d", len(m.activeConnections))
	listenPort := 51821 + len(m.activeConnections)
	m.mu.Unlock()

	wgClient, err := vpn.SetupInterface(ifaceName, privKey, listenPort)
	if err != nil {
		log.Printf("VPN: Interface setup failed: %v", err)
		m.ipPool.ReleaseIP(remotePeer.String())
		return
	}

	// 5. Add Peer
	seekerAllowedIP := fmt.Sprintf("%s/32", seekerTunnelIP.String())
	err = vpn.AddPeer(wgClient, ifaceName, seekerWgKey, []string{seekerAllowedIP}, "")
	if err != nil {
		log.Printf("VPN: Failed to add peer: %v", err)
		wgClient.Close()
		m.ipPool.ReleaseIP(remotePeer.String())
		return
	}

	// 6. Configure Warden's Interface IP and Routing
	// Assign the gateway IP to the Warden's interface
	wardenGatewayIP := vpn.GetWardenGatewayIP(seekerTunnelIP)
	if err := vpn.SetupWardenRouting(ifaceName, wardenGatewayIP, seekerTunnelIP.String()); err != nil {
		log.Printf("VPN: Routing setup failed: %v", err)
	}

	// 7. Send Response
	endpoint := getPublicEndpoint(m.host, listenPort)
	resp := KeyExchangeResponse{
		WireGuardPublicKey: pubKey.String(),
		Endpoint:           endpoint,
		WardenAllowedIP:    "0.0.0.0/0",
		SeekerAllowedIP:    seekerAllowedIP,
	}

	if err := json.NewEncoder(s).Encode(resp); err != nil {
		log.Printf("VPN: Failed to send response: %v", err)
		wgClient.Close()
		m.ipPool.ReleaseIP(remotePeer.String())
		return
	}

	// 8. Track Connection
	conn := &WireGuardConnection{
		SeekerPeerID:    remotePeer,
		WardenPeerID:    m.host.ID(),
		SeekerAuthority: seekerAuthority,
		ConnectionPDA:   connPDA,
		Interface:       wgClient,
		InterfaceName:   ifaceName,
		LocalKey:        privKey,
		RemoteKey:       seekerWgKey,
		StopChan:        make(chan struct{}),
		IsWarden:        true,
		SeekerIP:        seekerTunnelIP.String(),
	}

	m.mu.Lock()
	m.activeConnections[remotePeer] = conn
	m.mu.Unlock()

	log.Printf("VPN: Session established with %s on %s (Gateway: %s, Seeker: %s)", 
		remotePeer, ifaceName, wardenGatewayIP, seekerAllowedIP)
}

func (m *Manager) handleBandwidth(s network.Stream, sc *solana.Client) {
}

func pingHandler(s network.Stream) {
	buf := make([]byte, 1)
	_, _ = s.Read(buf)
}

func getPublicEndpoint(h host.Host, listenPort int) string {
	var publicAddr multiaddr.Multiaddr
	
	for _, addr := range h.Addrs() {
		if manet.IsPublicAddr(addr) {
			if _, err := addr.ValueForProtocol(multiaddr.P_IP4); err == nil {
				publicAddr = addr
				break
			}
		}
	}

	if publicAddr == nil {
		for _, addr := range h.Addrs() {
			if manet.IsPublicAddr(addr) {
				publicAddr = addr
				break
			}
		}
	}

	if publicAddr == nil && len(h.Addrs()) > 0 {
		publicAddr = h.Addrs()[0]
	}

	if publicAddr == nil { return "" }

	ip, err := publicAddr.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		ip, _ = publicAddr.ValueForProtocol(multiaddr.P_IP6)
	}

	return fmt.Sprintf("/ip4/%s/udp/%d", ip, listenPort)
}
