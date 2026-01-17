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
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (m *Manager) RegisterHandlers(sc *solana.Client) {
	m.solanaClient = sc
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
	logger.VPN("Key exchange request from %s", remotePeer)

	var req KeyExchangeRequest
	if err := json.NewDecoder(s).Decode(&req); err != nil {
		logger.Error("VPN", "Failed to decode request: %v", err)
		return
	}

	seekerWgKey, err := wgtypes.ParseKey(req.WireGuardPublicKey)
	if err != nil {
		logger.Error("VPN", "Invalid WG key: %v", err)
		return
	}

	seekerAuthority, err := solanago.PublicKeyFromBase58(req.SeekerAuthority)
	if err != nil {
		logger.Error("VPN", "Invalid authority: %v", err)
		return
	}

	// 1. Verify On-Chain Connection
	seekerPDA, _, _ := solana.GetSeekerPDA(seekerAuthority)
	wardenPDA, _, _ := sc.GetWardenPDA()
	connPDA, _, _ := solana.GetConnectionPDA(seekerPDA, wardenPDA)

	connAccount, err := sc.FetchConnectionAccount(connPDA)
	if err != nil {
		logger.Error("VPN", "Failed to fetch connection account %s: %v", connPDA, err)
		return
	}

	if connAccount.AmountEscrowed == 0 {
		logger.Warn("VPN", "Connection account has zero escrow")
		return
	}

	// 2. Allocate Resources
	seekerTunnelIP, err := m.ipPool.AllocateIP(remotePeer.String())
	if err != nil {
		logger.Error("VPN", "IP allocation failed: %v", err)
		return
	}

	// 3. Generate Warden Keys
	privKey, pubKey, err := vpn.GenerateKeyPair()
	if err != nil {
		logger.Error("VPN", "Key generation failed: %v", err)
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
		logger.Error("VPN", "Interface setup failed: %v", err)
		m.ipPool.ReleaseIP(remotePeer.String())
		return
	}

	// 5. Add Peer
	seekerAllowedIP := fmt.Sprintf("%s/32", seekerTunnelIP.String())
	err = vpn.AddPeer(wgClient, ifaceName, seekerWgKey, []string{seekerAllowedIP}, "")
	if err != nil {
		logger.Error("VPN", "Failed to add peer: %v", err)
		wgClient.Close()
		m.ipPool.ReleaseIP(remotePeer.String())
		return
	}

	// 6. Configure Warden's Interface IP and Routing
	// Assign the gateway IP to the Warden's interface
	wardenGatewayIP := vpn.GetWardenGatewayIP(seekerTunnelIP)
	if err := vpn.SetupWardenRouting(ifaceName, wardenGatewayIP, seekerTunnelIP.String()); err != nil {
		logger.Error("VPN", "Routing setup failed: %v", err)
	}

	// 7. Send Response
	endpoint := getPublicEndpoint(m.host, listenPort)
	
	// Use Cluster Time for handshake to prevent ProofTooOld errors due to clock drift
	clusterTime, err := sc.GetClusterTime(context.Background())
	if err != nil {
		logger.Warn("VPN", "Could not fetch cluster time, falling back to system time: %v", err)
		clusterTime = time.Now().Unix()
	} else {
		logger.P2P("Handshake anchored to Cluster Time: %d", clusterTime)
	}

	resp := KeyExchangeResponse{
		WireGuardPublicKey: pubKey.String(),
		Endpoint:           endpoint,
		WardenAllowedIP:    "0.0.0.0/0",
		SeekerAllowedIP:    seekerAllowedIP,
		Timestamp:          clusterTime,
	}

	if err := json.NewEncoder(s).Encode(resp); err != nil {
		logger.Error("VPN", "Failed to send response: %v", err)
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

	logger.Success("VPN", "Session established with %s on %s (Gateway: %s, Seeker: %s)", 
		remotePeer, ifaceName, wardenGatewayIP, seekerAllowedIP)
}

func (m *Manager) handleBandwidth(s network.Stream, sc *solana.Client) {
	remotePeer := s.Conn().RemotePeer()
	
	var batch BatchedCertificate
	if err := json.NewDecoder(s).Decode(&batch); err != nil {
		logger.Error("VPN", "Failed to decode bandwidth batch: %v", err)
		return
	}

	if len(batch.Certificates) == 0 { return }

	// 1. Process Batch (Validate and SUM)
	var totalBatchMB uint64
	for _, tc := range batch.Certificates {
		totalBatchMB += tc.CumulativeMB
	}

	// For on-chain submission, we use the LATEST TC's metadata (Sig, TS)
	// but with the SUMMED MB of the entire batch.
	// NOTE: This requires the seeker to have signed the SUMMED amount.
	// WAIT! The Seeker only signed the individual TCs.
	
	// FIX: The Warden must submit the TCs one by one? NO (too expensive).
	// The Seeker must sign the BATCH TOTAL.
	
	latestTC := batch.Certificates[len(batch.Certificates)-1]
	
	logger.VPN("Received Batch %d from %s (%d TCs, Total Delta: %d MB)", 
		batch.BatchID, remotePeer, len(batch.Certificates), totalBatchMB)

	m.mu.Lock()
	_, exists := m.activeConnections[remotePeer]
	m.mu.Unlock()

	if !exists {
		logger.Warn("VPN", "Received batch for unknown connection %s", remotePeer)
		return
	}

	// 2. Countersign (Warden part)
	// Note: We'd verify MBs against our local stats here too
	
	// 3. Submit to Chain
	if m.SubmitTC {
		go func(tc ThroughputCertificate) {
			logger.VPN("Submitting Proof to Solana: [Seq %d | %d MB]...", tc.SequenceNumber, tc.CumulativeMB)
			
			sig, err := sc.SubmitBandwidthProof(
				tc.CumulativeMB, 
				tc.SeekerAuthority, 
				tc.SeekerSignature, 
				tc.Timestamp,
			)
			if err != nil {
				logger.Error("VPN", "On-chain submission FAILED: %v", err)
				return
			}
			logger.Success("SOLANA", "Proof confirmed! [Seq %d | %d MB] -> Sig: %s", tc.SequenceNumber, tc.CumulativeMB, sig)
		}(latestTC)
	} else {
		logger.Warn("VPN", "TC Submission disabled by config. Skipping on-chain proof.")
	}

	// 4. Send Ack
	freshClusterTime, _ := sc.GetClusterTime(context.Background())
	if freshClusterTime == 0 { freshClusterTime = time.Now().Unix() }

	ack := P2PBandwidthAck{
		AcceptedCerts:      []uint64{latestTC.SequenceNumber},
		LastSubmittedSeq:   latestTC.SequenceNumber,
		CurrentClusterTime: freshClusterTime,
	}
	if err := json.NewEncoder(s).Encode(ack); err != nil {
		logger.Error("VPN", "Failed to send bandwidth ack: %v", err)
	}
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
