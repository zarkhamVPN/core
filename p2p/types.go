package p2p

import (
	"zarkham/core/vpn"

	"github.com/gagliardetto/solana-go"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	ProtocolStream      = "/zarkham/vpn/1.0.0"
	ProtocolKeyExchange = "/zarkham/vpn-key-exchange/1.0.0"
	ProtocolBandwidth   = "/zarkham/bandwidth/1.0.0"
	ProtocolPing        = "/zarkham/ping/1.0.0"
	ProtocolMDNS        = "zarkham-vpn-local"
	ProtocolDHT         = "zarkham-vpn-global"
)

// KeyExchangeRequest is sent from seeker to warden to initiate tunnel setup
type KeyExchangeRequest struct {
	WireGuardPublicKey string `json:"wireguard_public_key"`
	SeekerAuthority    string `json:"seeker_authority"`
}

// KeyExchangeResponse is sent from warden to seeker
type KeyExchangeResponse struct {
	WireGuardPublicKey string `json:"wireguard_public_key"`
	Endpoint           string `json:"endpoint"` // Warden's public IP and port
	WardenAllowedIP    string `json:"warden_allowed_ip"`
	SeekerAllowedIP    string `json:"seeker_allowed_ip"`
	Timestamp          int64  `json:"timestamp"` // Added for clock synchronization
}

// PeerInfo holds detailed information about a discovered peer
type PeerInfo struct {
	ID      string   `json:"id"`
	Addrs   []string `json:"addrs"`
	Latency int64    `json:"latency"`
}

// WireGuardConnection holds the state for an active WireGuard tunnel
type WireGuardConnection struct {
	SeekerPeerID    peer.ID
	WardenPeerID    peer.ID
	SeekerAuthority solana.PublicKey
	WardenAuthority solana.PublicKey // Added: Required for correct signing
	WardenPDA       solana.PublicKey
	ConnectionPDA   solana.PublicKey
	Interface       *wgctrl.Client
	InterfaceName   string
	LocalKey        wgtypes.Key
	RemoteKey       wgtypes.Key
	StopChan        chan struct{}
	AttestedBytes   uint64
	IsWarden        bool
	SeekerIP        string

	// BC Protocol Fields
	ClockOffset       int64 // WardenTime - LocalTime
	CertBuffer        []ThroughputCertificate
	SequenceCount     uint64
	LastStatsRx       uint64
	LastStatsTx       uint64
	LastAttestedBytes uint64 // Added: Total bytes handled in previous TCs
	CumulativeMB      uint64
}

func (c *WireGuardConnection) Close() {
	if c.Interface != nil {
		if c.IsWarden {
			vpn.TeardownWardenRouting(c.InterfaceName, c.SeekerIP)
		} else {
			vpn.TeardownRouting(c.InterfaceName)
		}
		c.Interface.Close()
	}
}

func (c *WireGuardConnection) GetStats() (uint64, uint64) {
	if c.Interface == nil { return 0, 0 }
	dev, err := c.Interface.Device(c.InterfaceName)
	if err != nil { return 0, 0 }
	
	totalRx := uint64(0)
	totalTx := uint64(0)
	for _, p := range dev.Peers {
		if p.PublicKey == c.RemoteKey {
			totalRx += uint64(p.ReceiveBytes)
			totalTx += uint64(p.TransmitBytes)
		}
	}
	return totalRx, totalTx
}

// ThroughputCertificate represents a verified data claim for a 5-second interval
type ThroughputCertificate struct {
	SeekerAuthority   solana.PublicKey `json:"seeker_authority"`
	WardenAuthority   solana.PublicKey `json:"warden_authority"`
	ConnectionPDA     solana.PublicKey `json:"connection_pda"`
	CumulativeMB      uint64           `json:"cumulative_mb"`
	BytesThisInterval uint64           `json:"bytes_this_interval"`
	Timestamp         int64            `json:"timestamp"`
	SequenceNumber    uint64           `json:"sequence_number"`
	SeekerSignature   [64]byte         `json:"seeker_signature"`
	WardenSignature   [64]byte         `json:"warden_signature"`
}

// BatchedCertificate is sent from seeker to warden every minute
type BatchedCertificate struct {
	Certificates []ThroughputCertificate `json:"certificates"`
	BatchID      uint64                  `json:"batch_id"`
}

// P2PBandwidthAck is sent from warden back to seeker
type P2PBandwidthAck struct {
	AcceptedCerts      []uint64   `json:"accepted_certs"`
	WardenSignatures   [][64]byte `json:"warden_signatures"`
	LastSubmittedSeq   uint64     `json:"last_submitted_seq"`
	CurrentClusterTime int64      `json:"current_cluster_time"` // Added for continuous sync
}

// NodeStatus represents the current state of the P2P node
type NodeStatus struct {
	IsRunning bool     `json:"isRunning"`
	PeerID    string   `json:"peerId,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}
