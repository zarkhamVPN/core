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

// BandwidthProofRequest is sent from warden to seeker to request a signature for data consumed
type BandwidthProofRequest struct {
	MbConsumed uint64 `json:"mb_consumed"`
	Timestamp  int64  `json:"timestamp"`
}

// BandwidthProofResponse is sent from seeker back to warden with the signature
type BandwidthProofResponse struct {
	Signature string `json:"signature"` // Base58 encoded solana.Signature
}

// NodeStatus represents the current state of the P2P node
type NodeStatus struct {
	IsRunning bool     `json:"isRunning"`
	PeerID    string   `json:"peerId,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}
