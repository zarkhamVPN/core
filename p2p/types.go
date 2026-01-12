package p2p

import (
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
	WardenAuthority solana.PublicKey
	ConnectionPDA   solana.PublicKey
	Interface       *wgctrl.Client
	InterfaceName   string
	LocalKey        wgtypes.Key
	RemoteKey       wgtypes.Key
	StopChan        chan struct{}
	AttestedBytes   uint64
}

// NodeStatus represents the current state of the P2P node
type NodeStatus struct {
	IsRunning bool     `json:"isRunning"`
	PeerID    string   `json:"peerId,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}
