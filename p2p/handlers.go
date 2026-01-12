package p2p

import (
	"encoding/json"
	"log"

	"zarkham/core/solana"
	"github.com/libp2p/go-libp2p/core/network"
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
	var req KeyExchangeRequest
	if err := json.NewDecoder(s).Decode(&req); err != nil {
		log.Printf("P2P: Failed to decode key exchange: %v", err)
		return
	}
	log.Printf("P2P: Received key exchange request from %s", req.SeekerAuthority)
	// TODO: Integrate with VPN interface creation logic
}

func (m *Manager) handleBandwidth(s network.Stream, sc *solana.Client) {
	// Seeker signs bandwidth claims from Warden
}

func pingHandler(s network.Stream) {
	buf := make([]byte, 1)
	_, _ = s.Read(buf)
}
