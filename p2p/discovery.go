package p2p

import (
	"context"
	"log"
	"time"

	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
)

func (m *Manager) setupDiscovery() error {
	ctx := context.Background()
	h := m.host

	// 1. mDNS Setup
	m.mdns = mdns.NewMdnsService(h, ProtocolMDNS, &discoveryNotifee{h: h})
	if err := m.mdns.Start(); err != nil {
		return err
	}

	// 2. DHT Setup
	kdht, err := kaddht.New(ctx, h)
	if err != nil {
		return err
	}
	m.dht = kdht

	if err = kdht.Bootstrap(ctx); err != nil {
		return err
	}

	routingDiscovery := routing.NewRoutingDiscovery(kdht)
	util.Advertise(ctx, routingDiscovery, ProtocolDHT)

	// Peer discovery loop
	go func() {
		for {
			if !m.isRunning { return }
			peers, err := routingDiscovery.FindPeers(ctx, ProtocolDHT)
			if err != nil {
				time.Sleep(1 * time.Minute)
				continue
			}
			for p := range peers {
				if p.ID == h.ID() { continue }
				if h.Network().Connectedness(p.ID) != network.Connected {
					_ = h.Connect(ctx, p)
				}
			}
			time.Sleep(1 * time.Minute)
		}
	}()

	return nil
}

type discoveryNotifee struct {
	h host.Host
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() { return }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = n.h.Connect(ctx, pi)
}
