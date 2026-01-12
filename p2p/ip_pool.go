package p2p

import (
	"fmt"
	"log"
	"net"
	"sync"
)

type IPPoolManager struct {
	mu          sync.Mutex
	baseIP      net.IP
	nextOffset  uint8
	allocations map[string]net.IP
}

func NewIPPoolManager(baseNetwork string) *IPPoolManager {
	ip := net.ParseIP(baseNetwork)
	return &IPPoolManager{
		baseIP:      ip,
		nextOffset:  2, // Start from .2 (warden is .1)
		allocations: make(map[string]net.IP),
	}
}

func (ipm *IPPoolManager) AllocateIP(peerID string) (net.IP, error) {
	ipm.mu.Lock()
	defer ipm.mu.Unlock()

	if ip, exists := ipm.allocations[peerID]; exists {
		return ip, nil
	}

	if ipm.nextOffset > 254 {
		return nil, fmt.Errorf("IP pool exhausted")
	}

	ip := make(net.IP, len(ipm.baseIP))
	copy(ip, ipm.baseIP)
	ip[len(ip)-1] = ipm.nextOffset
	ipm.nextOffset++

	ipm.allocations[peerID] = ip
	log.Printf("IP_POOL: Allocated %s to peer %s", ip.String(), peerID)
	return ip, nil
}

func (ipm *IPPoolManager) ReleaseIP(peerID string) {
	ipm.mu.Lock()
	defer ipm.mu.Unlock()
	delete(ipm.allocations, peerID)
	log.Printf("IP_POOL: Released IP for peer %s", peerID)
}
