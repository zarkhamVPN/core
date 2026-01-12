package tests

import (
	"testing"
	"zarkham/core/p2p"
)

func TestIPPoolAllocation(t *testing.T) {
	pool := p2p.NewIPPoolManager("10.10.10.0")

	// 1. Allocate first IP
	ip1, err := pool.AllocateIP("peerA")
	if err != nil {
		t.Fatalf("Failed to allocate first IP: %v", err)
	}
	if ip1.String() != "10.10.10.2" {
		t.Errorf("Expected 10.10.10.2, got %s", ip1.String())
	}

	// 2. Allocate second IP
	ip2, err := pool.AllocateIP("peerB")
	if err != nil {
		t.Fatalf("Failed to allocate second IP: %v", err)
	}
	if ip2.String() != "10.10.10.3" {
		t.Errorf("Expected 10.10.10.3, got %s", ip2.String())
	}

	// 3. Test Idempotency (Same peer gets same IP)
	ip1Again, err := pool.AllocateIP("peerA")
	if err != nil {
		t.Fatalf("Failed to re-allocate peerA: %v", err)
	}
	if ip1Again.String() != ip1.String() {
		t.Errorf("Idempotency failed. Expected %s, got %s", ip1.String(), ip1Again.String())
	}

	// 4. Release and Re-use
	pool.ReleaseIP("peerB")
	ip3, err := pool.AllocateIP("peerC")
	if err != nil {
		t.Fatalf("Failed to allocate peerC: %v", err)
	}
	// Note: Simple implementation usually just increments nextOffset, 
	// it doesn't reuse holes immediately unless specific logic exists. 
	// Our current logic increments offset. So peerC should be .4
	if ip3.String() != "10.10.10.4" {
		t.Errorf("Expected 10.10.10.4 (incremental), got %s", ip3.String())
	}
}
