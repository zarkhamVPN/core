package vpn

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"

	"github.com/multiformats/go-multiaddr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GenerateKeyPair creates a new WireGuard private and public key pair.
func GenerateKeyPair() (wgtypes.Key, wgtypes.Key, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}
	return priv, priv.PublicKey(), nil
}

// SetupInterface creates and configures a WireGuard interface.
func SetupInterface(name string, privKey wgtypes.Key, port int) (*wgctrl.Client, error) {
	// Cleanup existing
	_ = exec.Command("ip", "link", "delete", name).Run()

	// Create interface
	if err := exec.Command("ip", "link", "add", name, "type", "wireguard").Run(); err != nil {
		return nil, fmt.Errorf("failed to create wg interface: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	cfg := wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &port,
	}

	if err := client.ConfigureDevice(name, cfg); err != nil {
		client.Close()
		return nil, err
	}

	if err := exec.Command("ip", "link", "set", name, "up").Run(); err != nil {
		client.Close()
		return nil, err
	}

	log.Printf("WireGuard interface %s initialized on port %d", name, port)
	return client, nil
}

// AddPeer adds a remote peer to the WireGuard interface.
func AddPeer(client *wgctrl.Client, iface string, pubKey wgtypes.Key, allowedIPs []string, endpoint string) error {
	parsedIPs := make([]net.IPNet, len(allowedIPs))
	for i, ipStr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("invalid allowed IP: %s", ipStr)
		}
		parsedIPs[i] = *ipNet
	}

	var udpAddr *net.UDPAddr
	if endpoint != "" {
		maddr, err := multiaddr.NewMultiaddr(endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint: %w", err)
		}
		udpAddr, err = extractUDPEndpoint(maddr)
		if err != nil {
			return err
		}
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  pubKey,
			AllowedIPs: parsedIPs,
			Endpoint:   udpAddr,
		}},
	}

	return client.ConfigureDevice(iface, cfg)
}

func extractUDPEndpoint(maddr multiaddr.Multiaddr) (*net.UDPAddr, error) {
	var ipStr string
	var port int
	var foundIP, foundUDP bool

	multiaddr.ForEach(maddr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case multiaddr.P_IP4, multiaddr.P_IP6:
			ipStr = c.Value()
			foundIP = true
		case multiaddr.P_UDP:
			port, _ = strconv.Atoi(c.Value())
			foundUDP = true
		}
		return true
	})

	if !foundIP || !foundUDP {
		return nil, fmt.Errorf("missing IP or UDP")
	}
	return &net.UDPAddr{IP: net.ParseIP(ipStr), Port: port}, nil
}
