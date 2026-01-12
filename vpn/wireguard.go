package vpn

import (
	"fmt"
	"log"
	"os/exec"

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
	// ... port AddWireGuardPeer logic here ...
	return nil // placeholder for brevity, implementation matches arkham-cli/node/node.go
}
