package vpn

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Try with sudo if first attempt fails
		cmd = exec.Command("sudo", append([]string{name}, args...)...)
		if output, err = cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("command %s %v failed: %v (output: %s)", name, args, err, string(output))
		}
	}
	return nil
}

func SetupWardenRouting(ifaceName, vpnSubnet string) error {
	log.Printf("VPN: Setting up Warden routing for %s", ifaceName)
	
	// Enable IP forwarding
	_ = runCommand("sysctl", "-w", "net.ipv4.ip_forward=1")

	// Set up NAT (MASQUERADE)
	_ = runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpnSubnet, "-j", "MASQUERADE")
	_ = runCommand("iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	_ = runCommand("iptables", "-A", "FORWARD", "-s", vpnSubnet, "-j", "ACCEPT")

	return nil
}

func SetupSeekerRouting(ifaceName, gatewayIP string) error {
	log.Printf("VPN: Setting up Seeker routing for %s", ifaceName)
	
	// Policy Based Routing (PBR) to redirect all traffic through WG
	table := "51820"
	_ = runCommand("ip", "route", "add", "default", "dev", ifaceName, "table", table)
	_ = runCommand("ip", "rule", "add", "from", "all", "lookup", table, "pref", "200")

	// DNS Configuration
	log.Printf("VPN: Configuring DNS for %s", ifaceName)
	
	// Try resolvectl (systemd-resolved) - Pass IPs as SEPARATE arguments
	err := runCommand("resolvectl", "dns", ifaceName, "1.1.1.1", "1.0.0.1")
	if err == nil {
		_ = runCommand("resolvectl", "domain", ifaceName, "~.")
		return nil
	}
	
	log.Printf("Warning: resolvectl failed: %v. Trying nmcli...", err)

	// Fallback: nmcli (NetworkManager)
	// nmcli dev modify arkhamwg0 ipv4.dns "1.1.1.1 1.0.0.1"
	err = runCommand("nmcli", "dev", "modify", ifaceName, "ipv4.dns", "1.1.1.1 1.0.0.1")
	if err != nil {
		log.Printf("Warning: DNS setup failed. Internet access might be limited. Error: %v", err)
	}
	
	return nil
}

func TeardownRouting(ifaceName string) {
	_ = runCommand("ip", "rule", "del", "pref", "200")
	_ = runCommand("ip", "link", "delete", ifaceName)
}
