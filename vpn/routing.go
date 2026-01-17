package vpn

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"zarkham/core/logger"
)

const resolvConfPath = "/etc/resolv.conf"
const resolvConfBackup = "/etc/resolv.conf.zarkham.bak"

// DNSManager represents the active DNS management system
type DNSManager int

const (
	DNSManagerUnknown DNSManager = iota
	DNSManagerSystemdResolved
	DNSManagerNetworkManager
	DNSManagerResolvConf
	DNSManagerOpenResolv
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

// detectDNSManager identifies which DNS management system is active
func detectDNSManager() DNSManager {
	if isServiceActive("systemd-resolved") {
		return DNSManagerSystemdResolved
	}
	if isServiceActive("NetworkManager") {
		return DNSManagerNetworkManager
	}
	if _, err := exec.LookPath("resolvconf"); err == nil {
		return DNSManagerOpenResolv
	}
	return DNSManagerResolvConf
}

func isServiceActive(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "active"
}

func SetupWardenRouting(ifaceName, wardenIP, seekerIP string) error {
	logger.VPN("Setting up Warden routing for %s (Warden IP: %s, Seeker IP: %s)", 
		ifaceName, wardenIP, seekerIP)
	
	// Use /24 for the interface IP so it sees the seeker as local
	ipNoMask := strings.Split(wardenIP, "/")[0]
	if err := runCommand("ip", "addr", "add", ipNoMask+"/24", "dev", ifaceName); err != nil {
		logger.Warn("VPN", "Could not assign IP to %s: %v", ifaceName, err)
	}

	_ = runCommand("ip", "link", "set", ifaceName, "up")
	_ = runCommand("sysctl", "-w", "net.ipv4.ip_forward=1")

	_ = runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", seekerIP, "-j", "MASQUERADE")
	_ = runCommand("iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	_ = runCommand("iptables", "-A", "FORWARD", "-s", seekerIP, "-j", "ACCEPT")

	return nil
}

func SetupSeekerRouting(ifaceName, seekerIP string) error {
	logger.VPN("Setting up Seeker routing. Interface: %s, IP: %s", ifaceName, seekerIP)
	
	// 1. Assign local tunnel IP
	if err := runCommand("ip", "addr", "add", seekerIP, "dev", ifaceName); err != nil {
		logger.Warn("VPN", "Could not assign IP to %s: %v", ifaceName, err)
	}

	if err := runCommand("ip", "link", "set", ifaceName, "up"); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	// 2. CRITICAL: Prevent routing loop using fwmark
	table := "51820"
	_ = runCommand("ip", "route", "add", "default", "dev", ifaceName, "table", table)
	
	// Marked packets (VPN traffic) bypass the tunnel
	_ = runCommand("ip", "rule", "add", "fwmark", "51820", "lookup", "main", "pref", "100")
	// Unmarked packets (app traffic) go into the tunnel
	_ = runCommand("ip", "rule", "add", "not", "fwmark", "51820", "lookup", table, "pref", "200")

	// 3. DNS Configuration with smart detection
	return configureDNS(ifaceName)
}

func TeardownRouting(ifaceName string) {
	logger.VPN("Tearing down routing for %s", ifaceName)
	
	_ = runCommand("ip", "rule", "del", "pref", "100")
	_ = runCommand("ip", "rule", "del", "pref", "200")
	
	manager := detectDNSManager()
	switch manager {
	case DNSManagerSystemdResolved:
		_ = runCommand("resolvectl", "revert", ifaceName)
	case DNSManagerNetworkManager, DNSManagerOpenResolv:
		_ = runCommand("resolvconf", "-d", ifaceName)
		restoreResolvConf()
	case DNSManagerResolvConf:
		restoreResolvConf()
	}
	
	_ = runCommand("ip", "link", "delete", ifaceName)
}

func configureDNS(ifaceName string) error {
	logger.VPN("Configuring DNS for %s", ifaceName)
	dnsServers := []string{"1.1.1.1", "1.0.0.1"}
	manager := detectDNSManager()
	
	logger.VPN("Detected DNS manager: %v", manager)

	switch manager {
	case DNSManagerSystemdResolved:
		return configureDNSSystemdResolved(ifaceName, dnsServers)
	case DNSManagerNetworkManager, DNSManagerOpenResolv:
		if err := configureDNSOpenresolv(ifaceName, dnsServers); err == nil {
			return nil
		}
		logger.Warn("VPN", "openresolv failed, falling back to direct /etc/resolv.conf")
		fallthrough
	default:
		return overwriteResolvConf(dnsServers)
	}
}

func configureDNSSystemdResolved(ifaceName string, dnsServers []string) error {
	args := append([]string{"dns", ifaceName}, dnsServers...)
	if err := runCommand("resolvectl", args...); err != nil {
		return err
	}
	return runCommand("resolvectl", "domain", ifaceName, "~.")
}

func configureDNSOpenresolv(ifaceName string, dnsServers []string) error {
	config := ""
	for _, dns := range dnsServers {
		config += fmt.Sprintf("nameserver %s\n", dns)
	}

	cmd := exec.Command("sudo", "resolvconf", "-a", ifaceName)
	stdin, err := cmd.StdinPipe()
	if err != nil { return err }

	if err := cmd.Start(); err != nil { return err }

	_, err = stdin.Write([]byte(config))
	stdin.Close()
	if err != nil { return err }

	return cmd.Wait()
}

func overwriteResolvConf(dnsServers []string) error {
	logger.VPN("Using direct /etc/resolv.conf modification (last resort)")
	if _, err := os.Stat(resolvConfBackup); os.IsNotExist(err) {
		// Use cp for more reliable permission handling
		_ = exec.Command("sudo", "cp", resolvConfPath, resolvConfBackup).Run()
	}
	dnsConfig := "# Generated by Zarkham dVPN\n"
	for _, dns := range dnsServers {
		dnsConfig += fmt.Sprintf("nameserver %s\n", dns)
	}
	// Write to temp file first then mv to avoid permission issues with WriteFile
	tmpPath := "/tmp/resolv.conf.zarkham"
	_ = os.WriteFile(tmpPath, []byte(dnsConfig), 0644)
	return exec.Command("sudo", "mv", tmpPath, resolvConfPath).Run()
}

// TeardownWardenRouting cleans up Warden-specific routing
func TeardownWardenRouting(ifaceName, seekerIP string) {
	logger.VPN("Tearing down Warden routing for %s (Seeker: %s)", ifaceName, seekerIP)
	
	// Remove iptables rules for this specific Seeker
	_ = runCommand("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", seekerIP, "-j", "MASQUERADE")
	_ = runCommand("iptables", "-D", "FORWARD", "-s", seekerIP, "-j", "ACCEPT")
	
	// Delete interface
	_ = runCommand("ip", "link", "delete", ifaceName)
}

func restoreResolvConf() {
	if _, err := os.Stat(resolvConfBackup); err == nil {
		logger.VPN("Restoring original /etc/resolv.conf from backup")
		err := exec.Command("sudo", "cp", resolvConfBackup, resolvConfPath).Run()
		if err == nil {
			_ = exec.Command("sudo", "rm", resolvConfBackup).Run()
			logger.VPN("DNS restoration successful.")
		}
	}
}

func GetWardenGatewayIP(seekerIP net.IP) string {
	ip := seekerIP.To4()
	if ip == nil { return "" }
	gatewayIP := net.IPv4(ip[0], ip[1], ip[2], 1)
	return fmt.Sprintf("%s/24", gatewayIP.String())
}