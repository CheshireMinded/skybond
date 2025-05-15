package server

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func SetupStarlinkDHCP() {
	interfaces := detectStarlinkInterfaces()
	if len(interfaces) == 0 {
		fmt.Println("No Starlink interfaces found.")
		return
	}

	var dnsmasqEntries []string
	baseIP := "192.168.100."
	counter := 1

	for _, iface := range interfaces {
		if hasIPAssigned(iface) {
			fmt.Printf("[✓] Interface %s already has IP assigned. Skipping.\n", iface)
			continue
		}

		subnetIP := fmt.Sprintf("%s%d", baseIP, counter)
		err := assignStaticIP(iface, subnetIP)
		if err != nil {
			fmt.Printf("[!] Failed to assign IP to %s: %v\n", iface, err)
			continue
		}

		entry := fmt.Sprintf(`interface=%s\ndhcp-range=%s,%s,255.255.255.252,1h\ndhcp-option=3,%s`, iface, subnetIP, subnetIP, subnetIP)
		dnsmasqEntries = append(dnsmasqEntries, entry)
		counter += 4 // move to next /30 range
	}

	if len(dnsmasqEntries) > 0 {
		writeDnsmasqConfig(dnsmasqEntries)
		exec.Command("systemctl", "restart", "dnsmasq").Run()
		fmt.Println("[+] DHCP config applied and dnsmasq restarted.")
	} else {
		fmt.Println("[!] No dnsmasq updates were required.")
	}
}

func detectStarlinkInterfaces() []string {
	var results []string
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "eth") || strings.Contains(iface.Name, "star") {
			results = append(results, iface.Name)
		}
	}
	return results
}

func hasIPAssigned(iface string) bool {
	out, err := exec.Command("ip", "addr", "show", iface).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "inet ")
}

func assignStaticIP(iface, ip string) error {
	exec.Command("ip", "link", "set", iface, "up").Run()
	cmd := exec.Command("ip", "addr", "add", ip+"/30", "dev", iface)
	return cmd.Run()
}

func writeDnsmasqConfig(lines []string) {
	data := strings.Join(lines, "\n\n") + "\n"
	err := os.WriteFile("/etc/dnsmasq.d/starlink.conf", []byte(data), 0644)
	if err != nil {
		fmt.Println("[!] Failed to write dnsmasq config:", err)
	}
}
