package network

import (
	"fmt"
	"net"
)

// GetAllIPs returns IPv4 addresses for every non-loopback, non-link-local interface.
func GetAllIPs() ([]string, error) {
	result := []string{}

	ifaces, err := net.Interfaces()
	if err != nil {
		return result, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return result, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			result = append(result, ip.To4().String())
		}
	}

	return result, nil
}

// GetIPByInterface returns the first routable IPv4 address for a named interface.
func GetIPByInterface(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip.To4().String(), nil
	}

	return "", fmt.Errorf("no non-loopback address found for interface %q", name)
}
