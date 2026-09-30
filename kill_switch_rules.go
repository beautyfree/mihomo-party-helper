package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// KillSwitchEndpoint is a single transport address used by the proxy core.
// Hostnames must be resolved before the rules are installed: resolving through
// an unavailable tunnel must never open a general DNS exception.
type KillSwitchEndpoint struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type KillSwitchRules struct {
	Tunnel    string               `json:"tunnel"`
	Endpoints []KillSwitchEndpoint `json:"endpoints"`
}

var tunnelNamePattern = regexp.MustCompile(`^utun[0-9]{1,5}$`)

func renderKillSwitchRules(request KillSwitchRules) (string, error) {
	if !tunnelNamePattern.MatchString(request.Tunnel) {
		return "", errors.New("tunnel must name a utun interface")
	}
	if len(request.Endpoints) == 0 || len(request.Endpoints) > 256 {
		return "", errors.New("one to 256 proxy endpoints are required")
	}

	lines := []string{
		"# Clash Party Kill Switch. Managed by party.mihomo.helper.",
		"pass quick on lo0 all keep state (if-bound)",
		fmt.Sprintf("pass out quick on %s all keep state (if-bound)", request.Tunnel),
	}
	seen := make(map[string]struct{}, len(request.Endpoints))
	for _, endpoint := range request.Endpoints {
		ip := net.ParseIP(endpoint.IP)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || endpoint.Port < 1 || endpoint.Port > 65535 {
			return "", errors.New("invalid proxy endpoint")
		}
		if endpoint.Protocol != "tcp" && endpoint.Protocol != "udp" {
			return "", errors.New("proxy endpoint protocol must be tcp or udp")
		}
		family := "inet6"
		if ip.To4() != nil {
			family = "inet"
		}
		line := fmt.Sprintf("pass out quick %s proto %s from any to %s port %d user = 0 keep state (if-bound)", family, endpoint.Protocol, ip.String(), endpoint.Port)
		seen[line] = struct{}{}
	}
	endpointLines := make([]string, 0, len(seen))
	for line := range seen {
		endpointLines = append(endpointLines, line)
	}
	sort.Strings(endpointLines)
	lines = append(lines, endpointLines...)
	lines = append(lines, "block drop out quick all", "")
	return strings.Join(lines, "\n"), nil
}
