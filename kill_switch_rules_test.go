package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderKillSwitchRules(t *testing.T) {
	rules, err := renderKillSwitchRules(KillSwitchRules{
		Tunnel: "utun1500",
		Endpoints: []KillSwitchEndpoint{
			{IP: "203.0.113.5", Port: 8443, Protocol: "tcp"},
			{IP: "203.0.113.5", Port: 8443, Protocol: "tcp"},
			{IP: "2001:db8::5", Port: 443, Protocol: "udp"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(rules, "203.0.113.5") != 1 || !strings.Contains(rules, "on utun1500") || !strings.HasSuffix(rules, "block drop out quick all\n") {
		t.Fatalf("unexpected rules:\n%s", rules)
	}
	if strings.Contains(rules, "pass out quick all user = 0") {
		t.Fatal("root must not have unrestricted physical access")
	}
}

func TestRenderKillSwitchRulesRejectsInvalidInput(t *testing.T) {
	for _, request := range []KillSwitchRules{
		{Tunnel: "en0", Endpoints: []KillSwitchEndpoint{{IP: "203.0.113.5", Port: 443, Protocol: "tcp"}}},
		{Tunnel: "utun0", Endpoints: []KillSwitchEndpoint{{IP: "0.0.0.0", Port: 443, Protocol: "tcp"}}},
		{Tunnel: "utun0", Endpoints: []KillSwitchEndpoint{{IP: "203.0.113.5", Port: 0, Protocol: "tcp"}}},
		{Tunnel: "utun0", Endpoints: []KillSwitchEndpoint{{IP: "203.0.113.5", Port: 443, Protocol: "any"}}},
		{Tunnel: "utun0"},
	} {
		if _, err := renderKillSwitchRules(request); err == nil {
			t.Fatalf("accepted unsafe request: %+v", request)
		}
	}
}

func TestAddPFAnchorBeforeOtherFilterRules(t *testing.T) {
	config := "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n"
	updated, err := addPFAnchor(config, "/tmp/test-anchor.conf")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(updated, "\n"+pfAnchorLine) > strings.Index(updated, "\n"+`anchor "com.apple/*"`) {
		t.Fatal("Kill Switch anchor must precede other filter anchors")
	}
	again, err := addPFAnchor(updated, "/tmp/test-anchor.conf")
	if err != nil || again != updated {
		t.Fatalf("anchor insertion is not idempotent: %v", err)
	}
	if _, err := addPFAnchor("anchor \"another-kill-switch\" quick\nanchor \"com.apple/*\"\n", "/tmp/test-anchor.conf"); err == nil {
		t.Fatal("competing quick anchor was accepted")
	}
	if _, err := addPFAnchor("pass out quick all\n"+pfAnchorLine+"\n", "/tmp/test-anchor.conf"); err == nil {
		t.Fatal("a pass rule preceding the Kill Switch anchor was accepted")
	}
	if anchorIsFirstFilterRule("pass out quick all\n" + pfAnchorLine) {
		t.Fatal("an ineffective runtime anchor was reported healthy")
	}
	if !anchorIsFirstFilterRule(pfAnchorLine + "\nanchor \"com.apple/*\"\n") {
		t.Fatal("the first quick Kill Switch anchor was not recognized")
	}
}

func TestKillSwitchRulesParseOnMacOS(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("PF syntax check requires macOS")
	}
	rules, err := renderKillSwitchRules(KillSwitchRules{
		Tunnel: "utun1500",
		Endpoints: []KillSwitchEndpoint{
			{IP: "203.0.113.5", Port: 8443, Protocol: "tcp"},
			{IP: "2001:db8::5", Port: 443, Protocol: "udp"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "anchor.conf")
	if err := os.WriteFile(file, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("/sbin/pfctl", "-n", "-a", pfAnchorName, "-f", file).CombinedOutput()
	if err != nil {
		t.Fatalf("PF rejected rules: %v\n%s", err, output)
	}
	config, err := addPFAnchor("scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\nrdr-anchor \"com.apple/*\"\ndummynet-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n", file)
	if err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(t.TempDir(), "pf.conf")
	if err := os.WriteFile(mainFile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	output, err = exec.Command("/sbin/pfctl", "-n", "-f", mainFile).CombinedOutput()
	if err != nil {
		t.Fatalf("PF rejected main anchor registration: %v\n%s", err, output)
	}
}
