package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakePF struct {
	configPath string
	anchorPath string
	mainRules  string
	anchor     string
	tokens     map[string]bool
	nextToken  int
	kills      int
	failKill   bool
}

func (f *fakePF) run(args ...string) (string, error) {
	command := strings.Join(args, " ")
	switch {
	case command == "-s info":
		if len(f.tokens) > 0 {
			return "Status: Enabled\n", nil
		}
		return "Status: Disabled\n", nil
	case command == "-sr":
		return f.mainRules, nil
	case command == "-a "+pfAnchorName+" -sr":
		return f.anchor, nil
	case command == "-a "+pfAnchorName+" -f "+f.anchorPath:
		data, err := os.ReadFile(f.anchorPath)
		f.anchor = string(data)
		return "", err
	case command == "-f "+f.configPath:
		data, err := os.ReadFile(f.configPath)
		f.mainRules = string(data)
		return "", err
	case command == "-E":
		f.nextToken++
		token := fmt.Sprint(f.nextToken)
		f.tokens[token] = true
		return "Token : " + token + "\n", nil
	case strings.HasPrefix(command, "-X "):
		delete(f.tokens, strings.TrimPrefix(command, "-X "))
		return "", nil
	case strings.HasPrefix(command, "-k "):
		if f.failKill {
			return "", errors.New("state purge failed")
		}
		f.kills++
		return "", nil
	case strings.HasPrefix(command, "-n "):
		return "", nil
	default:
		return "", fmt.Errorf("unexpected PF command: %s", command)
	}
}

func makeTestKillSwitch(t *testing.T, config string) (*KillSwitch, *fakePF) {
	t.Helper()
	dir := t.TempDir()
	paths := killSwitchPaths{
		state:  filepath.Join(dir, "db", "kill-switch.json"),
		anchor: filepath.Join(dir, "etc", "pf.anchors", "party.mihomo.killswitch"),
		config: filepath.Join(dir, "etc", "pf.conf"),
		token:  filepath.Join(dir, "run", "pf-token"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.config), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.config, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakePF{configPath: paths.config, anchorPath: paths.anchor, tokens: make(map[string]bool)}
	return &KillSwitch{paths: paths, runPF: f.run}, f
}

func TestKillSwitchPersistsAcrossRestartAndStopsOnManualDisable(t *testing.T) {
	k, pf := makeTestKillSwitch(t, "scrub-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n")
	request := KillSwitchRules{Tunnel: "utun1500", Endpoints: []KillSwitchEndpoint{{IP: "203.0.113.5", Port: 8443, Protocol: "tcp"}}}
	if err := k.Enable(request); err != nil {
		t.Fatal(err)
	}
	if !k.Status().Healthy || pf.kills != 2 {
		t.Fatal("enable did not install the block and clear existing IPv4/IPv6 states")
	}
	if _, err := os.Stat(k.paths.state); err != nil {
		t.Fatal("user intent was not persisted:", err)
	}
	restarted := &KillSwitch{paths: k.paths, runPF: pf.run}
	if err := restarted.Restore(); err != nil || pf.kills != 2 {
		t.Fatalf("an unchanged restore must preserve existing connections: %v", err)
	}
	if err := k.Refresh(KillSwitchRules{Tunnel: "utun1500", Endpoints: []KillSwitchEndpoint{{IP: "203.0.113.6", Port: 8443, Protocol: "tcp"}}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pf.anchor, "203.0.113.5") || !strings.Contains(pf.anchor, "203.0.113.6") {
		t.Fatal("refresh did not replace the endpoint allowlist")
	}
	if err := k.Disable(); err != nil {
		t.Fatal(err)
	}
	if k.Status().Enabled || len(pf.tokens) != 0 || pf.anchor != "" {
		t.Fatal("manual disable did not release the block")
	}
	if err := k.Refresh(request); !errors.Is(err, ErrKillSwitchDisabled) {
		t.Fatalf("background refresh re-enabled a manually disabled switch: %v", err)
	}
}

func TestKillSwitchRefusesCompetingPFAnchor(t *testing.T) {
	config := "anchor \"another-kill-switch\" quick\nanchor \"com.apple/*\"\n"
	k, pf := makeTestKillSwitch(t, config)
	err := k.Enable(KillSwitchRules{Tunnel: "utun1500", Endpoints: []KillSwitchEndpoint{{IP: "203.0.113.5", Port: 8443, Protocol: "tcp"}}})
	if err == nil {
		t.Fatal("competing PF anchor was accepted")
	}
	updated, readErr := os.ReadFile(k.paths.config)
	if readErr != nil || string(updated) != config || len(pf.tokens) != 0 {
		t.Fatal("conflict changed the system PF configuration")
	}
	if _, statErr := os.Stat(k.paths.state); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("conflict persisted a false enabled state")
	}
}

func TestKillSwitchFailureStaysBlockedUntilRestore(t *testing.T) {
	k, pf := makeTestKillSwitch(t, "anchor \"com.apple/*\"\n")
	request := KillSwitchRules{Tunnel: "utun1500", Endpoints: []KillSwitchEndpoint{{IP: "203.0.113.5", Port: 8443, Protocol: "tcp"}}}
	pf.failKill = true
	if err := k.Enable(request); err == nil {
		t.Fatal("state purge failure was ignored")
	}
	if pf.anchor != "block drop out quick all\n" || k.Status().Healthy {
		t.Fatal("partial enable opened an endpoint before old states were purged")
	}
	pf.failKill = false
	restarted := &KillSwitch{paths: k.paths, runPF: pf.run}
	if err := restarted.Restore(); err != nil || !restarted.Status().Healthy {
		t.Fatalf("persistent intent did not restore the protected state: %v", err)
	}
}
