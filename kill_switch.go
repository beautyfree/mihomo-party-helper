package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const (
	killSwitchDir    = "/var/db/party.mihomo"
	killSwitchState  = killSwitchDir + "/kill-switch.json"
	killSwitchAnchor = "/etc/pf.anchors/party.mihomo.killswitch"
	pfConfigPath     = "/etc/pf.conf"
	pfAnchorName     = "party.mihomo.killswitch"
	pfAnchorLine     = `anchor "party.mihomo.killswitch" quick`
)

func pfLoadLine(anchorPath string) string {
	return fmt.Sprintf(`load anchor "%s" from "%s"`, pfAnchorName, anchorPath)
}

var pfTokenPattern = regexp.MustCompile(`(?m)^Token : ([0-9]+)$`)
var ErrKillSwitchDisabled = errors.New("Kill Switch is not enabled")

// The daemon owns this state. The Electron process can die without clearing it.
type KillSwitch struct {
	mu sync.Mutex
}

type KillSwitchStatus struct {
	Enabled bool   `json:"enabled"`
	Healthy bool   `json:"healthy"`
	Error   string `json:"error,omitempty"`
}

func (k *KillSwitch) Status() KillSwitchStatus {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.statusLocked()
}

func (k *KillSwitch) statusLocked() KillSwitchStatus {
	if _, err := os.Stat(killSwitchState); errors.Is(err, os.ErrNotExist) {
		return KillSwitchStatus{}
	} else if err != nil {
		return KillSwitchStatus{Error: err.Error()}
	}
	status := KillSwitchStatus{Enabled: true}
	info, err := pfctl("-s", "info")
	if err != nil {
		status.Error = err.Error()
		return status
	}
	rules, err := pfctl("-a", pfAnchorName, "-sr")
	if err != nil {
		status.Error = err.Error()
		return status
	}
	mainRules, err := pfctl("-sr")
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Healthy = strings.Contains(info, "Status: Enabled") &&
		anchorIsFirstFilterRule(mainRules) &&
		strings.Contains(rules, "pass out quick on utun") &&
		strings.Contains(rules, "user = 0") &&
		strings.Contains(rules, "block drop out quick all")
	if !status.Healthy {
		status.Error = "PF is disabled or Kill Switch rules are missing"
	}
	return status
}

func pfctl(args ...string) (string, error) {
	output, err := exec.Command("/sbin/pfctl", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pfctl %v: %w: %s", args, err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func writeRootFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".party-mihomo-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func addPFAnchor(config, anchorPath string) (string, error) {
	lines := strings.Split(config, "\n")
	firstFilter := -1
	installed := -1
	loadInstalled := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == pfAnchorLine {
			installed = index
		}
		if trimmed == pfLoadLine(anchorPath) {
			loadInstalled = true
		}
		if firstFilter < 0 && (strings.HasPrefix(trimmed, "anchor ") || strings.HasPrefix(trimmed, "block ") || strings.HasPrefix(trimmed, "pass ")) {
			firstFilter = index
		}
	}
	if installed >= 0 {
		if installed != firstFilter {
			return "", errors.New("Kill Switch anchor is not the first PF filter rule")
		}
		if loadInstalled {
			return config, nil
		}
		return strings.TrimRight(config, "\n") + "\n" + pfLoadLine(anchorPath) + "\n", nil
	}
	if firstFilter >= 0 {
		trimmed := strings.TrimSpace(lines[firstFilter])
		// Another quick anchor may be a separate kill switch. Installing ours
		// ahead of it could silently disable that product's protection.
		if strings.HasPrefix(trimmed, "anchor ") && strings.Contains(trimmed, " quick") {
			return "", fmt.Errorf("another quick PF anchor is installed: %s", trimmed)
		}
		lines = append(lines[:firstFilter], append([]string{pfAnchorLine}, lines[firstFilter:]...)...)
		return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n" + pfLoadLine(anchorPath) + "\n", nil
	}
	return strings.TrimRight(config, "\n") + "\n" + pfAnchorLine + "\n" + pfLoadLine(anchorPath) + "\n", nil
}

func anchorIsFirstFilterRule(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "anchor ") || strings.HasPrefix(trimmed, "block ") || strings.HasPrefix(trimmed, "pass ") {
			return strings.Contains(trimmed, `"`+pfAnchorName+`"`) && strings.Contains(trimmed, "quick")
		}
	}
	return false
}

func (k *KillSwitch) ensurePFAnchor() error {
	config, err := os.ReadFile(pfConfigPath)
	if err != nil {
		return err
	}
	updated, err := addPFAnchor(string(config), killSwitchAnchor)
	if err != nil {
		return err
	}
	if updated == string(config) {
		rules, err := pfctl("-sr")
		if err != nil {
			return err
		}
		if anchorIsFirstFilterRule(rules) {
			return nil
		}
		_, err = pfctl("-f", pfConfigPath)
		return err
	}
	if err := writeRootFile(pfConfigPath+".party-mihomo.backup", config, 0600); err != nil {
		return err
	}
	if err := writeRootFile(pfConfigPath, []byte(updated), 0644); err != nil {
		return err
	}
	if _, err := pfctl("-n", "-f", pfConfigPath); err != nil {
		_ = writeRootFile(pfConfigPath, config, 0644)
		return err
	}
	if _, err := pfctl("-f", pfConfigPath); err != nil {
		_ = writeRootFile(pfConfigPath, config, 0644)
		return err
	}
	return nil
}

func (k *KillSwitch) loadRules(rules string) error {
	if err := writeRootFile(killSwitchAnchor, []byte(rules), 0600); err != nil {
		return err
	}
	if _, err := pfctl("-n", "-a", pfAnchorName, "-f", killSwitchAnchor); err != nil {
		return err
	}
	_, err := pfctl("-a", pfAnchorName, "-f", killSwitchAnchor)
	return err
}

func (k *KillSwitch) enablePF() error {
	output, err := pfctl("-E")
	if err != nil {
		return err
	}
	match := pfTokenPattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return errors.New("pfctl did not return an enable token")
	}
	oldToken, _ := os.ReadFile(killSwitchDir + "/pf-token")
	if err := writeRootFile(killSwitchDir+"/pf-token", []byte(match[1]), 0600); err != nil {
		return err
	}
	if previous := strings.TrimSpace(string(oldToken)); previous != "" && previous != match[1] {
		_, _ = pfctl("-X", previous)
	}
	return nil
}

func (k *KillSwitch) Enable(request KillSwitchRules) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.enableLocked(request)
}

func (k *KillSwitch) Refresh(request KillSwitchRules) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, err := os.Stat(killSwitchState); err != nil {
		return ErrKillSwitchDisabled
	}
	return k.enableLocked(request)
}

func (k *KillSwitch) enableLocked(request KillSwitchRules) error {
	if os.Geteuid() != 0 {
		return errors.New("kill switch requires the root helper")
	}
	rules, err := renderKillSwitchRules(request)
	if err != nil {
		return err
	}
	state, err := json.Marshal(request)
	if err != nil {
		return err
	}
	previous, _ := os.ReadFile(killSwitchState)
	if string(previous) == string(state) && k.statusLocked().Healthy {
		return nil
	}
	// Install the block first. Every later failure leaves traffic blocked.
	if err := k.loadRules("block drop out quick all\n"); err != nil {
		return err
	}
	if err := k.ensurePFAnchor(); err != nil {
		return err
	}
	if err := writeRootFile(killSwitchState, state, 0600); err != nil {
		return err
	}
	if err := k.enablePF(); err != nil {
		return err
	}
	// Existing PF states must not bypass a newly enabled block.
	if _, err := pfctl("-k", "0.0.0.0/0", "-k", "0.0.0.0/0"); err != nil {
		return err
	}
	if _, err := pfctl("-k", "::/0", "-k", "::/0"); err != nil {
		return err
	}
	return k.loadRules(rules)
}

func (k *KillSwitch) Restore() error {
	state, err := os.ReadFile(killSwitchState)
	if errors.Is(err, os.ErrNotExist) {
		if _, anchorErr := os.Stat(killSwitchAnchor); anchorErr == nil {
			return k.Disable()
		}
		return nil
	}
	if err != nil {
		return err
	}
	var request KillSwitchRules
	if err := json.Unmarshal(state, &request); err != nil {
		return err
	}
	return k.Enable(request)
}

func (k *KillSwitch) Disable() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if os.Geteuid() != 0 {
		return errors.New("kill switch requires the root helper")
	}
	if err := os.Remove(killSwitchState); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := k.loadRules(""); err != nil {
		return err
	}
	token, _ := os.ReadFile(killSwitchDir + "/pf-token")
	if value := strings.TrimSpace(string(token)); value != "" {
		if _, err := pfctl("-X", value); err != nil {
			return err
		}
	}
	if err := os.Remove(killSwitchDir + "/pf-token"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
