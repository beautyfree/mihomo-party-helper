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
	pfTokenPath      = "/var/run/party.mihomo.pf-token"
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
	mu          sync.Mutex
	paths       killSwitchPaths
	runPF       func(...string) (string, error)
	requireRoot bool
}

type killSwitchPaths struct {
	state  string
	anchor string
	config string
	token  string
}

func newKillSwitch() KillSwitch {
	return KillSwitch{
		paths: killSwitchPaths{
			state:  killSwitchState,
			anchor: killSwitchAnchor,
			config: pfConfigPath,
			token:  pfTokenPath,
		},
		requireRoot: true,
	}
}

func (k *KillSwitch) pfctl(args ...string) (string, error) {
	if k.runPF != nil {
		return k.runPF(args...)
	}
	return pfctl(args...)
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
	if _, err := os.Stat(k.paths.state); errors.Is(err, os.ErrNotExist) {
		return KillSwitchStatus{}
	} else if err != nil {
		return KillSwitchStatus{Error: err.Error()}
	}
	status := KillSwitchStatus{Enabled: true}
	info, err := k.pfctl("-s", "info")
	if err != nil {
		status.Error = err.Error()
		return status
	}
	rules, err := k.pfctl("-a", pfAnchorName, "-sr")
	if err != nil {
		status.Error = err.Error()
		return status
	}
	mainRules, err := k.pfctl("-sr")
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
		if strings.HasPrefix(trimmed, "anchor ") || strings.HasPrefix(trimmed, "block ") || strings.HasPrefix(trimmed, "pass ") {
			if trimmed != pfAnchorLine && trimmed != `anchor "com.apple/*"` {
				return "", fmt.Errorf("Kill Switch cannot safely share PF with this filter rule: %s", trimmed)
			}
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
	config, err := os.ReadFile(k.paths.config)
	if err != nil {
		return err
	}
	updated, err := addPFAnchor(string(config), k.paths.anchor)
	if err != nil {
		return err
	}
	if updated == string(config) {
		rules, err := k.pfctl("-sr")
		if err != nil {
			return err
		}
		if anchorIsFirstFilterRule(rules) {
			return nil
		}
		_, err = k.pfctl("-f", k.paths.config)
		return err
	}
	if err := writeRootFile(k.paths.config+".party-mihomo.backup", config, 0600); err != nil {
		return err
	}
	if err := writeRootFile(k.paths.config, []byte(updated), 0644); err != nil {
		return err
	}
	if _, err := k.pfctl("-n", "-f", k.paths.config); err != nil {
		_ = writeRootFile(k.paths.config, config, 0644)
		return err
	}
	if _, err := k.pfctl("-f", k.paths.config); err != nil {
		_ = writeRootFile(k.paths.config, config, 0644)
		return err
	}
	return nil
}

func (k *KillSwitch) loadRules(rules string) error {
	if err := writeRootFile(k.paths.anchor, []byte(rules), 0600); err != nil {
		return err
	}
	if _, err := k.pfctl("-n", "-a", pfAnchorName, "-f", k.paths.anchor); err != nil {
		return err
	}
	_, err := k.pfctl("-a", pfAnchorName, "-f", k.paths.anchor)
	return err
}

func (k *KillSwitch) enablePF() error {
	output, err := k.pfctl("-E")
	if err != nil {
		return err
	}
	match := pfTokenPattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return errors.New("pfctl did not return an enable token")
	}
	oldToken, _ := os.ReadFile(k.paths.token)
	if err := writeRootFile(k.paths.token, []byte(match[1]), 0600); err != nil {
		return err
	}
	if previous := strings.TrimSpace(string(oldToken)); previous != "" && previous != match[1] {
		_, _ = k.pfctl("-X", previous)
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
	if _, err := os.Stat(k.paths.state); err != nil {
		return ErrKillSwitchDisabled
	}
	return k.enableLocked(request)
}

func (k *KillSwitch) enableLocked(request KillSwitchRules) error {
	if k.requireRoot && os.Geteuid() != 0 {
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
	previous, _ := os.ReadFile(k.paths.state)
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
	if err := writeRootFile(k.paths.state, state, 0600); err != nil {
		return err
	}
	if err := k.enablePF(); err != nil {
		return err
	}
	// Existing PF states must not bypass a newly enabled block.
	if _, err := k.pfctl("-k", "0.0.0.0/0", "-k", "0.0.0.0/0"); err != nil {
		return err
	}
	if _, err := k.pfctl("-k", "::/0", "-k", "::/0"); err != nil {
		return err
	}
	return k.loadRules(rules)
}

func (k *KillSwitch) Restore() error {
	state, err := os.ReadFile(k.paths.state)
	if errors.Is(err, os.ErrNotExist) {
		if _, anchorErr := os.Stat(k.paths.anchor); anchorErr == nil {
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
	if k.requireRoot && os.Geteuid() != 0 {
		return errors.New("kill switch requires the root helper")
	}
	if err := os.Remove(k.paths.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := k.loadRules(""); err != nil {
		return err
	}
	token, _ := os.ReadFile(k.paths.token)
	if value := strings.TrimSpace(string(token)); value != "" {
		if _, err := k.pfctl("-X", value); err != nil {
			return err
		}
	}
	if err := os.Remove(k.paths.token); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
