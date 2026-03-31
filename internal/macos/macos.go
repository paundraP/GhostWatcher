package macos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type SystemProfile struct {
	Hostname          string
	OSVersion         string
	SerialNumber      string
	GatekeeperEnabled bool
	SIPEnabled        bool
}

type SignatureInfo struct {
	Signed            bool
	AppleSigned       bool
	SigningIdentifier string
	TeamID            string
	CDHash            string
	Detail            string
}

type ProcessMeta struct {
	PID  int
	Path string
}

func CollectSystemProfile() SystemProfile {
	hostname, _ := os.Hostname()

	profile := SystemProfile{
		Hostname:          hostname,
		OSVersion:         runtime.GOOS,
		SerialNumber:      "unknown",
		GatekeeperEnabled: false,
		SIPEnabled:        false,
	}

	if runtime.GOOS != "darwin" {
		return profile
	}

	if out, err := runCommand(3*time.Second, "sw_vers", "-productVersion"); err == nil && out != "" {
		profile.OSVersion = out
	}

	if out, err := runCommand(4*time.Second, "system_profiler", "SPHardwareDataType"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "Serial Number") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					profile.SerialNumber = strings.TrimSpace(parts[1])
				}
				break
			}
		}
	}

	if out, err := runCommand(2*time.Second, "spctl", "--status"); err == nil {
		profile.GatekeeperEnabled = strings.Contains(strings.ToLower(out), "assessments enabled")
	}

	if out, err := runCommand(2*time.Second, "csrutil", "status"); err == nil {
		profile.SIPEnabled = strings.Contains(strings.ToLower(out), "enabled")
	}

	return profile
}

func AnalyzeSignature(path string) SignatureInfo {
	if path == "" {
		return SignatureInfo{Detail: "empty path"}
	}

	if runtime.GOOS != "darwin" {
		return SignatureInfo{Detail: "codesign check is available only on macOS"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "codesign", "-dv", "--verbose=4", path)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))

	if err != nil {
		lower := strings.ToLower(text)
		if strings.Contains(lower, "not signed") || strings.Contains(lower, "code object is not signed") {
			return SignatureInfo{Signed: false, Detail: "binary is unsigned"}
		}
		if text == "" {
			text = err.Error()
		}
		return SignatureInfo{Signed: false, Detail: text}
	}

	info := SignatureInfo{Signed: true, Detail: "signature parsed"}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Identifier="):
			info.SigningIdentifier = strings.TrimPrefix(trimmed, "Identifier=")
		case strings.HasPrefix(trimmed, "TeamIdentifier="):
			teamID := strings.TrimPrefix(trimmed, "TeamIdentifier=")
			if !strings.EqualFold(teamID, "not set") {
				info.TeamID = teamID
			}
		case strings.HasPrefix(trimmed, "CDHash="):
			info.CDHash = strings.TrimPrefix(trimmed, "CDHash=")
		case strings.HasPrefix(trimmed, "Authority="):
			if strings.Contains(trimmed, "Apple") {
				info.AppleSigned = true
			}
		}
	}

	if info.SigningIdentifier == "" {
		info.SigningIdentifier = "unknown"
	}

	return info
}

func ListProcesses(limit int) ([]ProcessMeta, error) {
	out, err := runCommand(4*time.Second, "ps", "-axo", "pid=,comm=")
	if err != nil {
		return nil, err
	}

	processes := make([]ProcessMeta, 0, limit)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pid, convErr := strconv.Atoi(fields[0])
		if convErr != nil {
			continue
		}

		path := strings.TrimSpace(line[len(fields[0]):])
		if path == "" {
			continue
		}

		processes = append(processes, ProcessMeta{PID: pid, Path: path})
		if limit > 0 && len(processes) >= limit {
			break
		}
	}

	return processes, nil
}

func BundleID(path string) string {
	if runtime.GOOS != "darwin" || path == "" {
		return ""
	}

	out, err := runCommand(2*time.Second, "mdls", "-name", "kMDItemCFBundleIdentifier", "-raw", path)
	if err != nil {
		return ""
	}
	out = strings.TrimSpace(out)
	if out == "(null)" {
		return ""
	}
	return out
}

func FileSHA256(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func IsSandboxedPath(path string) bool {
	return strings.Contains(path, "/Containers/") || strings.Contains(path, "/AppTranslocation/")
}

func runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
