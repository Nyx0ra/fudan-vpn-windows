package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type ConnectionSettings struct {
	TargetIP               string `json:"targetIP"`
	TunnelTLSCompatibility bool   `json:"tunnelTLSCompatibility"`
}

func (s ConnectionSettings) normalized() (ConnectionSettings, error) {
	ip := net.ParseIP(strings.TrimSpace(s.TargetIP))
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Equal(net.IPv4bcast) {
		return s, fmt.Errorf("请填写一个有效的校园目标 IPv4 单播地址（不是网段或域名）")
	}
	s.TargetIP = ip.To4().String()
	return s, nil
}
func (s ConnectionSettings) targetCIDR() string { return s.TargetIP + "/32" }
func settingsPath() string                      { return filepath.Join(ConfigDir(), "settings.json") }
func loadSettings(path string) (ConnectionSettings, error) {
	var s ConnectionSettings
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return s, err
	}
	if info.Size() > 8192 {
		return s, fmt.Errorf("连接设置超过大小限制")
	}
	dec := json.NewDecoder(io.LimitReader(f, 8193))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil {
		return s, fmt.Errorf("无法读取连接设置：%w", err)
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return s, fmt.Errorf("连接设置包含额外内容")
	}
	return s, nil
}
func saveSettings(path string, s ConnectionSettings) error {
	normalized, err := s.normalized()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func connectionArgs(s ConnectionSettings, rules string, reuse bool) ([]string, error) {
	s, err := s.normalized()
	if err != nil {
		return nil, err
	}
	args := []string{"-protocol", "atrust", "-server", "vpn.fudan.edu.cn", "-port", "443", "-auth-type", "auth/httpsOauth2", "-login-domain", "id.fudan.edu.cn", "-socks-bind", "127.0.0.1:1080", "-http-bind", "127.0.0.1:1081", "-router-bind", "127.0.0.1:1082", "-router-rules", rules, "-client-data-file", clientDataPath(), "-no-upstream", "-router-strict-cidr", s.targetCIDR()}
	if s.TunnelTLSCompatibility {
		args = append(args, "-fudan-tunnel-tls-compat")
	}
	if reuse {
		args = append(args, "-reuse-session")
	}
	return args, nil
}
func (a *App) GetConnectionSettings() (ConnectionSettings, error) {
	return loadSettings(settingsPath())
}
func (a *App) SaveConnectionSettings(s ConnectionSettings) error {
	if !a.loginMu.TryLock() {
		return fmt.Errorf("认证进行中，暂时不能修改连接设置")
	}
	defer a.loginMu.Unlock()
	a.engine.op.Lock()
	defer a.engine.op.Unlock()
	phase, _ := a.engine.Phase()
	if phase == PhaseLaunching || a.engine.Details()["canDisconnect"] == true {
		return fmt.Errorf("请先断开连接，再修改目标或 TLS 模式")
	}
	return saveSettings(settingsPath(), s)
}
func (a *App) validateConnectionSettings() error {
	if a.engine.Details()["canConnect"] != true {
		return fmt.Errorf("正在连接、客户端正在退出或端口被其他程序占用")
	}
	s, err := loadSettings(settingsPath())
	if err != nil {
		return err
	}
	_, err = s.normalized()
	return err
}
