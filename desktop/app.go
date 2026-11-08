package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mythologyli/zju-connect/router"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// 复旦统一身份认证的授权入口。
//
// redirect_uri 必须和 aTrust 服务端下发的逐字一致，服务端会校验 sfDomain，
// 改一个字符 code 就换不回会话。
const (
	authHost  = "id.fudan.edu.cn"
	authPath  = "/idp/authCenter/authenticate"
	callHost  = "vpn.fudan.edu.cn"
	callPath  = "/passport/v1/auth/httpsOauth2"
	rulePath  = "sfDomain=id.fudan.edu.cn"
	maxLogLen = 800
)

// LoginURL 是点「登录」时用系统浏览器打开的那个地址。
func LoginURL() string {
	q := url.Values{}
	q.Set("client_id", "vpn")
	q.Set("redirect_uri", "https://"+callHost+callPath+"?"+rulePath)
	q.Set("response_type", "code")

	u := url.URL{Scheme: "https", Host: authHost, Path: authPath, RawQuery: q.Encode()}
	return u.String()
}

// ExtractCode 从登录完成后地址栏里那条 URL 取出授权码。
//
// 用户把整条 URL 粘进来就行，多余的参数、前后空格都容忍。
func ExtractCode(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("没有粘贴内容")
	}
	// 有人会连 "code=" 一起复制，或者粘过来的是一段带引号的文本
	raw = strings.Trim(raw, "\"'<> ")

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// 退一步：直接在整段文本里找 code=
		if i := strings.Index(raw, "code="); i >= 0 {
			rest := raw[i+len("code="):]
			if j := strings.IndexAny(rest, "&# "); j >= 0 {
				rest = rest[:j]
			}
			if rest != "" {
				return rest, nil
			}
		}
		return "", fmt.Errorf("这不是一条完整的网址，需要包含 %s", callPath)
	}

	if !strings.EqualFold(u.Host, callHost) || !strings.Contains(u.Path, callPath) {
		return "", fmt.Errorf("这条网址不是登录回调，需要是 %s 开头", "https://"+callHost+callPath)
	}
	code := u.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("网址里没有 code 参数")
	}
	return code, nil
}

// App 是绑定给前端的对象，方法名就是前端能调的 API。
type App struct {
	ctx         context.Context
	engine      *Engine
	loginMu     sync.Mutex
	loginCtx    context.Context
	cancelLogin context.CancelFunc

	mu            sync.Mutex
	logs          []string
	tray          desktopTray
	exiting       bool
	logsRequested bool
}

func NewApp() *App {
	a := &App{engine: NewEngine()}
	a.engine.onLog = func(line string) {
		a.appendLog(line)
		wailsruntime.EventsEmit(a.ctx, "log", line)
	}
	a.engine.onPhase = func(p Phase, msg string) {
		a.appendLog("状态：" + string(p) + " · " + safeLog(msg))
		wailsruntime.EventsEmit(a.ctx, "phase", map[string]string{
			"phase": string(p),
			"error": msg,
		})
	}
	return a
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.loginCtx, a.cancelLogin = context.WithCancel(ctx)
	ensureRulesFile()
	a.appendLog("桌面客户端已启动；托盘健康状态不等于实验室服务可达性")
	a.engine.Monitor(a.loginCtx)
	tray, err := startDesktopTray(a)
	if err != nil {
		a.appendLog("托盘初始化失败，关闭窗口将退出：" + err.Error())
	} else {
		a.tray = tray
	}
}

func (a *App) shutdown(ctx context.Context) {
	if a.cancelLogin != nil {
		a.cancelLogin()
	}
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	a.engine.Close()
	if a.tray != nil {
		a.tray.Close()
	}
}

func (a *App) appendLog(line string) {
	line = safeLog(line)
	a.mu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > maxLogLen {
		a.logs = a.logs[len(a.logs)-maxLogLen:]
	}
	_ = os.MkdirAll(ConfigDir(), 0700)
	if st, err := os.Stat(logFile()); err == nil && st.Size() > 2*1024*1024 {
		_ = os.WriteFile(logFile(), nil, 0600)
	}
	if f, err := os.OpenFile(logFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
		_, _ = f.WriteString(line + "\n")
		_ = f.Close()
	}
	a.mu.Unlock()
}

// ---------------------------------------------------------------- 前端 API

// LoginURL 返回登录页地址，前端拿它显示成按钮。
func (a *App) LoginURL() string { return LoginURL() }

// OpenLogin 在 Windows 使用独立认证窗口，在其他平台保留原登录入口。
func (a *App) OpenLogin() error {
	if err := a.validateConnectionSettings(); err != nil {
		return err
	}
	if !a.loginMu.TryLock() {
		return nil
	}
	defer a.loginMu.Unlock()
	a.engine.setPhase(PhaseLaunching, "等待本机学校认证")
	if callback, handled, err := platformLogin(a.loginCtx); handled {
		if err != nil || callback == "" {
			a.engine.setPhase(PhaseFailed, "认证未完成，请重新打开登录页")
			return err
		}
		if err := a.loginCtx.Err(); err != nil {
			return err
		}
		return a.connect("", callback)
	}
	wailsruntime.BrowserOpenURL(a.ctx, LoginURL())
	a.appendLog("已在浏览器打开登录页，扫码后把地址栏那条网址复制回来")
	wailsruntime.EventsEmit(a.ctx, "log", "已在浏览器打开登录页，扫码后把地址栏那条网址复制回来")
	return nil
}

// Reconnect prefers the saved session. Login is interactive only when necessary.
func (a *App) Reconnect() error {
	if err := a.validateConnectionSettings(); err != nil {
		return err
	}
	if a.engine.Details()["needsLogin"] == true {
		return a.OpenLogin()
	}
	if _, err := os.Stat(clientDataPath()); err != nil {
		return a.OpenLogin()
	}
	if err := ensureRulesFile(); err != nil {
		return err
	}
	return a.engine.StartSaved(RulesPath())
}
func (a *App) Show() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowShow(a.ctx)
	wailsruntime.WindowUnminimise(a.ctx)
	wailsruntime.WindowSetAlwaysOnTop(a.ctx, true)
	wailsruntime.WindowSetAlwaysOnTop(a.ctx, false)
}
func (a *App) ViewLogs() error {
	a.mu.Lock()
	a.logsRequested = true
	a.mu.Unlock()
	a.Show()
	wailsruntime.EventsEmit(a.ctx, "show-logs")
	return nil
}
func (a *App) Exit() {
	if !a.engine.Close() {
		a.Show()
		return
	}
	a.mu.Lock()
	a.exiting = true
	a.mu.Unlock()
	if a.cancelLogin != nil {
		a.cancelLogin()
	}
	wailsruntime.Quit(a.ctx)
}
func (a *App) beforeClose(ctx context.Context) bool {
	a.mu.Lock()
	exit := a.exiting
	a.mu.Unlock()
	if exit {
		return false
	}
	if a.tray == nil {
		return !a.engine.Close()
	}
	notice := filepath.Join(ConfigDir(), "tray-close-notice")
	if _, err := os.Stat(notice); err != nil {
		a.tray.Notify()
		_ = os.WriteFile(notice, []byte("关闭窗口仅隐藏；使用托盘菜单退出。"), 0600)
	}
	wailsruntime.WindowHide(ctx)
	return true
}

// Connect 用回调 URL 里的授权码起隧道。
func (a *App) Connect(callbackURL string) error {
	code, err := ExtractCode(callbackURL)
	if err != nil {
		return err
	}
	return a.connect(code, "")
}

func (a *App) connect(code, callback string) error {
	if err := ensureRulesFile(); err != nil {
		return err
	}
	return a.engine.Start(code, callback, RulesPath())
}

func (a *App) AutomaticLogin() bool { return automaticPlatformLogin }

// Disconnect 断开隧道。
func (a *App) Disconnect() {
	a.engine.Disconnect()
}

// Status 给前端一次拿全状态。
func (a *App) Status() map[string]any {
	phase, msg := a.engine.Phase()
	since := a.engine.ConnectedSince()
	var sinceUnix int64
	if !since.IsZero() {
		sinceUnix = since.Unix()
	}
	status := map[string]any{
		"phase":     string(phase),
		"error":     msg,
		"since":     sinceUnix,
		"splitPort": "1082",
		"rulesPath": RulesPath(),
	}
	a.mu.Lock()
	status["showLogs"] = a.logsRequested
	a.logsRequested = false
	a.mu.Unlock()
	for k, v := range a.engine.Details() {
		status[k] = v
	}
	return status
}

// Logs 返回历史日志（前端首次加载时补一次）。
func (a *App) Logs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if lines, err := readSavedLogs(logFile()); err == nil {
		return lines
	}
	out := make([]string, len(a.logs))
	copy(out, a.logs)
	return out
}

// ReadRules 读规则文件内容。
func (a *App) ReadRules() (string, error) {
	if err := ensureRulesFile(); err != nil {
		return "", err
	}
	data, err := os.ReadFile(RulesPath())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SaveRules 写回规则文件，写完立刻校验一遍，写错了当场报行号。
func (a *App) SaveRules(text string) error {
	if _, err := router.Parse(strings.NewReader(text)); err != nil {
		return err
	}
	return os.WriteFile(RulesPath(), []byte(text), 0o644)
}

// ValidateRules 只校验不保存，前端做实时提示用。
func (a *App) ValidateRules(text string) (int, error) {
	rt, err := router.Parse(strings.NewReader(text))
	if err != nil {
		return 0, err
	}
	return rt.Len(), nil
}

// OpenRules 用系统默认编辑器打开规则文件。
func (a *App) OpenRules() error {
	if err := ensureRulesFile(); err != nil {
		return err
	}
	return openWithDefaultApp(RulesPath())
}

// RevealRules 在文件管理器里定位规则文件。
func (a *App) RevealRules() error {
	if err := ensureRulesFile(); err != nil {
		return err
	}
	wailsruntime.BrowserOpenURL(a.ctx, "file://"+filepath.Dir(RulesPath()))
	return nil
}

// ---------------------------------------------------------------- 路径

// ConfigDir is isolated from existing private/production installations.
func ConfigDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "FudanVPNWindows")
	}
	return filepath.Join(base, "FudanVPNWindows")
}

// RulesPath 是规则文件位置。
func RulesPath() string { return filepath.Join(ConfigDir(), "rules.conf") }

func clientDataPath() string {
	return filepath.Join(ConfigDir(), "client_data.json")
}

// ensureRulesFile 在文件不存在时放一份默认规则。
//
// 默认规则和引擎用的是同一份源（engine/router/default_rules.conf），
// 由构建脚本复制到程序旁边，这里只做拷贝，不硬编码文本。
func ensureRulesFile() error {
	path := RulesPath()
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	// 找构建时复制过来的模板
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "rules.conf"),
			filepath.Join(dir, "..", "Resources", "rules.conf"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "rules.conf"),
			filepath.Join(wd, "..", "engine", "router", "default_rules.conf"),
		)
	}
	for _, c := range candidates {
		if data, err := os.ReadFile(c); err == nil {
			return os.WriteFile(path, data, 0o644)
		}
	}
	// 模板找不到也不能留空文件，否则用户一打开就是空白
	return os.WriteFile(path, []byte(router.DefaultRules), 0o644)
}
