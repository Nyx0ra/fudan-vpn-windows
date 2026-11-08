package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mythologyli/zju-connect/desktopstatus"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Phase string

const (
	PhaseIdle      Phase = "idle"
	PhaseLaunching Phase = "launching"
	PhaseConnected Phase = "connected"
	PhaseFailed    Phase = "failed"
)

type processIdentity struct {
	PID   int
	Start int64
	Exe   string
}
type Engine struct {
	mu           sync.Mutex
	op           sync.Mutex
	cmd          *exec.Cmd
	identity     *processIdentity
	owned        bool
	external     bool
	foreign      bool
	closing      atomic.Bool
	runID        string
	generation   uint64
	phase        Phase
	failMsg      string
	connectedAt  time.Time
	startedAt    time.Time
	wasConnected bool
	needsLogin   bool
	settings     ConnectionSettings
	onLog        func(string)
	onPhase      func(Phase, string)
	splitPort    string
}

func NewEngine() *Engine                       { return &Engine{phase: PhaseIdle, splitPort: "1082"} }
func (e *Engine) Phase() (Phase, string)       { e.mu.Lock(); defer e.mu.Unlock(); return e.phase, e.failMsg }
func (e *Engine) ConnectedSince() time.Time    { e.mu.Lock(); defer e.mu.Unlock(); return e.connectedAt }
func (e *Engine) setPhase(p Phase, msg string) { e.changePhase(p, msg, nil) }
func (e *Engine) setPhaseFor(gen uint64, id *processIdentity, p Phase, msg string) {
	e.changePhase(p, msg, func() bool { return e.generation == gen && e.identity == id })
}
func (e *Engine) changePhase(p Phase, msg string, guard func() bool) {
	e.mu.Lock()
	if guard != nil && !guard() {
		e.mu.Unlock()
		return
	}
	changed := e.phase != p || e.failMsg != msg
	e.phase = p
	e.failMsg = safeLog(msg)
	if p == PhaseConnected {
		if e.connectedAt.IsZero() {
			e.connectedAt = time.Now()
		}
		e.wasConnected = true
	} else {
		e.connectedAt = time.Time{}
	}
	cb := e.onPhase
	e.mu.Unlock()
	if changed && cb != nil {
		cb(p, safeLog(msg))
	}
}
func (e *Engine) log(s string) {
	if e.onLog != nil {
		e.onLog(safeLog(s))
	}
}

var urlInLog = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
var secretInLog = regexp.MustCompile(`(?i)(code|sid|token|ticket|password|oauth2_callback|oauth2_code)=([^\s&]+)`)

func safeLog(s string) string {
	s = urlInLog.ReplaceAllString(s, "[网址已隐藏]")
	return secretInLog.ReplaceAllString(s, "$1=[已隐藏]")
}
func statusFile() string { return filepath.Join(ConfigDir(), "engine-status.json") }
func logFile() string    { return filepath.Join(ConfigDir(), "desktop.log") }
func binaryPath() (string, error) {
	name := "fudan-connect"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(dir, name), filepath.Join(dir, "..", "Resources", name))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, name), filepath.Join(wd, "..", "Resources", name))
	}
	candidates = append(candidates, "/usr/lib/fudan-vpn/"+name)
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			p, _ = filepath.Abs(p)
			return filepath.Clean(p), nil
		}
	}
	return "", fmt.Errorf("找不到 %s，请确认它和程序放在同一目录", name)
}
func evidencePhase(s desktopstatus.Snapshot, pid int, start int64, run string, now time.Time, expected ConnectionSettings) (Phase, string) {
	age := now.Sub(time.Unix(0, s.Updated))
	if s.Version != 1 || s.PID != pid || s.ProcessStart != start || s.RunID == "" || s.RunID != run || age < -time.Second || age > 5*time.Second {
		return PhaseFailed, "引擎健康状态缺失、过期或归属不匹配"
	}
	if !s.Session {
		return PhaseLaunching, "等待有效 VPN 会话"
	}
	if !s.PolicyValid {
		return PhaseFailed, "引擎参数不符合校园专用保护，不能报告已连接"
	}
	settings, err := expected.normalized()
	if err != nil || s.TargetCIDR != settings.targetCIDR() || s.TLSCompatibility != settings.TunnelTLSCompatibility {
		return PhaseFailed, "引擎目标或 TLS 模式与客户端设置不匹配"
	}
	if s.Tunnels < 1 {
		if s.Reconnecting {
			return PhaseLaunching, "L3 隧道正在重连"
		}
		return PhaseFailed, "没有近期服务端响应的 L3 隧道"
	}
	return PhaseConnected, "会话有效、L3 服务端响应正常、1082 归属已核对；未持续探测实验室服务"
}
func readSnapshot() (desktopstatus.Snapshot, error) {
	var s desktopstatus.Snapshot
	b, err := os.ReadFile(statusFile())
	if err == nil {
		err = json.Unmarshal(b, &s)
	}
	return s, err
}
func (e *Engine) Details() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	pid := 0
	if e.identity != nil {
		pid = e.identity.PID
	}
	liveOwned := e.owned && e.identity != nil && identityAlive(*e.identity)
	return map[string]any{"pid": pid, "owned": e.owned, "external": e.external, "canConnect": !e.closing.Load() && !e.foreign && e.phase != PhaseLaunching, "canDisconnect": liveOwned, "needsLogin": e.needsLogin}
}
func (e *Engine) Monitor(ctx context.Context) {
	settings, settingsErr := loadSettings(settingsPath())
	if settingsErr == nil {
		settings, settingsErr = settings.normalized()
	}
	// Discover once: unknown external programs are never silently taken over.
	if id, err := listenerIdentity(1082); err == nil && id != nil {
		bin, _ := binaryPath()
		e.mu.Lock()
		e.identity = id
		e.external = true
		e.mu.Unlock()
		if sameExecutable(id.Exe, bin) {
			if s, err := readSnapshot(); err == nil && settingsErr == nil && s.Version == 1 && s.TargetCIDR == settings.targetCIDR() && s.TLSCompatibility == settings.TunnelTLSCompatibility && s.PolicyValid && s.PID == id.PID && s.ProcessStart == id.Start && s.RunID != "" && time.Since(time.Unix(0, s.Updated)) >= -time.Second && time.Since(time.Unix(0, s.Updated)) < 5*time.Second {
				e.mu.Lock()
				e.owned = true
				e.external = false
				e.runID = s.RunID
				e.startedAt = time.Now()
				e.settings = settings
				e.mu.Unlock()
				e.log(fmt.Sprintf("已接管同目录引擎 PID %d（进程创建时间与健康快照匹配）", id.PID))
			} else {
				e.setPhase(PhaseFailed, fmt.Sprintf("发现同目录脚本引擎 PID %d，健康尚未验证；请选择接管并重新连接", id.PID))
			}
		} else {
			e.setPhase(PhaseFailed, "1082 被其他程序占用；未接管、不会停止该程序")
			e.mu.Lock()
			e.foreign = true
			e.external = false
			e.mu.Unlock()
		}
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		e.poll()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.poll()
			}
		}
	}()
}
func (e *Engine) poll() {
	e.mu.Lock()
	id := e.identity
	owned := e.owned
	run := e.runID
	gen := e.generation
	started := e.startedAt
	was := e.wasConnected
	settings := e.settings
	e.mu.Unlock()
	if id != nil && !owned && !identityAlive(*id) {
		e.mu.Lock()
		same := e.identity == id && e.generation == gen
		if same {
			e.identity = nil
			e.external = false
			e.foreign = false
		}
		e.mu.Unlock()
		if same {
			e.setPhaseFor(gen, nil, PhaseIdle, "")
		}
		return
	}
	if id == nil || !owned {
		return
	}
	p, msg := PhaseFailed, "引擎已退出"
	if identityAlive(*id) {
		owner, err := listenerIdentity(1082)
		if err != nil || owner == nil || owner.PID != id.PID || owner.Start != id.Start {
			msg = "引擎尚未拥有 1082 监听"
		} else if s, err := readSnapshot(); err == nil {
			p, msg = evidencePhase(s, id.PID, id.Start, run, time.Now(), settings)
		} else {
			msg = "尚未收到引擎健康状态"
		}
		if p != PhaseConnected && !was && time.Since(started) < 45*time.Second {
			p = PhaseLaunching
		}
	}
	e.setPhaseFor(gen, id, p, msg)
}
func (e *Engine) StartSaved(rules string) error {
	if _, err := os.Stat(clientDataPath()); err != nil {
		return errors.New("没有缓存会话，请打开登录页")
	}
	return e.start("", "", rules, true)
}
func (e *Engine) Start(code, callback, rules string) error {
	return e.start(code, callback, rules, false)
}

var errEngineClosed = errors.New("客户端已退出，不再启动引擎")

func (e *Engine) start(code, callback, rules string, reuse bool) (result error) {
	e.op.Lock()
	defer e.op.Unlock()
	if e.closing.Load() {
		return errEngineClosed
	}
	defer func() {
		if result != nil {
			e.setPhase(PhaseFailed, safeLog(result.Error()))
		}
	}()
	settings, err := loadSettings(settingsPath())
	if err != nil {
		return err
	}
	settings, err = settings.normalized()
	if err != nil {
		return err
	}
	args, err := connectionArgs(settings, rules, reuse)
	if err != nil {
		return err
	}
	bin, err := binaryPath()
	if err != nil {
		e.setPhase(PhaseFailed, err.Error())
		return err
	}
	// Refuse collisions before stopping anything. A legacy same-path instance may
	// only be replaced when this explicit connect/reconnect action is invoked.
	for _, port := range []uint16{1080, 1081, 1082} {
		owner, err := listenerIdentity(port)
		if err != nil {
			return err
		}
		if owner == nil {
			continue
		}
		if !sameExecutable(owner.Exe, bin) {
			err = fmt.Errorf("端口 %d 被其他程序占用，未停止该程序", port)
			e.setPhase(PhaseFailed, err.Error())
			return err
		}
		e.mu.Lock()
		known := e.identity
		e.mu.Unlock()
		if known == nil || known.PID != owner.PID || known.Start != owner.Start {
			err = errors.New("检测到未确认归属的引擎；请重新打开客户端检查")
			e.setPhase(PhaseFailed, err.Error())
			return err
		}
	}
	e.mu.Lock()
	old := e.identity
	owned := e.owned
	external := e.external
	e.mu.Unlock()
	if old != nil && (owned || (external && sameExecutable(old.Exe, bin))) {
		if err := stopIdentity(*old); err != nil && identityAlive(*old) {
			return err
		}
	}
	e.mu.Lock()
	e.generation++
	gen := e.generation
	e.identity = nil
	e.owned = false
	e.external = false
	e.foreign = false
	e.wasConnected = false
	e.needsLogin = false
	e.cmd = nil
	e.startedAt = time.Now()
	e.settings = settings
	e.mu.Unlock()
	e.setPhase(PhaseLaunching, "正在启动用户态引擎")
	cmd := exec.Command(bin, args...)
	quietEngineCommand(cmd)
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	run := hex.EncodeToString(nonce)
	env := []string{}
	for _, kv := range os.Environ() {
		lower := strings.ToLower(kv)
		skip := false
		for _, prefix := range []string{"http_proxy=", "https_proxy=", "all_proxy=", "no_proxy=", "fudan_connect_", "fudan_vpn_status_file=", "fudan_vpn_run_id="} {
			if strings.HasPrefix(lower, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			env = append(env, kv)
		}
	}
	env = append(env, "FUDAN_VPN_STATUS_FILE="+statusFile(), "FUDAN_VPN_RUN_ID="+run)
	if callback != "" {
		env = append(env, "FUDAN_CONNECT_OAUTH2_CALLBACK="+callback)
	} else if code != "" {
		env = append(env, "FUDAN_CONNECT_OAUTH2_CODE="+code)
	}
	cmd.Env = env
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err = cmd.Start(); err != nil {
		e.setPhase(PhaseFailed, "引擎启动失败")
		return err
	}
	id, err := identifyProcess(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 3 {
			e.mu.Lock()
			e.needsLogin = true
			e.mu.Unlock()
			return errors.New("学校会话已过期，请打开登录页")
		}
		return err
	}
	e.mu.Lock()
	e.cmd = cmd
	e.identity = &id
	e.owned = true
	e.runID = run
	e.mu.Unlock()
	go e.pump(out)
	go func() {
		err := cmd.Wait()
		e.mu.Lock()
		same := e.generation == gen && e.cmd == cmd
		if same {
			e.cmd = nil
			e.needsLogin = cmd.ProcessState.ExitCode() == 3
		}
		e.mu.Unlock()
		if same {
			msg := "引擎意外退出"
			if cmd.ProcessState.ExitCode() == 3 {
				msg = "学校会话已过期，请打开登录页"
			} else if err != nil {
				msg += "：" + err.Error()
			}
			e.setPhaseFor(gen, &id, PhaseFailed, msg)
		}
	}()
	return nil
}
func (e *Engine) Stop() bool {
	e.op.Lock()
	defer e.op.Unlock()
	return e.stopLocked()
}
func (e *Engine) stopLocked() bool {
	e.mu.Lock()
	id := e.identity
	owned := e.owned
	e.mu.Unlock()
	if owned && id != nil {
		if err := stopIdentity(*id); err != nil && identityAlive(*id) {
			e.setPhase(PhaseFailed, "无法停止受管理引擎，进程仍在运行")
			return false
		}
	}
	e.mu.Lock()
	e.generation++
	e.cmd = nil
	if owned {
		e.identity = nil
		e.owned = false
	}
	e.mu.Unlock()
	return true
}
func (e *Engine) Close() bool { e.closing.Store(true); return e.Stop() }
func (e *Engine) Disconnect() {
	e.op.Lock()
	defer e.op.Unlock()
	if e.stopLocked() {
		e.setPhase(PhaseIdle, "")
	}
}
func (e *Engine) pump(r io.ReadCloser) {
	defer r.Close()
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 65536), 1024*1024)
	for s.Scan() {
		e.log(strings.TrimRight(s.Text(), "\r"))
	}
}
func sameExecutable(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
