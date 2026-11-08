package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

var trayUser = windows.NewLazySystemDLL("user32.dll")
var trayShell = windows.NewLazySystemDLL("shell32.dll")
var activeTray *windowsTray
var trayProc = windows.NewCallback(trayWindowProc)

const trayEvent = 0x8001
const trayNoticeEvent = 0x8002

type notifyIconData struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Timeout             uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                windows.GUID
	BalloonIcon         uintptr
}
type windowsTray struct {
	app     *App
	hwnd    uintptr
	icons   map[Phase]uintptr
	data    notifyIconData
	last    string
	taskbar uint32
	done    chan struct{}
	once    sync.Once
}

func putTrayText(dst []uint16, s string) {
	src := windows.StringToUTF16(s)
	if len(src) > len(dst) {
		src = src[:len(dst)-1]
	}
	for i := range dst {
		dst[i] = 0
	}
	copy(dst, src)
}
func startDesktopTray(a *App) (desktopTray, error) {
	ready := make(chan error, 1)
	t := &windowsTray{app: a, icons: map[Phase]uintptr{}, done: make(chan struct{})}
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(t.done)
		instance, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
		name, _ := windows.UTF16PtrFromString("FudanVPNStatusTray")
		class := loginWindowClass{proc: trayProc, instance: instance, name: name}
		class.size = uint32(unsafe.Sizeof(class))
		trayUser.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&class)))
		activeTray = t
		t.hwnd, _, _ = trayUser.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, 0, 0, 0, instance, 0)
		if t.hwnd == 0 {
			ready <- fmt.Errorf("创建托盘消息窗口失败")
			return
		}
		defer func() {
			for _, icon := range t.icons {
				trayUser.NewProc("DestroyIcon").Call(icon)
			}
		}()
		for _, p := range []Phase{PhaseIdle, PhaseLaunching, PhaseConnected, PhaseFailed} {
			t.icons[p] = makeTrayIcon(p)
		}
		task, _ := windows.UTF16PtrFromString("TaskbarCreated")
		r, _, _ := trayUser.NewProc("RegisterWindowMessageW").Call(uintptr(unsafe.Pointer(task)))
		t.taskbar = uint32(r)
		t.data = notifyIconData{Window: t.hwnd, ID: 1, Flags: 7, Callback: trayEvent, Icon: t.icons[PhaseIdle]}
		t.data.Size = uint32(unsafe.Sizeof(t.data))
		putTrayText(t.data.Tip[:], "复旦 VPN · 未连接")
		ok, _, _ := trayShell.NewProc("Shell_NotifyIconW").Call(0, uintptr(unsafe.Pointer(&t.data)))
		if ok == 0 {
			trayUser.NewProc("DestroyWindow").Call(t.hwnd)
			ready <- fmt.Errorf("系统未接受托盘图标")
			return
		}
		trayUser.NewProc("SetTimer").Call(t.hwnd, 1, 1000, 0)
		t.update(true)
		ready <- nil
		defer trayShell.NewProc("Shell_NotifyIconW").Call(2, uintptr(unsafe.Pointer(&t.data)))
		var msg loginWindowMessage
		for {
			r, _, _ := trayUser.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if int32(r) <= 0 {
				break
			}
			trayUser.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg)))
			trayUser.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg)))
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return t, nil
}
func (t *windowsTray) update(force bool) {
	p, msg := t.app.engine.Phase()
	v := presentTray(p, msg, t.app.engine.Details())
	if !force && t.last == v.Tooltip {
		return
	}
	t.last = v.Tooltip
	t.data.Icon = t.icons[p]
	putTrayText(t.data.Tip[:], v.Tooltip)
	t.data.Flags = 7
	trayShell.NewProc("Shell_NotifyIconW").Call(1, uintptr(unsafe.Pointer(&t.data)))
}
func (t *windowsTray) Notify() { trayUser.NewProc("PostMessageW").Call(t.hwnd, trayNoticeEvent, 0, 0) }
func (t *windowsTray) Close() {
	t.once.Do(func() { trayUser.NewProc("PostMessageW").Call(t.hwnd, 0x10, 0, 0) })
	select {
	case <-t.done:
	case <-time.After(3 * time.Second):
	}
}
func trayWindowProc(hwnd uintptr, msg uint32, w, l uintptr) uintptr {
	t := activeTray
	if t != nil {
		if msg == t.taskbar && t.taskbar != 0 {
			trayShell.NewProc("Shell_NotifyIconW").Call(0, uintptr(unsafe.Pointer(&t.data)))
			t.update(true)
			return 0
		}
		switch msg {
		case 0x113:
			t.update(false)
			return 0
		case trayNoticeEvent:
			t.data.Flags = 0x10
			putTrayText(t.data.InfoTitle[:], "复旦 VPN 仍在后台运行")
			putTrayText(t.data.Info[:], "关闭窗口仅隐藏到托盘。右键托盘图标可连接、断开、查看日志或退出。")
			t.data.InfoFlags = 1
			t.data.Timeout = 10000
			trayShell.NewProc("Shell_NotifyIconW").Call(1, uintptr(unsafe.Pointer(&t.data)))
			t.data.Flags = 7
			return 0
		case trayEvent:
			switch uint32(l) & 0xffff {
			case 0x202, 0x203:
				go t.app.Show()
			case 0x205, 0x7b:
				t.menu()
			}
			return 0
		case 0x10:
			trayUser.NewProc("DestroyWindow").Call(hwnd)
			return 0
		case 2:
			trayUser.NewProc("PostQuitMessage").Call(0)
			return 0
		}
	}
	r, _, _ := trayUser.NewProc("DefWindowProcW").Call(hwnd, uintptr(msg), w, l)
	return r
}
func (t *windowsTray) menu() {
	p, msg := t.app.engine.Phase()
	v := presentTray(p, msg, t.app.engine.Details())
	menu, _, _ := trayUser.NewProc("CreatePopupMenu").Call()
	defer trayUser.NewProc("DestroyMenu").Call(menu)
	add := func(id uintptr, label string, enabled bool) {
		s, _ := windows.UTF16PtrFromString(label)
		flags := uintptr(0)
		if !enabled {
			flags = 3
		}
		trayUser.NewProc("AppendMenuW").Call(menu, flags, id, uintptr(unsafe.Pointer(s)))
	}
	add(10, "复旦 VPN · "+v.Label, false)
	trayUser.NewProc("AppendMenuW").Call(menu, 0x800, 0, 0)
	add(1, "打开主界面", true)
	add(2, v.ConnectLabel, v.CanConnect)
	add(3, "断开", v.CanDisconnect)
	add(4, "查看日志", true)
	trayUser.NewProc("AppendMenuW").Call(menu, 0x800, 0, 0)
	add(5, "退出", true)
	var point struct{ X, Y int32 }
	trayUser.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&point)))
	trayUser.NewProc("SetForegroundWindow").Call(t.hwnd)
	choice, _, _ := trayUser.NewProc("TrackPopupMenu").Call(menu, 0x182, uintptr(point.X), uintptr(point.Y), 0, t.hwnd, 0)
	trayUser.NewProc("PostMessageW").Call(t.hwnd, 0, 0, 0)
	switch choice {
	case 1:
		go t.app.Show()
	case 2:
		go func() {
			if err := t.app.Reconnect(); err != nil {
				t.app.engine.setPhase(PhaseFailed, safeLog(err.Error()))
			}
		}()
	case 3:
		go t.app.Disconnect()
	case 4:
		go t.app.ViewLogs()
	case 5:
		go t.app.Exit()
	}
}
func makeTrayIcon(p Phase) uintptr {
	mask := make([]byte, 32)
	for i := range mask {
		mask[i] = 255
	}
	pixels := make([]byte, 16*16*4)
	color := [3]byte{128, 128, 128}
	switch p {
	case PhaseLaunching:
		color = [3]byte{230, 156, 35}
	case PhaseConnected:
		color = [3]byte{35, 180, 91}
	case PhaseFailed:
		color = [3]byte{220, 65, 65}
	}
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			dx, dy := x-8, y-8
			if dx*dx+dy*dy > 49 {
				continue
			}
			mask[(15-y)*2+x/8] &= ^(byte(1) << uint(7-x%8))
			i := ((15-y)*16 + x) * 4
			pixels[i] = color[2]
			pixels[i+1] = color[1]
			pixels[i+2] = color[0]
			pixels[i+3] = 255
			white := false
			switch p {
			case PhaseIdle:
				white = y >= 7 && y <= 8 && x >= 4 && x <= 11
			case PhaseLaunching:
				white = (x == 6 || x == 10) && y >= 5 && y <= 10
			case PhaseConnected:
				white = (x >= 4 && x <= 7 && y == x+2) || (x >= 7 && x <= 12 && y == 16-x)
			case PhaseFailed:
				white = (x >= 5 && x <= 10) && (y == x || y == 15-x)
			}
			if white {
				pixels[i] = 255
				pixels[i+1] = 255
				pixels[i+2] = 255
			}
		}
	}
	icon, _, _ := trayUser.NewProc("CreateIcon").Call(0, 16, 16, 1, 32, uintptr(unsafe.Pointer(&mask[0])), uintptr(unsafe.Pointer(&pixels[0])))
	return icon
}
