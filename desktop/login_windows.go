package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
	"unsafe"

	"github.com/wailsapp/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"
)

const automaticPlatformLogin = true
const loginChildFlag = "--webview-login"

type loginResult struct {
	Callback string
	Error    string
}

func newWindowsLoginCommand(ctx context.Context, exe string) (*exec.Cmd, func(), error) {
	// A WebView2 session can reuse a previous OAuth redirect. Each attempt
	// needs its own profile so the identity provider issues a fresh code.
	profile, err := os.MkdirTemp("", "FudanVPN-login-")
	if err != nil {
		return nil, nil, fmt.Errorf("无法创建临时登录配置：%w", err)
	}
	cleanup := func() {
		// WebView2 may still have file handles as the login child exits.
		for attempt := 0; attempt < 10; attempt++ {
			if os.RemoveAll(profile) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return exec.CommandContext(ctx, exe, loginChildFlag, profile), cleanup, nil
}

func platformLogin(ctx context.Context) (string, bool, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", true, err
	}
	cmd, cleanup, err := newWindowsLoginCommand(ctx, exe)
	if err != nil {
		return "", true, err
	}
	defer cleanup()
	out, err := cmd.Output()
	if err != nil {
		return "", true, fmt.Errorf("登录窗口退出：%w", err)
	}
	var result loginResult
	if err := json.Unmarshal(out, &result); err != nil {
		return "", true, errors.New("登录窗口未返回有效结果")
	}
	if result.Error != "" {
		return "", true, errors.New(result.Error)
	}
	return result.Callback, true, nil
}

func runPlatformLoginChild() bool {
	if len(os.Args) < 2 || os.Args[1] != loginChildFlag {
		return false
	}
	// The only consumer is the parent process's private stdout pipe.
	if len(os.Args) != 3 {
		_ = json.NewEncoder(os.Stdout).Encode(loginResult{Error: "登录窗口缺少临时配置"})
		return true
	}
	_ = json.NewEncoder(os.Stdout).Encode(showLoginWindow(os.Args[2]))
	return true
}

const (
	wmDestroy = 0x0002
	wmSize    = 0x0005
	wmClose   = 0x0010
)

var (
	user32Login     = windows.NewLazySystemDLL("user32.dll")
	loginBrowser    *edge.Chromium
	loginWindowProc = windows.NewCallback(handleLoginWindowMessage)
)

type loginWindowClass struct {
	size, style                        uint32
	proc                               uintptr
	classExtra, windowExtra            int32
	instance, icon, cursor, background uintptr
	menu, name                         *uint16
	smallIcon                          uintptr
}

type loginWindowMessage struct {
	hwnd           uintptr
	message        uint32
	wparam, lparam uintptr
	time           uint32
	x, y           int32
	private        uint32
}

func handleLoginWindowMessage(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case wmSize:
		if loginBrowser != nil {
			loginBrowser.Resize()
		}
		return 0
	case wmDestroy:
		user32Login.NewProc("PostQuitMessage").Call(0)
		return 0
	}
	result, _, _ := user32Login.NewProc("DefWindowProcW").Call(hwnd, uintptr(msg), wparam, lparam)
	return result
}

func showLoginWindow(profile string) (result loginResult) {
	// go-webview2 initializes COM on the locked main OS thread.
	instance, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
	className, _ := windows.UTF16PtrFromString("FudanVPNLoginWindow")
	title, _ := windows.UTF16PtrFromString("复旦大学统一身份认证")
	cursor, _, _ := user32Login.NewProc("LoadCursorW").Call(0, 32512)
	class := loginWindowClass{
		proc: loginWindowProc, instance: instance, cursor: cursor, background: 6, name: className,
	}
	class.size = uint32(unsafe.Sizeof(class))
	atom, _, _ := user32Login.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&class)))
	if atom == 0 {
		return loginResult{Error: "无法注册登录窗口"}
	}
	const overlappedWindow = 0x00cf0000
	const useDefault = 0x80000000
	hwnd, _, _ := user32Login.NewProc("CreateWindowExW").Call(
		0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)),
		overlappedWindow, useDefault, useDefault, 980, 780, 0, 0, instance, 0,
	)
	if hwnd == 0 {
		return loginResult{Error: "无法创建登录窗口"}
	}
	defer user32Login.NewProc("DestroyWindow").Call(hwnd)
	closeWindow := func() {
		user32Login.NewProc("PostMessageW").Call(hwnd, wmClose, 0, 0)
	}
	fail := func(message string) {
		result = loginResult{Error: message}
		closeWindow()
	}

	browser := edge.NewChromium()
	browser.DataPath = profile
	browser.SetErrorCallback(func(error) { fail("WebView2 初始化或登录导航失败") })
	browser.Embed(hwnd)
	if result.Error != "" || browser.GetController() == nil {
		return loginResult{Error: "无法初始化 WebView2 登录窗口"}
	}
	loginBrowser = browser
	defer func() {
		loginBrowser = nil
		browser.ShuttingDown()
		closeLoginController(browser.GetController())
	}()

	settings, err := browser.GetSettings()
	if err != nil {
		return loginResult{Error: "无法读取登录窗口设置"}
	}
	for _, set := range []func(bool) error{
		settings.PutAreHostObjectsAllowed, settings.PutIsWebMessageEnabled,
		settings.PutAreDevToolsEnabled, settings.PutAreDefaultContextMenusEnabled,
		settings.PutIsStatusBarEnabled,
	} {
		if err := set(false); err != nil {
			return loginResult{Error: "无法隔离登录窗口"}
		}
	}
	browser.SetGlobalPermission(edge.CoreWebView2PermissionStateDeny)
	_ = browser.PutIsPasswordAutosaveEnabled(false)
	_ = browser.PutIsGeneralAutofillEnabled(false)

	user32Login.NewProc("ShowWindow").Call(hwnd, 5)
	browser.Resize()
	if err := browser.Show(); err != nil {
		return loginResult{Error: "无法显示 WebView2 登录页面"}
	}
	stopFetch, err := startLoginFetch(browser, "https://"+callHost+callPath+"?*", func() {
		browser.Navigate(LoginURL())
	}, func(raw string) {
		if result.Callback != "" || result.Error != "" {
			return
		}
		callback := windowsLoginCallback(raw)
		if callback == "" {
			fail("收到无效的学校认证回调")
			return
		}
		result = loginResult{Callback: callback}
		closeWindow()
	}, fail)
	if err != nil {
		return loginResult{Error: "无法初始化 WebView2 的认证回调拦截"}
	}
	defer stopFetch()

	getMessage := user32Login.NewProc("GetMessageW")
	translateMessage := user32Login.NewProc("TranslateMessage")
	dispatchMessage := user32Login.NewProc("DispatchMessageW")
	var message loginWindowMessage
	for {
		status, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		switch int32(status) {
		case -1:
			return loginResult{Error: "登录窗口消息循环失败"}
		case 0:
			return result
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&message)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
	}
}
