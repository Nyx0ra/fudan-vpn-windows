package main

import (
	"encoding/json"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/wailsapp/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"
)

// go-webview2 exposes the WebView but does not bind its DevTools protocol
// methods. The vtable layouts below are from the base WebView2 SDK interfaces.
type loginWebViewVtbl struct {
	_                        [36]uintptr
	callDevToolsMethod       uintptr
	_                        [5]uintptr
	getDevToolsEventReceiver uintptr
}

func closeLoginController(controller *edge.ICoreWebView2Controller) {
	vtbl := *(**struct {
		_     [24]uintptr
		close uintptr
	})(unsafe.Pointer(controller))
	syscall.SyscallN(vtbl.close, uintptr(unsafe.Pointer(controller)))
	controller.Release()
}

type loginEventReceiver struct {
	vtbl *struct {
		_       [2]uintptr
		release uintptr
		add     uintptr
		remove  uintptr
	}
}

type loginEventArgs struct {
	vtbl *struct {
		_       [3]uintptr
		getJSON uintptr
	}
}

type loginCOMHandler struct {
	vtbl   *[4]uintptr
	iid    windows.GUID
	invoke func(uintptr, *loginEventArgs)
}

var (
	loginIUnknownIID = windows.GUID{Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	loginEventIID    = windows.GUID{Data1: 0xe2fda4be, Data2: 0x5456, Data3: 0x406c, Data4: [8]byte{0xa2, 0x61, 0x3d, 0x45, 0x21, 0x38, 0x36, 0x2c}}
	loginMethodIID   = windows.GUID{Data1: 0x5c4889f0, Data2: 0x5ef6, Data3: 0x4c5a, Data4: [8]byte{0x95, 0x2c, 0xd8, 0xf1, 0xb9, 0x2d, 0x05, 0x74}}
	loginCOMVtbl     = [4]uintptr{
		windows.NewCallback(func(handler *loginCOMHandler, iid *windows.GUID, out *unsafe.Pointer) uintptr {
			if out == nil {
				return 0x80004003 // E_POINTER
			}
			*out = nil
			if iid == nil || (*iid != loginIUnknownIID && *iid != handler.iid) {
				return 0x80004002 // E_NOINTERFACE
			}
			*out = unsafe.Pointer(handler)
			return 0
		}),
		// The login child owns and pins every handler until it exits.
		windows.NewCallback(func(*loginCOMHandler) uintptr { return 1 }),
		windows.NewCallback(func(*loginCOMHandler) uintptr { return 1 }),
		windows.NewCallback(func(handler *loginCOMHandler, status uintptr, args *loginEventArgs) uintptr {
			handler.invoke(status, args)
			return 0
		}),
	}
)

// startLoginFetch pauses only requests to the configured callback. Navigate
// after Fetch.enable completes, and deliver the URL only after Chromium has
// acknowledged the abort. WebResourceRequested and NavigationStarting can
// both observe a redirected GET after the destination has already received it.
func startLoginFetch(browser *edge.Chromium, pattern string, onReady func(), onCallback func(string), fail func(string)) (func(), error) {
	webview, err := browser.GetController().GetCoreWebView2()
	if err != nil {
		return nil, err
	}
	vtbl := *(**loginWebViewVtbl)(unsafe.Pointer(webview))
	var pin runtime.Pinner
	var receiver *loginEventReceiver
	var token int64
	var subscribed bool
	cleanup := func() {
		if subscribed {
			syscall.SyscallN(receiver.vtbl.remove, uintptr(unsafe.Pointer(receiver)), uintptr(token))
		}
		if receiver != nil {
			syscall.SyscallN(receiver.vtbl.release, uintptr(unsafe.Pointer(receiver)))
		}
		webview.Release()
		pin.Unpin()
	}
	newHandler := func(iid windows.GUID, invoke func(uintptr, *loginEventArgs)) *loginCOMHandler {
		handler := &loginCOMHandler{vtbl: &loginCOMVtbl, iid: iid, invoke: invoke}
		pin.Pin(handler)
		return handler
	}
	call := func(method string, params any, done func()) error {
		payload, err := json.Marshal(params)
		if err != nil {
			return err
		}
		name, _ := windows.UTF16PtrFromString(method)
		body, _ := windows.UTF16PtrFromString(string(payload))
		handler := newHandler(loginMethodIID, func(status uintptr, _ *loginEventArgs) {
			if int32(status) < 0 {
				fail("WebView2 无法暂停或中止认证回调")
				return
			}
			done()
		})
		hr, _, _ := syscall.SyscallN(vtbl.callDevToolsMethod, uintptr(unsafe.Pointer(webview)),
			uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(handler)))
		if int32(hr) < 0 {
			return windows.Errno(hr)
		}
		return nil
	}

	eventName, _ := windows.UTF16PtrFromString("Fetch.requestPaused")
	hr, _, _ := syscall.SyscallN(vtbl.getDevToolsEventReceiver, uintptr(unsafe.Pointer(webview)),
		uintptr(unsafe.Pointer(eventName)), uintptr(unsafe.Pointer(&receiver)))
	if int32(hr) < 0 {
		cleanup()
		return nil, windows.Errno(hr)
	}
	handler := newHandler(loginEventIID, func(_ uintptr, args *loginEventArgs) {
		var eventJSON *uint16
		hr, _, _ := syscall.SyscallN(args.vtbl.getJSON, uintptr(unsafe.Pointer(args)), uintptr(unsafe.Pointer(&eventJSON)))
		if int32(hr) < 0 {
			fail("无法读取暂停的认证回调")
			return
		}
		defer windows.CoTaskMemFree(unsafe.Pointer(eventJSON))
		var event struct {
			RequestID string `json:"requestId"`
			Request   struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		if err := json.Unmarshal([]byte(windows.UTF16PtrToString(eventJSON)), &event); err != nil || event.RequestID == "" {
			fail("无法读取暂停的认证回调")
			return
		}
		if err := call("Fetch.failRequest", map[string]string{"requestId": event.RequestID, "errorReason": "Aborted"}, func() {
			onCallback(event.Request.URL)
		}); err != nil {
			fail("无法中止浏览器的认证回调")
		}
	})
	hr, _, _ = syscall.SyscallN(receiver.vtbl.add, uintptr(unsafe.Pointer(receiver)),
		uintptr(unsafe.Pointer(handler)), uintptr(unsafe.Pointer(&token)))
	if int32(hr) < 0 {
		cleanup()
		return nil, windows.Errno(hr)
	}
	subscribed = true
	params := map[string]any{"patterns": []map[string]string{{"urlPattern": pattern, "requestStage": "Request"}}}
	if err := call("Fetch.enable", params, onReady); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, nil
}
