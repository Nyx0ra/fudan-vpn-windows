package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
	"unsafe"
)

func quietEngineCommand(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
func identifyHandle(h windows.Handle, pid int) (processIdentity, error) {
	var made, end, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &made, &end, &kernel, &user); err != nil {
		return processIdentity{}, err
	}
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return processIdentity{}, err
	}
	return processIdentity{PID: pid, Start: made.Nanoseconds(), Exe: windows.UTF16ToString(buf[:n])}, nil
}
func identifyProcess(pid int) (processIdentity, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return processIdentity{}, err
	}
	defer windows.CloseHandle(h)
	return identifyHandle(h, pid)
}
func identityAlive(id processIdentity) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(id.PID))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	now, err := identifyHandle(h, id.PID)
	if err != nil || now.Start != id.Start || !sameExecutable(now.Exe, id.Exe) {
		return false
	}
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == 259
}
func stopIdentity(id processIdentity) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(id.PID))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	current, err := identifyHandle(h, id.PID)
	if err != nil {
		return err
	}
	if current.Start != id.Start || !sameExecutable(current.Exe, id.Exe) {
		return fmt.Errorf("进程归属已变化，拒绝停止")
	}
	if err = windows.TerminateProcess(h, 0); err != nil {
		return err
	}
	result, err := windows.WaitForSingleObject(h, 5000)
	if err == nil && result != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("等待引擎停止超时")
	}
	return err
}
func listenerIdentity(port uint16) (*processIdentity, error) {
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	size := uint32(0)
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 3, 0)
	if size < 4 {
		return nil, fmt.Errorf("无法读取 TCP 监听归属")
	}
	b := make([]byte, size)
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, 2, 3, 0)
	if r != 0 {
		return nil, fmt.Errorf("无法读取 TCP 监听归属 (%d)", r)
	}
	count := *(*uint32)(unsafe.Pointer(&b[0]))
	for i := uint32(0); i < count; i++ {
		off := 4 + i*24
		if int(off+24) > len(b) {
			return nil, fmt.Errorf("TCP 表长度无效")
		}
		row := (*[6]uint32)(unsafe.Pointer(&b[off]))
		p := uint16(row[2]&255)<<8 | uint16((row[2]>>8)&255)
		if p == port && (row[1] == 0 || row[1] == 0x0100007f) {
			id, err := identifyProcess(int(row[5]))
			return &id, err
		}
	}
	return nil, nil
}
