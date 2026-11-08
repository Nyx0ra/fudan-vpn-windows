package desktopstatus

import "golang.org/x/sys/windows"

func ProcessStart() int64 {
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user) != nil {
		return 0
	}
	return created.Nanoseconds()
}
