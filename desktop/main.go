package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	if runPlatformLoginChild() {
		return
	}
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "复旦 VPN Windows（预览版）",
		Width:     780,
		Height:    600,
		MinWidth:  640,
		MinHeight: 480,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:     app.startup,
		OnShutdown:    app.shutdown,
		OnBeforeClose: app.beforeClose,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "fudan-vpn-windows-public-v1",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) { app.Show() },
		},
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("启动失败:", err.Error())
	}
}
