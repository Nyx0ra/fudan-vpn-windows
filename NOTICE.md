# 来源与修改声明

本项目是独立整理的、非官方 Windows 移植版，与复旦大学、深信服及上游维护者没有隶属或背书关系。

- 原项目：[wyleeyuan/fudan-vpn](https://github.com/wyleeyuan/fudan-vpn)，基础提交
  `e2f9df7592171a8c794bc318749fa6e472107102`。
- 引擎来源：[mythologyli/zju-connect](https://github.com/mythologyli/zju-connect)。
  引擎及桌面模块名保留上游命名，桌面通过本地 replace 使用本目录的引擎源码。
- 保留根目录及 engine/LICENSE 的 GNU Affero General Public License v3。
  engine/internal/ping/LICENSE 的 MIT 许可及其版权声明保持不变。
- 本地 Windows 修改整理日期：2026-11-08。包含 WebView2 CDP 登录回调截获、私有回调传递、
  Windows 托盘与进程管理、隧道健康状态、限定端点的可选 TLS 兼容模式、
  单目标强制 VPN、底层接口选择及 TLS SNI 适配，以及本次公开版配置隔离和文档。

保留现有版权声明；不声称原创上游实现。公开分发修改版时应同时提供对应完整源码、
构建脚本、许可及修改说明，不能只注明原项目而省略其许可要求。

Windows 构建脚本会从实际模块缓存收集依赖模块的许可/NOTICE，写入分发包
`THIRD_PARTY_NOTICES.txt`，并生成模块版本清单。第三方组件适用各自许可。
请在发布前复核这些清单及随附源码；本地生成的构建包尚未发布。
