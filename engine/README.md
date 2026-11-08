# Windows 移植版引擎

本目录基于 [mythologyli/zju-connect](https://github.com/mythologyli/zju-connect)，
随 [wyleeyuan/fudan-vpn](https://github.com/wyleeyuan/fudan-vpn) 基础提交引入，并包含本地 Windows 修订。
完整来源、基础提交和许可见根目录 [NOTICE.md](../NOTICE.md)。

当前修改包含 aTrust 认证 HTTPS 校验、原始 OAuth 回调传递、可选且限定端点的隧道 TLS 例外、
用户态栈底层网络选择、状态上报，以及 1082 分流端口的可配置强制 VPN 目标。
默认严格 TLS，不把现场证书当成可信证书。例外的具体风险见 [SECURITY.md](../SECURITY.md)。
本次 Windows 桌面预览版只允许一个 IPv4 /32 作为强制目标；无 upstream、无额外 TUN。

模块路径保留上游命名，桌面通过本地 replace 编译本目录。不要用其他下载的同名引擎替换后声称行为一致。
从根目录运行 `scripts/Build-Windows.ps1` 执行完整测试并构建两个正式程序。
根目录 README 是 Windows 使用入口；`README.upstream*.md`、`docs/` 及
`config.toml.example` 是保留的上游 CLI 参考，可能涉及其他平台、协议、服务或较宽的监听绑定，
不代表本 Windows 桌面默认配置。原 Tools/Resources 构建链不包含在本发行目录中。

发行 CLI 在任何网络请求之前拒绝非 aTrust 协议；EasyConnect 源码仅作上游参考。
节点 TLS 延迟探测与数据隧道共用限定端点的验证策略。
CLI 仍保留部分上游高级功能与兼容参数；不要通过命令行传授权码、密码或回调。
推荐桌面私有登录流程，不要将高级 CLI 配置等同于桌面安全默认值。

本目录 LICENSE 为 AGPL v3；internal/ping/LICENSE 为保留的 MIT 许可。
本地源码尚未上传，分发二进制前需一并提供对应完整源码及许可。
