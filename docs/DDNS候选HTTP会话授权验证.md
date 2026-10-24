# DDNS 候选 HTTP 会话授权验证

本入口实际运行 Python HTTP 客户端 → uhttpd/ubus 插件 → rpcd session.access → 原候选 ucode。继承 r82 的八项真实 RPC 检查，再增加十项 HTTP 检查。候选源码、ACL 和 `native_ddns_rpc_enabled=false` 保持不变，生产配方不安装候选。这里验证宿主 HTTP RPC 的会话授权，不表示 Lua/LuCI 控制器、CSRF、HTTPS、目标 ABI 或设备已经验收。

## 执行入口与来源

以普通 Linux 用户执行，需要 r82 的工具/开发库和可用的非特权命名空间；本轮不增加系统依赖：

```sh
sh scripts/check-http.sh
# 或复用三个已校验的运行时，顺序为 HTTP、RPC、ucode：
sh scripts/check-http.sh /absolute/http-runtime /absolute/rpc-runtime /absolute/ucode-runtime
```

默认目录为 `build/uhttpd`、`build/rpcd`、`build/ucode`。准备脚本只下载固定源归档并在工作目录构建。ucode 和 RPC 来源、摘要及安装产物先按 r81/r82 规则核实后复用；未完成构建保留，另选新目录。uhttpd 固定为 OpenWrt v25.12.0 配方的 `ebb92e6b339b88bbc6b76501b6603c52d4887ba1`，官方源归档 SHA256 为 `2d00da72db0ec08132bb169f2bad0b153bd998ea1eee0700b4ec01e65c35127d`。构建只启用 UBUS，关闭 TLS/LUA/UCODE 插件；记录 uhttpd 与 uhttpd_ubus.so 摘要，并绑定所复用 RPC 库的逐文件摘要。

这套宿主组件组合不代表旧 QWRT 的版本或 ABI。CI 新增同一入口，按项目集中周期执行；本地成功不记作远端成功。

## 隔离与夹具边界

复用 r82 的 bubblewrap 启动器，外层普通 UID 映射为内部 UID 0，移除全部 capabilities；user/mount/PID/network 等命名空间独立。源码和运行时只读挂载，私有 `/etc`、`/var`、`/tmp`、socket 与状态目录，业务后端缺席。uhttpd 以前台方式只监听私有网络的 `127.0.0.1` 临时端口，客户端使用 Python http.client，不经过代理。HTTP 认证保持默认开启，未传 `-a`，CORS 未传 `-X`。结束后只终止自身进程，临时测试状态删除，原候选/ACL/运行时摘要再次核实。

原候选 ACL 逐字复制。另加独立测试 ACL：匿名会话仅获 session.login，两个测试账户额外获销毁自身 session 的权限，用于经真实 HTTP 登录和退出；它不授予任何额外 homegate_ddns 方法。测试口令固定且只用于夹具，随机会话标识不写进输出、断言正文或报告，登录响应仅在内存中处理。

## 十项 HTTP 检查

- 核实回环监听、HTTP 静态夹具、未启用免认证/CORS，OPTIONS 不返回跨域许可头。
- 匿名、无效和空会话分别调用八方法，均获 JSON-RPC Access denied，区别于业务回调的拒绝对象。
- 真实 HTTP 登录只读账户：status/jobs 进入候选并返回关闭门禁对象，六个写方法在派发前拒绝。
- 真实 HTTP 登录可写账户：八方法通过会话授权，仍返回精确七字段关闭门禁对象；submit 为 unknown，其余 none，全部 write_ready:false。
- 错误口令/不存在账户不能登录；经 HTTP 销毁会话后，八方法全部拒绝。
- 授权后的未知字段、字符串字段错误类型、未知对象/方法、错误 JSON-RPC 方法、缺失参数及损坏 JSON 按固定实现拒绝。
- 业务参数夹带 ubus_rpc_session 被拒绝；匿名/只读会话不能借夹带的可写会话升级权限，旧式 JSON-RPC 的 Bearer 头也不能覆盖 params 中的会话。
- 同一批量请求逐元素验证权限：允许的只读、禁止的写、无效会话及错误参数分别返回各自结果和请求 id。
- `/ubus/call/homegate_ddns` 的 Bearer 入口同样核实只读/可写/无效会话与会话字段注入拒绝；响应格式与旧式 `/ubus` 分别核实。
- GET/PUT/DELETE 不能作为旧式 `/ubus` 调用；带外部 Origin 的只读写请求仍拒绝，且不返回跨域许可头。

旧式 `/ubus` 对业务 ubus 结果使用 result 数组，协议/权限错误使用 error；Bearer 入口成功使用 result 对象。测试明确区分 HTTP 200、RPC 授权通过和候选业务拒绝，不能把 HTTP 200 当成授权或写入成功。没有跨域许可头也不等于 LuCI CSRF 已通过；实际控制器会话与 POST/CSRF 仍须单独验证。TLS 未编译，因此本轮不报告 HTTPS 或传输凭据保护通过。

实现依据：[固定 OpenWrt uhttpd 配方](https://github.com/openwrt/openwrt/blob/v25.12.0/package/network/services/uhttpd/Makefile)、[固定 uhttpd HTTP/ubus 实现](https://github.com/openwrt/uhttpd/blob/ebb92e6b339b88bbc6b76501b6603c52d4887ba1/ubus.c)、[固定 uhttpd 构建选项](https://github.com/openwrt/uhttpd/blob/ebb92e6b339b88bbc6b76501b6603c52d4887ba1/CMakeLists.txt)、[r82 的 RPC 与 ACL 入口](DDNS候选rpcd与会话ACL验证.md)。

r84 新增独立的[Lua LuCI CGI会话与POST/CSRF宿主入口](LuaLuCI会话与CSRF宿主验证.md)。本页十项仍是uhttpd HTTP/ubus范围；固定Lua基线不能代替目标09ae68b源码及兼容性确认，TLS/设备验收仍待完成。
