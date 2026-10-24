# Lua LuCI 会话与 POST/CSRF 宿主验证

`scripts/check-luci.sh` 使用真实 uhttpd CGI、Lua 5.1、LuCI dispatcher/http/模板及 nixio、rpcd 会话。原页面、DDNS 模型和共用 writer 的门禁保持关闭。本文所述 `luci-ddns-regressions.py` 验证只在独立 namespace 中向临时副本开放路由或模型，用计数夹具代替业务后端；不执行配置写入、服务动作或 DNS 操作。r85 同一入口另接入 [真实 Shell 只读链路检查](LuCI与ShellDDNS只读链路验证.md)，其私有配置初始化和业务读取范围独立说明。

## 来源与入口

目标历史包记录为 LuCI `git-26.067.15087-09ae68b-1`，但该短提交尚不能映射到官方仓库；当前目标 SDK/ABI 和实际 LuCI 接口证据仍未核实。本入口固定官方 openwrt-21.02 分支提交 `e4c46338b196e486a88b1a75b78e283708c82bc4` 建立宿主基线，**不代表 QWRT 的对应源码或兼容性已确定**。

```sh
sh scripts/check-luci.sh
# 显式复用时，参数依次为 LuCI、HTTP、RPC、ucode 运行时：
sh scripts/check-luci.sh /absolute/luci-runtime /absolute/http-runtime /absolute/rpc-runtime /absolute/ucode-runtime
```

以普通 Linux 用户执行。除 r83 已有工具外，需要 Lua 5.1 解释器与开发库；脚本只检查缺项，不安装系统软件。固定 LuCI 归档 SHA256 为 `964157d74b0690ea5f9ed8b09284315cabe9edc74e451422dea5875a890e912f`（固定 GitHub HTTPS 提交归档下载后冻结，并非目标供应商签名）。lucihttp 固定为该分支配方的 `3dc89af4`，libnl-tiny 固定为 OpenWrt v25.12.0 的 `40493a65`，二者官方镜像摘要写在 prepare-luci.py。ubus Lua 绑定从已验证的 r82 ubus 归档独立提取，链接原 RPC 库，不重编或更改它们。

准备器在私有目录构建 nixio（无 TLS）、模板解析器、jsonc、IP、lucihttp 与 ubus Lua 模块；保留源归档、日志、完整安装文件/符号链接摘要，并绑定既有 Lua 解释器与 RPC 产物。运行时默认 `build/luci`，另三个默认目录沿用 r81–r83。未完成构建保留，另选新目录。摘要一致才复用。

## 真实模块与夹具的分界

dispatcher、HTTP/form 解析、Cookie/会话验证、POST/CSRF 判断、模板解析、nixio 文件操作和 rpcd session.login/set/get/access/destroy 都是真实固定实现，没有以 package.preload 替代它们。CGI 使用现有 uhttpd 的 CGI 通道，不需要启用其 Lua 插件。测试通过真实 LuCI 登录表单取得 Cookie，原候选模板输出的 token 必须等于真实 rpcd 会话中的 token；随机 Cookie/token 仅在内存及私有请求中使用，不输出到报告或断言正文。

隔离夹具只提供最小 admin 父节点、主题展示模板、私有 UCI 配置，以及独立的探测路由。页面控制器的临时副本只改 page gate；通常使用原关闭的业务模型。单独的模型探测路由刻意绕过 dispatcher 的 post 包装，以测试模型自身的冗余 POST/token 检查；只有这项控制在临时模型副本中开 gate。另一个控制临时打开共用 writer 副本。两个固定假后端只读取临时请求的目录/文件权限，记录常量计数，返回无效业务响应 `{}`，不读取请求内容，不代表业务成功。

外层非 root 用户映射为私有 namespace 内 UID 0，capabilities 全部移除并核实 CapEff/CapPrm/CapBnd 为零；网络只用私有回环。源码/工具只读，控制器、模型和假后端仅在私有挂载中替换，所有原字节及运行时摘要在结束后再核。测试账户用于单一管理员会话语义，不验证多角色 Lua 菜单 ACL；不报告目标浏览器、HTTPS、设备、资源、安装或完整业务链路通过。

## 十一项检查

- 原候选门禁均 false；实际 LuCI 路由树没有注册候选页面，隔离 UID/capability/只读挂载正确。
- 未登录及错误口令拒绝，真实登录返回 SameSite=Strict/HttpOnly Cookie；原页面 token 与真实会话绑定。
- 无 Cookie、无效 Cookie及自报 authorized/token 的八方法请求拒绝。
- 已认证 status/jobs 不需要 CSRF，仍返回精确关闭门禁对象。
- 六个写方法的 GET 均返回 405 和 Allow: POST。
- 六个写方法缺 token、错误 token、其他会话 token、重复 token 均 403。
- 正确 Cookie/POST/token 可到达回调，但业务门禁仍返回 503 和精确拒绝对象，submit 保留 unknown。
- 表单中的会话字段和授权标志不能替代 Cookie。
- 经真实 rpcd 销毁后，旧 Cookie/token 的八方法请求均拒绝。
- 临时开启的模型在独立 call 探测路由上拒绝错误方法/token，且不触及假后端；正确 POST/token 才增加一次固定计数，随后仍拒绝无效业务结果并清理私有文件。
- 共用 writer 原门禁先拒绝；临时开启副本才到达权限计数夹具，实际目录为 0700、文件为 0600，随后拒绝无效结果并清理。

## r84 原生权限接口修复

真实 nixio 将 mode 参数按八进制字符串解析。旧 DDNS 模型及共用 writer 传入十进制 `448/384`，会被视作包含非法八进制数字的文本，导致 mkdir/open 报错；早期 Lua 边界夹具也错误接受了这些数值。r84 将两处传输的参数改为 `'700'/'600'`，并更正对应旧夹具预期；真实计数夹具使用 stat 核实实际权限，不放宽隔离或门禁。其余生产逻辑、路由、ACL 和配方不变。

本入口已接入集中 CI 配置，本地通过不表示远端 CI 成功。依据：[固定 LuCI dispatcher](https://github.com/openwrt/luci/blob/e4c46338b196e486a88b1a75b78e283708c82bc4/modules/luci-base/luasrc/dispatcher.lua)、[固定 nixio 权限解析](https://github.com/openwrt/luci/blob/e4c46338b196e486a88b1a75b78e283708c82bc4/libs/luci-lib-nixio/src/fs.c)、[固定 lucihttp 配方](https://github.com/openwrt/luci/blob/e4c46338b196e486a88b1a75b78e283708c82bc4/contrib/package/lucihttp/Makefile)。
