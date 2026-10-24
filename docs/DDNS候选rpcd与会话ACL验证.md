# DDNS 候选 rpcd 与会话 ACL 验证

本入口使用真实 Linux 宿主 rpcd、ubusd、ubus CLI 和 r81 的 libucode/fs，加载原候选 `homegate-ddns.uc` 与 `ddns-acl.json`。`native_ddns_rpc_enabled=false`，生产配方仍不安装候选。本次覆盖脚本注册、参数过滤、关闭门禁响应，以及真实 session.login/access/destroy 对候选 ACL 的解释；HTTP/LuCI 授权与 CSRF、目标 ABI、设备验收仍需分别完成。

## 运行方式

需要 Python 3.12+、C 编译器、make、CMake、pkg-config、json-c/libcrypt 开发库、zstd、bubblewrap，以及可用的非特权 user/mount/network namespace。以普通用户执行：

```sh
sh scripts/check-rpcd.sh
# 或复用已验明摘要的两个既有运行时：
sh scripts/check-rpcd.sh /absolute/path/to/rpc-runtime /absolute/path/to/ucode-runtime
```

默认目录为 `build/rpcd` 与 `build/ucode`。准备脚本只在该目录构建固定源码，不安装系统软件；已有构建复用前核实四份源归档、安装文件与符号链接摘要。未完成构建保留，另选新目录。rpcd 构建只启用 ucode 插件，复用既有 libucode/fs 原字节；其头文件从已验证的 ucode 源归档提取。未启用 file/iwinfo/sys 插件。

四组件来源为 OpenWrt v25.12.0 的包配方，完整提交及归档 SHA256 固定在 `prepare-rpcd.py`：libubox `1aa36ee7`、ubus `3cc98db1`、uci `66127cd7`、rpcd `ffb9961c`。ucode 沿用 r81 的 `85922056`。官方源归档名使用 `日期点分~短提交.tar.zst`。这是宿主验证组合，不表示旧 QWRT 的组件版本或 ABI 已匹配。

## 隔离与权限边界

外层构建和启动都使用普通用户。bubblewrap 创建独立 user、mount、PID、network 等命名空间，把外层唯一非 root UID 映射为内部 UID 0，并移除全部 capabilities；测试逐字核实 uid_map。原版 ubusd 按 OS 身份控制本地总线发布/调用，此处使用命名空间内的管理身份驱动总线。这个映射不授予宿主 root 权限，也不是候选的 session ACL。

源目录和运行时只读挂载，`/etc` 使用私有测试用户及 rpcd 配置，`/var`、`/tmp`、总线 socket、会话状态均独立；网络空间没有外部路由，业务后端不存在。原候选和 ACL 逐字复制，结束后核实原字节与运行时摘要不变。测试只终止自己启动的两个进程，临时状态随后删除。登录使用固定测试口令，随机会话标识只保存在进程内存和测试调用中，不写入报告或断言正文。若 namespace 不可用则明确失败，不改用宿主配置，也不自动放宽系统限制。

rpcd 的 ucode 参数校验会检查已声明字段类型、拒绝未知字段，且专门允许字符串 `ubus_rpc_session`；它不会因此替 HTTP 传输层调用 session.access。八方法在关闭门禁下，即使直接本地总线携带只读或无效会话，也只返回候选拒绝对象。因此 **session.access 的授权结果与直接 ubus 的派发结果是两项独立证据**，不能把本地总线通过写成 HTTP 权限通过。后续 HTTP 入口必须在派发前验证会话权限，不能信任客户端提交的会话字段。

## 八项检查

- 私有网络、UID 映射、只读挂载、私有配置、业务后端缺席及显式关闭门禁。
- 真实总线上八个方法及参数签名与合同完全一致。
- 八方法分别以完整字符串参数和空参数调用，返回精确七字段拒绝对象；submit 保留 unknown，其余 none，均 write_ready:false。
- 未声明字段、各字符串参数的布尔/整数/数组/对象/null 类型、未知方法均被 rpcd/ubus 拒绝；按固定 CLI 的负状态退出码及错误文本核实。
- 只读测试会话仅允许 status/jobs，拒绝六个写方法。
- 可写测试会话允许八个方法，拒绝未知方法。
- 匿名会话全部拒绝、无效会话不存在、错误口令/用户拒绝登录、销毁后的会话不可访问。
- 只读及无效会话直接调用本地总线仍能派发至关闭门禁回调，证明其不能代替 HTTP 授权；非字符串会话字段被参数校验拒绝。

CI 已接入相同入口，按项目集中周期执行；本地成功不能记为远端成功。命令源码与边界依据：[OpenWrt v25.12.0](https://github.com/openwrt/openwrt/tree/v25.12.0/package)、[固定 rpcd ucode 插件](https://github.com/openwrt/rpcd/blob/ffb9961c1f8bc50830fdd4e144570f11062c2601/ucode.c)、[固定 rpcd session 实现](https://github.com/openwrt/rpcd/blob/ffb9961c1f8bc50830fdd4e144570f11062c2601/session.c)、[固定 ubusd OS ACL](https://github.com/openwrt/ubus/blob/3cc98db1a422dcf560f2d6347fd410f17565a89d/ubusd_acl.c)。

r83 增加独立的[真实 HTTP 会话授权验证入口](DDNS候选HTTP会话授权验证.md)，实际运行 uhttpd/ubus/session.access；本页八项仍只报告本地总线范围。Lua/LuCI 控制器、CSRF、TLS 及目标设备验收继续独立。
