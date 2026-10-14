# Cloudflare 私有只读业务适配

r28 增加 `homegate-cloudflare-read.sh <account-id>` 未安装原型。固定源码门禁关闭，不能由环境或额外参数启用。它读取已有 `/etc/homegate/transactions` 的同代公共配置和私有槽，复用 FD6 共享写锁、FD7 监督锁、现有 writer-check/snapshot-read；未知、未完成应用、错误存储或活锁都拒绝 HTTP。保留原始配置/凭据，读取不分配配置代次、不发布业务状态、不关闭恢复屏障。

本阶段只实现 Cloudflare 的只读 ValidateCredentials 方向：固定 GET `https://api.cloudflare.com/client/v4/zones?page=1&per_page=1`。旧 Go `ValidateCredentials` 同样调用区域列表第一页、每页一项；[Cloudflare 区域列表](https://developers.cloudflare.com/api/resources/zones/methods/list/) 使用 Bearer token 并支持分页。它证明这次区域读取请求成功，不证明 DNS Edit/TXT 写权限，也不是完整区域发现、AAAA 更新/删除、DNS-01 或其他三家服务商迁移完成。旧 factory 对 Cloudflare 只用 secret，endpoint 自定义只在 Huawei factory 中使用；本原型不接受外部 URL 或命令。

Shell 负责 HTTP 调度，Lua 仅作既有私有帧/配置和官方 JSON 解析及数据编码。私有 snapshot 经继承管道交给读取端，先核对预期代次、账户和 Cloudflare provider。缺秘密、二进制/控制字符、错账户或代次不发请求。令牌以受限运行目录 0700 和单链接 0600 的临时 curl 配置传递；引号/反斜线按 curl 配置格式转义，令牌不加入 argv 或应用环境。传输进程关闭配置/写锁，独立看门人保留共享锁到工作族静止。临时配置在正常失败/成功且工作族结束后删除。

curl 的首个选项为 --disable，固定 HTTPS 协议、禁用重定向和代理、固定系统 CA、连接三秒/请求十秒。不使用 insecure，不接受 CURL_CA_BUNDLE/代理/curlrc 的路径和安全覆盖。十秒是未安装原型的单次上限，用于限制共享锁持有时间；原正式 CLI 的十五秒上下文/底层二十秒和实际网络预算仍待迁移核对，不将本值当成已冻结的实机预算。参考 [curl 配置与 --disable 文档](https://curl.se/docs/manpage.html)，旧 7.83.1 源码接口另外核对。64 KiB 是完整响应/结束帧的字节上限；Lua 有界读取并关闭超过上限的流，不能依赖旧 curl 的 --max-filesize 处理未知长度或 chunked 数据。所有原始 stderr 被抑制，不公开供应商 message、请求/签名、header、响应正文、区域/账户元数据或本机路径。

成功需要 curl 退出 0、实际 HTTP 2xx、单一完整 JSON、布尔 success=true、合法 result 数组；空区域列表也可通过读取权限检查。复用官方 luci.jsonc 增量解析确认完整单文档，并逐层拒绝解码后重复键、NUL 与尾随内容；词法重复键检查不代替官方语法解析。失败保留 authentication/rate_limit/temporary/not_found/timeout/network_unavailable 等稳定分类及安全数字代码；不回显供应商文本。父协调器再次校验固定公共结果及退出码一致，空结果/虚假退出成功不算通过。

独立监督复用已有 `homegate-service-observer-watchdog.sh` 新的只读分支，固定三十秒加一秒终止宽限，不另建监督系统。服务观察/动作原来的五秒期限不变。信号仅作用于当前活看门人自身会话组；配置读取端和请求均为受信任固定代码。调用者 SIGKILL 后普通工作族仍受期限及 FD6/7 约束。中断可能留下 0700/0600 的孤立临时请求目录；下一次 DNS 检查拒绝复用/清理该目录，避免无界积累。冷启动/显式安全孤立清理、双重杀死看门人、逃逸会话或永久不响应 I/O 尚未验证，不能据此开放生产路径。

本地 5 项通过：实际 Lua 5.1 私有帧/编码、缺秘密/二进制/换行/代次/账户拒绝、固定门禁/语法与 TLS 参数。初次本地数据检查因 Windows 中文路径不能由 Lua C loadfile 打开而失败，夹具改为注入已加载的真实配置/读取模块后通过；产品路径校验未放宽。

20 项 Linux 及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38503054242)；实际源码 `b37eb5a719cacd373f7bbabe387dfa379e83f526`，64 个关键文件逐字节核对，SDK/发布跳过。Linux 使用复制路径/UID/gate、官方 BusyBox 1.33.2、Lua51/jsonc、真实管道/锁/进程/HTTPS 和真实 curl 7.83.1；curl 官方 archive SHA256 固定 `2cb9c2356e7263a1272fd1435ef7cdebf2cd21400ec287b068396deb705c22c4`，来源 https://curl.se/download/curl-7.83.1.tar.xz。宿主构建链接宿主 OpenSSL，不是 QWRT OpenSSL ABI 构建；构建只供测试，未替换目标系统 curl。自签名证书仅作为本地夹具的明确 CA；没有使用真实 Cloudflare 账号，没有访问公网 API 或修改 DNS 记录。

20 用例覆盖成功/空列表、错误分类、消息反射、恶意/重复/转义键、错误结果类型、重定向、TLS CA、curlrc/代理/环境、声明大小/chunked 上限、真正 curl 超时、凭据权限/argv、共享锁/未完成事务、错误依赖、源门禁/参数、虚假工作成功和调用者丢失。生产门禁/全部业务/ABI/三包/设备资源尚未完成，详细记录/当前三份 MD/完整 ZIP 仅本地。

下一步在这个通道上扩展 Cloudflare 区域发现和 AAAA/TXT 操作，核对幂等/记录隔离/凭据不泄漏，再迁移另外三家认证及 ACME、代理/WOL/防火墙、完整生命周期和 SDK/设备验收。开发继续 High，满足发布前置条件再提醒 Ultra。

## r29 后续参数修正

现行官方 List Zones 要求 per_page 最小 5，本轮将只读检查从 1 改为 5，并保留 r28 历史记录。完整区域分页实现与本轮验证见 Cloudflare区域发现.md；AAAA/TXT 操作尚未完成，生产门禁仍关闭。
