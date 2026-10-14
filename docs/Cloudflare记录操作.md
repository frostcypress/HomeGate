# Cloudflare 配置绑定记录操作（r30）

原型沿用 r28/r29 的 HGPRIVATE1、FD6/7 共锁、持久配置屏障、固定 curl 7.83.1 传输和独立会话监督。固定 `account --records`，额外 `dns_records_enabled=false` 记录门禁与既有只读门禁同时存在，三个固定入口均关闭；环境变量不能启用。生产配方不安装原型，没有连接真实 Cloudflare。

## 私有操作与配置绑定

操作从 stdin 私有管道进入，与私有快照分开：原始操作 FD4、快照 FD0，独立监督保存快照 FD5 后启动子进程。操作读取也在 30 秒监督范围内，不能用未结束 stdin 永久持锁。单包最多 4096 字节，要求共享 backup.json 的排序/转义 canonical JSON 加 LF、无重复键/NUL/额外文档。没有命令、路径、URL、provider/Token、记录 ID/TTL/任意名称等字段。

示例字段为 operation（upsert/delete）、kind（ddns/dns01）、resource（配置节名）、value；dns01 另有 domain，DDNS 空值删除另需显式 all=true。实际调用必须由未来受官方授权的确认操作或业务任务生成；本阶段没有生产 LuCI 写入口或自动 DDNS/ACME 调度。

同代快照核对账户/代次和原资源：AAAA 的账户/zone/host/type/TTL 来自 DDNS 规则，DNS01 的账户/zone/domain 来自 ACME 证书，domain 必须是该证书配置成员，通配符去星后产生固定 `_acme-challenge` 名称并验证属于区域。此手工隔离原型不以导入后已关闭的总开关自动运行服务。A 类型返回 unsupported，原 schema/Go 对照仍完整保留，不能据此认定业务迁移完成。

IPv6 有界解析并用展开后的 8 组数值身份比较，支持 IPv4 映射，拒绝多重压缩、单边多余冒号、zone scope 和无效地址。TXT 挑战值非空且只接受可打印 ASCII，引号/反斜线/Shell 字符作为数据经 JSON/Curl 双层转义；已有其他 TXT 的 Unicode 内容不回显。TTL 来自配置，支持 1 自动或 30..86400，30 的供应商 Enterprise 权限仍由 API 判定，不擅自调整。

## 分页与记录隔离

先以固定 name 参数解析配置区域；全部页读完且只有唯一匹配 ID 才查询记录。记录查询固定 name/type，100 条/页、最多 1000 页/100000 行；可选 result_info 与 r29 共用分页校验，满页缺元数据必须继续。私有上下文最大 8 MiB、每次完整 HTTP/transport 帧 64 KiB、总监督 30 秒，容量/时间越界失败，决策前不截断或部分成功。这些理论上限尚未取得 QWRT 峰值/预算依据。

供应商列表的每条记录都须核对 ID、实际名称、类型和内容，不能只信任 query 过滤；同页/跨页重复 ID 拒绝。AAAA 有任何等价值则 unchanged；否则对 API 顺序的首条已有记录做更新，无记录才创建。TXT 已有相同值则 unchanged；不同值保持不动，新值另建。完整分页后才决策，无法确认后页时没有变更。

AAAA 用官方 PATCH 只传 content/ttl，保留既有 proxied/comments/tags/settings，避免旧 PUT 覆盖无关字段。更新前 GET 核对同一 ID/范围和未变更内容。TXT/AAAA 按值删除只收集匹配 ID；DDNS 全删必须显式空 value + all=true，TXT 禁止全删。删除前逐条 GET 再核对名称/类型/内容；已不存在可视作幂等完成，其他值变化则拒绝。

创建/更新须同时核对变更响应与随后固定 ID GET 的名称/类型/内容；删除须核对响应 ID 并在 GET 404 后累计确认数量。没有 supplier CAS 条件，因此 GET 到 PATCH/DELETE 之间的外部并发窗口仍存在；不冒充多记录原子事务、TTL/代理设置生产兼容或 DNS 传播完成。

## 未知结果与证据

七个 0600 单链接槽位位于原 0700 工作目录：request/result/zones/state/input/context/attempt。Token/值只在私有槽位，curl 配置包含固定 URL/方法和有界 JSON body，argv/env 无凭据或挑战值，Curl 子进程关闭上下文/input/attempt 等 FD。Lua 只做数据校验与编解码，不执行 HTTP 或 Shell。

POST/PATCH/DELETE 前写固定 HGCFATTEMPT1 标记；不自动重试。随后 HTTP/TLS/超时/无效响应/回读失败属于保守 unknown，retryable=false、reconciliation_required=true；affected 只计已确认的结果，部分删除不返回全成功。协调器重新验证 canonical 公共结果、账户/代次、退出状态以及真实 attempt 槽，不能通过伪造 none/成功报告丢弃变更痕迹。

未知结果保留自己的私有同启动期槽位，阻止后续所有 DNS 请求；不把凭据、内容、记录 ID、域名或供应商消息放入公开结果。已有原生配置写入在家族安静后仍可进行，这**不是生产持久业务写屏障**。尚无生产持久回执、明确核对/恢复接口或冷启动收集；重启不能据 /var/run 恢复远端操作结论。这些是关闭生产门禁的实际缺口，未来实现前不能安装启用。

## 本阶段验证

5 项新增本地通过。30 项新增 Linux 及全部既有回归待当前 Actions。用实际私有帧、BusyBox ash、Lua51/jsonc、固定官方 curl、临时 CA/loopback TLS 和可丢弃记录数据库验证：AAAA/TXT 创建/重跑、等价 IPv6、PATCH 元数据保留、按值/显式全删、跨页重复值、完整分页/范围异常、删除前并发变化、HTTP 已变更但失败、超时、伪响应、回读失败/部分删除、TLS与共锁、curl argv/env/FD、未结束输入、父 SIGKILL 与关闭门禁。SIGKILL 故障明确使用仅夹具的 curl 包装器，不把它当成真实供应商网络证据。

当前记录源码和普通协议说明可公开；详细运行/失败记录、当前三份 MD 与完整 ZIP 仅本地。生产四家 DNS、自动 DDNS/来源采集、完整 ACME/代理/WOL/防火墙、受确认迁移/生产生命周期/冷启动、SDK ABI/三包/设备与资源仍待完成。High 开发及发布前 Ultra 提醒、一次终审/有限局部优化边界继续继承。

## 官方依据

[List DNS Records](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)、[Create](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)、[PATCH](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/)、[Delete](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/delete/)：固定方法/路径、完整记录名称、TTL 和权限；[curl](https://curl.se/docs/manpage.html)：私有配置、data-binary/TLS/协议与超时。原行为参考 internal/dnsprovider/cloudflare.go，DNS01 TTL=600 与按值清理参考 internal/acme/service.go；没有把历史成功当作本轮验收。
