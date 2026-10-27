# HomeGate 独立DDNS合同与网页工程包（r141）

## 网页入口

安装后的“服务 → HomeGate 工程验证”可进入“账户、规则与凭据”和“DDNS 授权与任务”。先初始化，逐项预览/确认账户和规则，保存私有凭据，再预览/确认当前配置发布；然后在 DDNS 页面预览并明确授权所选规则，再单独提交异步任务。密码输入不回显，不自动代填旧秘密；配置或凭据变化不会沿用旧授权。

写接口只接受已登录会话的 POST/CSRF 请求，有界私有请求文件以700/600权限传给固定后端，值不进入命令参数；网页以原生 LuCI/Bootstrap 结构和 DOM textContent 展示。任务结果未知保留原证据，不自动重试；已确认结果的维护仍要求预览和确认。页面和任务不会自动启动服务。

凭据更新已修复投影来源继承：仅在持有写锁、固定源仍逐字节等于已发布公开配置时，继承经既有manifest验证的来源证明；源变化拒绝且不发布新代际。配置确认中断返回原绑定句柄，可显式续完，不丢弃持久屏障。

## 手动 DDNS 工程入口

r139 在 r138 实际手动 DDNS 三包上接通原生 Lua 配置/凭据网页及明确授权/异步任务。Core、原生 Lua LuCI 网页、中文 LMO 三包同版本；纯 Shell/Lua，all 架构，无 Go 或目标原生 ELF。

命令 /usr/bin/homegate-engineering；私有数据 /etc/homegate-engineering/transactions；运行状态 /var/run/homegate-engineering；独立 UCI 源文件 /etc/config/homegate_engineering（600，conffiles 保留）。不读写旧 /etc/config/homegate 或 /etc/homegate，不替换 /usr/bin/homegate。新增独立 /etc/init.d/homegate-engineering 与 iface/95-homegate-engineering；不生成开机链接，不自动启动或清理用户数据。init 的 boot 明确不派发，start --confirm 只启动一次有限会话（SDK无确认调用start无业务动作）；不是已完成的持续生产 daemon。

## 手动业务链

下面是工程入口合同，实际目标安装另按授权执行。先在独立源文件中配置六类合法 UCI（DNS account 包含 provider 和所需凭据、DDNS rule 引用该 account，并设置 zone/host/source）。不要把秘密放进命令参数或环境。

1. prepare：创建独立的私有空基线；中断初始化使用 prepare-resume，不删除重来。
2. import-preview：捕获固定独立源文件，预览迁移；import-commit <confirmation> 明确确认。仅允许首次空基线导入，原始秘密进入私有保险库；预览不能产生 DNS 写入。
3. activate-preview：预览普通配置投影；config-commit <confirmation> 连续完成绑定提交、公开投影与观察收尾。公开源中总开关/业务开关保持关闭，秘密被移出。config-finish <apply_handle> 仅续完同一已绑定事务；失败保留原事务，不能换源重试。配置变更用 config-preview 的标准输入及 config-commit；config-export 不导出秘密，config-cancel 取消待确认预览。
4. grant-preview <rule> / grant-commit <confirmation>：对当前配置代际中的指定单条规则授予 DDNS 权限。预览、旧配置的授权或源文件开关均不能代替确认。grant-cancel 取消预览，grant-revoke --confirm 撤销授权。
5. ddns-sync <rule>：执行 Cloudflare / Aliyun / DNSPod / 华为云 AAAA 同步；ddns-status <rule> 读取有界状态。未授权、待恢复、并发或节流等待返回 4，并可附 ok=true 的状态报告；ok=true 只说明状态可读，不能当作执行成功，必须同时检查退出码、phase/result/effect。
6. 成功写入保留原始回执。ddns-reconcile <provider> <account> <job> --confirm 只读核对；ddns-collect-receipt 同参数只归档已确认原始回执。ddns-collect-work <job> --confirm / ddns-collect-orphan <provider> <account> <job> --confirm 收集经原证据绑定且已静止的残留；ddns-retire-archive 同 provider/account/job 参数退役原归档。结果未知不重发、不凭“记录现在存在”伪造成功，不删除凭据或日志强行放行。

secret-put <provider> <account> <slot> 从标准输入更新秘密槽（key_id/secret/account_id/endpoint），不接受值参数。它改变配置代际；之后须重新投影并明确授权，旧授权不沿用。

版本、四家 DNS/CA 目录、check-stdin 有界六类完整配置校验继续提供。LuCI 已有账户/规则编辑、私有凭据、预览确认、明确授权和异步任务/回执维护页面；本轮接入一次有界自动调度与网络事件，完整持续 daemon 尚待 WP03 后续接合；ACME、代理/访问/防火墙、WOL 属于其余既定工作包。

## 构建及验收边界

scripts/engineering_runtime.py 只在安装副本中按固定清单打开此工程业务所需门禁并搬迁固定路径；schema/协议名不改。原生产配方与原型默认门禁保留。所有提供商共用一个 IPK，内部选择对应的回执格式，避免单提供商试验门禁互斥。

依赖 Lua 5.1、luci.jsonc、curl/CA、OpenSSL CLI、flock、coreutils-stat、ip-full、ubus 与 BusyBox 所需 applet（含 fsync/setsid）。SDK 已确认 fsync/flock/setsid 默认开启，stat 由显式包依赖提供；目标固件缺少必须工具时入口拒绝创建业务状态。QWRT 组件、Lua/LuCI 接口及真实 opkg/HTTP/设备运行仍未验收，不据宿主 chroot 推断兼容。

构建入口 scripts/工程三包构建.py 校验官方 SDK SHA、新工作/输出目录及同源三包；scripts/工程三包验收.py 核对实际安装字节和只读入口；scripts/工程DDNS安装回归.py 在一次性 chroot 中执行包内原始业务字节，网络/工具边界连接四家本地 TLS 模拟服务。未调用真实 DNS 或部署路由器。完整产品及正式发布门禁继续独立。

DDNS 缓存的手动重置入口为 ddns-reset <rule> --confirm；仅清除可重建的节流历史，存在持久恢复屏障时拒绝，不能以此放行未知写入。

## 一次有界自动调度与网络事件

网页按钮或 CLI schedule-start --confirm 仅在已有当前配置的明确 DDNS 授权、静止恢复状态下启动；至多900秒/8批次，启动不授予新权限。schedule-status 只读；schedule-stop --confirm 合作停止，已进入的批次完成后结束；schedule-reap --confirm 仅回收已静止且无持久DNS屏障的控制记录。不会自动归档/退役回执或自动再开一轮。配置/凭据发布要求调度静止，停止/查看和显式撤权继续可用。

iface hook 仅将 ifup/ifupdate/ifdown 的有界接口信息交给当前会话；无会话不创建运行目录或派发业务。事件按租约绑定的不可变配置匹配WAN或指定设备，唤醒不改变租约/截止时间/次数或绕过每规则节流；接口断开合作停止，不与已进入批次争夺业务锁。每次真正派发仍重新核对代次、库、授权、来源和持久屏障。旧授权/已结束会话不会被网络事件恢复。控制锁占用期间只暂停新派发并继续原时限，不能把一次唤醒误当停止。

SDK生成的默认postinst会尝试enable/start；本包init不提供开机启用，且start无--confirm时直接返回，不派发任务。自定义prerm只请求合作停止并核对静止/持久屏障；活跃会话或未核对DNS状态返回4阻止删除执行文件，不清理配置/秘密/回执。普通安装/升级不自动再授权或重开调度。


## 账户、区域和删除入口

账户行提供“校验凭据”“发现区域”，使用已发布普通配置与私有凭据；不要求 DDNS 写权。CLI 为 dns-provider-status <account>、dns-zones <account>，保留原四家分页、失败清空、签名/TLS 和来源绑定。网页网络请求使用登录后的 POST/CSRF，响应有大小限制，超限明确拒绝而不返回部分区域。

ddns-delete <rule> --confirm 删除当前规则精确主机的全部 AAAA，TXT 和其他主机保持；不采样 WAN。必须有当前代次的明确规则授权，且调度已静止并无未决恢复屏障。网页删除另有确认框，不接受外部主机、地址、URL 或文件路径。成功保留原提供商回执，未知不重试、不卸载清除；维护沿用原显式核对/归档通道。删除只处理云记录，不删除本地规则，也不会自动撤销规则或启用持续服务。
