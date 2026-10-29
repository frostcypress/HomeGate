# HomeGate 独立DDNS合同与网页工程包（r142源码）

## r151 私有代理组件和集中CI入口（2026-10-29，当前源码）

工程代理及证书候选验证器统一调用 `/usr/libexec/homegate-nginx/nginx`，核心依赖独立原生 `homegate-nginx`，不使用或替换系统 `/usr/sbin/nginx`。nginx 1.30.6固定归档、交叉补丁、目标配方与必要构建流程见 `../components/homegate-nginx/README.md`；目标TLS依赖/完整组件/nixio及实机仍待验，不能把最小交叉探针视作完整支持。最近实际三包仍r141，当前r151未出包。

新增工程CI分9组，完整覆盖工程网页35场景和代理14场景；固定准备宿主运行时，保留单UID/cap-drop ALL及原每场景90秒边界，失败阻断后续构建。不因第10步例行构建三包。本步本地验证后才标CI到期，下一次继续单独投递，尚不代表远端CI已通过。


## 构建时机（2026-10-28用户更新，优先执行）

工程三包仅在实机验证前或确有必要通过构建验证时按需构建，平时不构建，第10步不固定构建；10步CI节奏独立。必要构建先记录问题、源码检查不足原因及最小范围，仍核对同源/版本/依赖/实际安装内容和SHA。当前源码r150、最近实际三包r141；以下阶段说明中的“第10步集中构建”属于历史计划，已由此规则取代。目标nginx/nixio来源、版本、安全、ABI及worker权限仍待验证，不能降低门禁或拿宿主通过冒充目标支持。


## 网页入口

安装后的“服务 → HomeGate 工程验证”可进入“账户、规则与凭据”和“DDNS 授权与任务”。先初始化，逐项预览/确认账户和规则，保存私有凭据，再预览/确认当前配置发布；然后在 DDNS 页面预览并明确授权所选规则，再单独提交异步任务。密码输入不回显，不自动代填旧秘密；配置或凭据变化不会沿用旧授权。

写接口只接受已登录会话的 POST/CSRF 请求，有界私有请求文件以700/600权限传给固定后端，值不进入命令参数；网页以原生 LuCI/Bootstrap 结构和 DOM textContent 展示。任务结果未知保留原证据，不自动重试；已确认结果的维护仍要求预览和确认。页面和任务不会自动启动服务。

凭据更新已修复投影来源继承：仅在持有写锁、固定源仍逐字节等于已发布公开配置时，继承经既有manifest验证的来源证明；源变化拒绝且不发布新代际。配置确认中断返回原绑定句柄，可显式续完，不丢弃持久屏障。

## 手动 DDNS 工程入口

r139 在 r138 实际手动 DDNS 三包上接通原生 Lua 配置/凭据网页及明确授权/异步任务。Core、原生 Lua LuCI 网页、中文 LMO 三包同版本；纯 Shell/Lua，all 架构，无 Go 或目标原生 ELF。

命令 /usr/bin/homegate-engineering；私有数据 /etc/homegate-engineering/transactions；运行状态 /var/run/homegate-engineering；独立 UCI 源文件 /etc/config/homegate_engineering（600，conffiles 保留）。不读写旧 /etc/config/homegate 或 /etc/homegate，不替换 /usr/bin/homegate。新增独立 /etc/init.d/homegate-engineering 与 iface/95-homegate-engineering；不生成开机链接，不自动启动或清理用户数据。init 的 boot 明确不派发，start --confirm 明确启动工程持续调度（SDK无确认调用start无业务动作）；完整启用意图消费与生产命名空间接管仍待。

## 手动业务链

下面是工程入口合同，实际目标安装另按授权执行。先在独立源文件中配置六类合法 UCI（DNS account 包含 provider 和所需凭据、DDNS rule 引用该 account，并设置 zone/host/source）。不要把秘密放进命令参数或环境。

1. prepare：创建独立的私有空基线；中断初始化使用 prepare-resume，不删除重来。
2. import-preview：捕获固定独立源文件，预览迁移；import-commit <confirmation> 明确确认。仅允许首次空基线导入，原始秘密进入私有保险库；预览不能产生 DNS 写入。
3. activate-preview：预览普通配置投影；config-commit <confirmation> 连续完成绑定提交、公开投影与观察收尾。公开源中总开关/业务开关保持关闭，秘密被移出。config-finish <apply_handle> 仅续完同一已绑定事务；失败保留原事务，不能换源重试。配置变更用 config-preview 的标准输入及 config-commit；config-export 不导出秘密，config-cancel 取消待确认预览。
4. grant-preview <rule> / grant-commit <confirmation>：对当前配置代际中的指定单条规则授予 DDNS 权限。预览、旧配置的授权或源文件开关均不能代替确认。grant-cancel 取消预览，grant-revoke --confirm 撤销授权。
5. ddns-sync <rule>：执行 Cloudflare / Aliyun / DNSPod / 华为云 AAAA 同步；ddns-status <rule> 读取有界状态。未授权、待恢复、并发或节流等待返回 4，并可附 ok=true 的状态报告；ok=true 只说明状态可读，不能当作执行成功，必须同时检查退出码、phase/result/effect。
6. 成功写入保留原始回执。ddns-reconcile <provider> <account> <job> --confirm 只读核对；ddns-collect-receipt 同参数只归档已确认原始回执。ddns-collect-work <job> --confirm / ddns-collect-orphan <provider> <account> <job> --confirm 收集经原证据绑定且已静止的残留；ddns-retire-archive 同 provider/account/job 参数退役原归档。结果未知不重发、不凭“记录现在存在”伪造成功，不删除凭据或日志强行放行。

secret-put <provider> <account> <slot> 从标准输入更新秘密槽（key_id/secret/account_id/endpoint），不接受值参数。它改变配置代际；之后须重新投影并明确授权，旧授权不沿用。

版本、四家 DNS/CA 目录、check-stdin 有界六类完整配置校验继续提供。LuCI 已有账户/规则编辑、私有凭据、预览确认、明确授权和异步任务/回执维护页面；工程入口已有明确启动的持续调度及原有限调度/网络事件，完整生产 daemon 与启用意图消费仍待 WP03 接合；ACME、代理/访问/防火墙、WOL 属于其余既定工作包。

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

## r142 持续运行源码接合（尚未构建新三包）

网页“启动持续运行”、CLI `schedule-serve --confirm` 或独立init的 `start --confirm` 明确启动同一个持续调度进程；默认安装、无确认start及boot继续不启动。原 `schedule-start --confirm` 仍是900秒/8批次有限会话。两模式共用唯一租约锁，不能并发，也不自动重开、重授权或清除残留。

持续模式不受一次会话的900秒/8批次限制，每批提供商调用仍由既有有界工作监督执行、保留逐规则节流/失败退避。等待期间每最多60秒重新核对来源、代次、授权和持久屏障；唤醒不提前派发。计数最大2147483647批时停止，避免计数溢出。合作停止等待已进入批次结束；已确认写入或未知结果均停在原回执/恢复屏障前，须原显式维护流程处理，不能自动归档后继续。

状态报告只增加continuous=true和admission_limit=0以区分持续模式；0表示持续模式，不是可无限重试提供商。PID/出生标记/启动模式/锁描述符均需一致，私有租约不能把有限会话伪造成持续进程。配置、凭据发布和删除继续要求调度静止。工程作用域不变，原生产数据及默认门禁保留。

本修订只做源码生成的临时安装树与受影响回归；最近实际三包仍r141，不能把r142源码回归称为r142 IPK验收。按用户规则本周期第10步再集中构建；当前尚未完成完整生产启用意图消费/撤销、自动启动及生产命名空间接管。

## r143 主开关意图消费与撤销（源码，尚未生成新三包）

网页“应用启用意图 / 禁用并撤权 / 查看主开关意图”对应CLI lifecycle-enable --confirm、lifecycle-disable --confirm、lifecycle-status。消费既有r136准备记录，重新核对完整候选、固定来源、代次和私有库标记后，把已确认主开关应用到私有startup-active覆盖层；普通公共投影继续关闭，不改写源配置、不从投影猜回原开关。启用不授予规则权限，不自动启动；切换先撤销旧DDNS授权，启用后须重新明确授权规则，再启动持续或有限会话。

禁用先请求合作停止；已进入批次/恢复屏障未完成则拒绝并保留现场，处理完成后重试。已静止且通过原恢复检查的控制记录可在这次明确禁用中回收。私有已应用意图绑定来源、代次、凭据及候选摘要，任一变化均不能继承旧开关；损坏、链接或未完成暂存都拒绝业务，不删除原证据。原手动模式在尚无已应用主开关时继续可用；一旦明确禁用，旧授权、网页任务和手动写入都不能绕过该意图。

CLI lifecycle-record-save/resume/check/apply/cancel <enabled|disabled> --confirm 提供明确的准备、续完、核对、消费和取消；取消只撤销未消费的匹配准备，不回滚已应用状态。同步/改名/清理中断保留屏障，apply可重新核对后续完；不能自动抹掉DNS/配置事务或未知记录。startup-active仅保存有界私有摘要，不复制秘密明文。

这仍是独立工程命名空间的主开关覆盖层；原型门禁、完整生产命名空间接管与目标验收状态保持。r143不提前构建工程三包，最近实际包仍r141。


## r144 生产配置只读复制到工程运行链（源码，尚未构建三包）

先执行 `prepare`，再通过网页“预览现有 HomeGate 配置 / 确认复制生产配置”，或CLI `production-copy-preview`、`production-copy-commit <confirmation>`，从固定 `/etc/config/homegate` 导入。仅接受未修改的初始工程库；来源须root私有600普通单链接文件，并已有安全的 `/var/run/homegate/frontend.lock`。使用只读打开的原写锁及完整来源字节反复核对，不从参数、stdin或环境选择来源。原配置、秘密、服务、开机设置和写锁内容不修改；来源变化/锁占用/恢复屏障拒绝确认。

完整旧配置备份和原开关保留在私有代次legacy.conf；四家凭据及URL类秘密进入受限vault，六类配置共用原迁移codec，公开差异、导出与网页无秘密。复制提交使用原持久应用日志，原子发布独立工程普通安全配置；失败保留应用句柄，通过 `config-finish <handle>` 或网页续完，不重做导入。普通import/config提交不能冒用production-copy确认。完成复制不会授予DDNS权限或启动服务；明确应用启用意图、重新授权当前规则，再使用持续/有限调度。原始开关信息只保留，不推断为本次授权。

这是把既有生产配置/秘密接入已验证工程运行入口的迁移链，不替换尚含完整旧业务的生产核心，也不自动操作生产服务。完整产品接管/自动启动、其余业务、目标依赖/实机仍待。最新源码r144，实际三包仍r141，第10步集中构建。

应用日志落盘后、取得句柄前中断时，可在网页明确选择“恢复应用前配置”或执行 `config-recover --confirm`，复用原journal/anchor/来源检查恢复工程配置并完成持久确认；这不恢复或操作生产服务，不清理未决DNS记录。已有句柄时仍可config-finish续完目标发布。


## r145 本地证书配置、校验、原子发布和状态（源码，尚未构建三包）

原生网页可预览/确认本地证书配置，再提交完整证书链和未加密私钥PEM；工程CLI为 `cert-status <id>`、`cert-import <id> --confirm`、`cert-resume <id> --confirm`、`cert-cancel <id> --confirm`。导入从stdin读取仅含certificate_pem/private_key_pem两字段的JSON，不接受服务器文件路径；私钥不进argv、公开响应或日志。证书资源必须已在当前已发布配置中，source=local；未知ID和ACME资源不能冒用本地材料入口。

使用现有OpenSSL pkey/x509/crl2pkcs7/pkcs7核对公钥匹配、全部PEM可解析、起止时间和叶证书DNS SAN精确集合；通配符与具体域名是不同身份，不接受仅CN、缺失或多出的DNS SAN。RSA/ECDSA均走同一发布通道。与旧本地导入合同一致，不验证公共CA信任，状态显式trust_checked=false。本工程入口证书链上限64KiB、未加密私钥16KiB、DNS名最多32个；这是工程上传边界，旧生产路径/参数和512KiB历史上限没有被替换。配置普通请求仍32KiB，仅证书上传HTTP上限256KiB，内部JSON上限112KiB且逐字段限长。

材料只保存在独立 `/etc/homegate-engineering/certs/<id>` 下0700/0600目录/文件。当前指针原子选中同一不可变证书对；校验失败不改原指针。原10秒看门狗监督完整OpenSSL进程族，调用方消失不能留下无限运行的校验。保留候选可明确续完；需重新核对当前来源、配置代次和密封材料，来源变化不沿用旧任务。取消仅清理受检候选及匹配暂存指针，不回滚已发布证书；原证书对历史保留，最多16个工程版本。私有校验中间件及摘要不进入公开状态。没有自动重载生产服务，也没有替换生产证书目录。

证书状态报告exists/valid/identity_valid/expiry/days/renew/pending；域名或环境变更后原材料不再显示匹配，续期阈值变化只影响renew，不改变证书身份。状态读取需要共享锁及有效当前配置，忙或配置恢复中明确拒绝，不编造健康。续期标记只是到期判断，不能当作已实现ACME续签。

WP04的DNS-01签发、账户持久化、TXT精确清理、正式/测试CA隔离和自动续期仍待实际接合。已核对 [acme.sh官方DNS接口约定](https://github.com/acmesh-official/acme.sh/wiki/DNS-API-Dev-Guide) 和 [参数](https://github.com/acmesh-official/acme.sh/wiki/Options-and-Params)：可作为Shell执行组件候选，但本轮未安装、未固定组件版本或完成其安全钩子接合，不能声称已选定/可生产签发。OpenSSL命令依据 [1.1.1 x509](https://docs.openssl.org/1.1.1/man1/x509/)；目标报告为1.1.1x，但本机OpenSSL隔离验证不证明目标加载与资源。下一步复用本轮材料发布通道接DNS-01实际签发，保持已有未知DNS操作与原始回执屏障。

本轮只做源码生成的私有安装树和真实OpenSSL/原生LuCI验证，实际工程三包仍r141，当前源码r145；第10步集中构建。无真实CA或公网DNS签发/路由器操作。


## r146 ACME DNS-01 手动签发与续签（源码，尚未生成新三包）

固定未修改的 acme.sh 3.1.6，来源/签名/完整 GPLv3 许可见 third_party/acme.sh-3.1.6/PROVENANCE.json 和 LICENSE.md。安装树在独立工程 libexec/acme，使用自有 dns_homegate 钩子及限定 HTTP 适配；不运行上游 installer、cron、自动升级、任意 hooks 或 reloadcmd。组件签名核对使用同一官方 HTTPS 仓库的 allowed_signers，不等于独立身份审计。

网页可预览/确认 ACME 证书配置，再手动签发、检查并续签、查询/停止任务、清理已确认挑战。CLI 对应 acme-issue|acme-renew <certificate> <job32hex> --confirm、acme-job <job>、acme-stop|acme-cleanup <job> --confirm。配置使用既有 DNS 账户/私有凭据，支持原四家 DNS 记录协调器，不需要 DDNS 规则授权；明确证书操作只允许配置域名的 _acme-challenge TXT 精确值。账户保存在工程私有 acme/accounts/letsencrypt-staging 或 letsencrypt-production；两种 CA 分开，HTTP URL 严格限制到当前环境的 Let’s Encrypt 主机。JSON/JWS、TXT、证书与私钥通过 stdin/私有文件传输，不进入外部执行参数。网页不返回凭据、完整客户端输出或证书私钥。

签发为异步单任务，前台/配置/凭据/主开关与 DDNS 调度互斥；签发最多15分钟，客户端进程族整体停止，保留任务和原 DNS 恢复证据。任务上限16个，不自动删除历史或重下订单。签发成功且 TXT 清理完成，才交给 r145 校验通道验证材料并成对原子发布；失败/停止不替换已有证书，状态的 trust_checked=false 仍不表示公共 CA 信任已验证。续签先查当前证书有效期，未到 renew_days 就跳过网络；当前仅明确手动检查/续签，定时续期尚未接通。

每次 TXT 记录以名称/精确值持久化 prepared/owned/preexisting/removed/unknown 状态。已存在相同 TXT 标记 preexisting，不删除；其他值由原提供商合同保留，包括华为同一 RRset 的其他值。已确认写入的原始上下文、manifest、终态、提供商/账户/代次/PID 先复制到任务 receipts，再通过原有绑定检查明确确认该次已知操作，允许继续同一已授权签发工作流；旧 DDNS 的未知核对、确认、归档规则不变。未知/准备中写入保留全局屏障，不猜测拥有权，不自动重试或清理。明确清理只删除本任务已确认拥有的值；旧原始回执恢复仍遵循既有维护流程，ACME未知结果的统一页面恢复与重启后接续仍待收口。

本地验证层为源码生成安装树、固定真实 LuCI/会话/CSRF、实际 acme.sh/OpenSSL 签名与 CSR；外部 CA/DNS HTTP 边界使用私有响应夹具，传播等待在夹具中虚拟化，产品60秒传播等待和900秒时限保持。未访问公网 CA/DNS，没有真实 staging 证书，不证明 DNS 传播、公共 CA/TLS、路由器 ABI 或资源已通过。实际三包仍 r141，本周期第10步集中构建；完整生产入口/定时续期及目标验收仍未完成。


## r147 定时续签及冷启动未决挑战处理（当前源码，三包待第10步集中构建）

网页或 CLI acme-schedule-start <certificate> --confirm 明确启动一个选定证书的续签会话；acme-schedule-status、acme-schedule-stop --confirm、acme-schedule-reap --confirm 分别查询、请求停止、收起已结束会话。会话退出网页后继续，使用单调时钟每3600秒检查，立即进行首次检查。未到 renew_days 不下订单、不新增持久任务；到期或缺证书复用固定签发客户端及原子发布通道，每个签发任务仍限制900秒。会话失败/未知/中断即结束，不自动重试。暂不在重启时自动授予/恢复会话，不安装 cron 或上游自动升级。工程明确操作授权独立于公共备份的关闭投影，已应用的主开关禁用意图始终拒绝新工作。

会话锁绑定其随机标识、当前启动、原证书配置/来源及私有代次。内部续签只能持有该会话的真实FD9锁，不能用外部参数或环境冒充；每次检查/下单重新核对来源和主开关。会话与手动签发、其他定时会话及DDNS调度互斥；配置/凭据变更须先停止会话。主开关禁用和工程init stop/shutdown先请求停止本会话及其已接纳任务，不按存储PID发信号。已接纳签发的原看门狗负责停止自己的进程族；未决挑战继续阻止完成禁用/收起，必须先按原流程明确处理。

新增历史任务守卫：任何活跃、没有明确终态、owned/prepared/unknown挑战或cleanup_required任务，都拒绝另一订单/续签会话。重启丢失/var/run并不抹除私有任务或放行重下订单。固定job状态仍返回interrupted；明确acme-cleanup只在原来源/代次一致及原DNS屏障可读写时删除已确认拥有的TXT，允许主开关禁用后执行这种清理，不发布证书、不重新启用主开关。未知写入、准备不确定、损坏证据继续保留，仍使用既有提供商明确恢复流程；GET观察不升级为拥有权，不据此猜测删除。收起会话仅删除已核对的固定运行态成员，保留证书、账户、签发任务及原始回执。

沿用最多16个签发任务/16个证书对历史，不自动删除私有历史；会话的未到期检查不消耗这些名额。容量达到上限时明确失败停止，不能绕过或覆盖证据。工程源码之外的完整生产接管、公网CA/DNS/TLS传播、目标设备资源/ABI和实机验收仍未完成。定时及冷恢复验证只在现有私有命名空间和外部协议/时钟夹具进行，不能冒充设备重启或公网staging成功。r146段落中的“定时未接通”为当时历史状态。


r147联调还修复了两项实际边界：手动签发/DDNS接纳在取得业务锁后再次核对续签会话，拒绝“空闲检查之后会话已启动”的竞态；私有签发和原看门狗对自己的负进程组发送TERM/KILL时明确使用 `--` 参数分隔，避免当前宿主外部kill解析歧义影响任务外进程。停止验证保持网页/会话服务存活，再验证清理和主开关收尾。持久未决任务也会阻止配置变更；允许必要的prepare重建丢失运行态锁，随后仍需明确清理，不以重建运行态绕过订单屏障。


签发后若证书对发布中断，定时检查会拒绝待发布候选，手动签发也在下单前检查pending而拒绝重复订单。原网页/CLI cert-resume/cert-cancel扩展到同源ACME候选：续完前必须所有签发任务已明确结束且挑战已清理，再按原OpenSSL/密封候选/来源绑定发布；不重新访问CA/DNS。取消只处理私有候选，不删除任务和DNS回执。新admission-status-internal仅为持有原业务锁的固定只读状态入口，不授予导入/发布能力。这样可以明确完成原已签发材料，避免用新订单替代本地发布恢复。


## r148 工程网站代理

原生配置页可预览网站规则（精确域名或单层 `*.example.com`）、保存不回显的私有上游 URL，发布当前配置，并选择最多16条规则明确启停。CLI：`proxy-start <id,id> open|allow --confirm`、`proxy-status`、`proxy-stop --confirm`、`proxy-reap --confirm`；`web-target-put <id> --confirm` 仅从 stdin 读 URL。运行期间先停止并收起会话，再变更配置/凭据。证书从原验证/原子发布通道复制到私有运行态；证书更新、失效或配置绑定改变时停止并返回 `restart_required`，重新明确启动后采用新证书，当前无热重载。

执行组件为系统 `/usr/sbin/nginx`（工程配方依赖 `nginx-ssl`）。原型门禁默认关闭，仅工程渲染开启。当前保守接纳官方版本号 nginx 1.30.6 或更新的1.x，再在10秒进程族期限内真实检查全部配置、DNS及证书。目标 SDK 内 nginx 包版本/构建选项/安全补丁和 worker 权限尚未验证；现有目标包若版本不足会明确拒绝，不能把当前宿主原生测试当作目标支持。第10步包级验证前必须确认匹配组件来源或完成目标构建，不以降低门禁绕过。

已接：HTTP/HTTPS双栈监听、SNI证书选择/未知SNI拒绝、未知Host404、HTTP到公开HTTPS端口308重定向、HTTP/HTTPS上游、编码路径/基路径/双查询串、WebSocket、流式请求、手动黑白名单（deny优先，open也执行deny）、转发头按实际连接重建。HTTPS上游开启系统CA和域名验证；当前拒绝字面IP的HTTPS上游，不能假设 nginx 的DNS身份路径等同于Go的IP SAN校验。WebSocket空闲读取期限3600秒；其他期限见固定生成器。访问控制 `allow` 明确启用手动白名单；配置含CN放行时拒绝此模式，CN库接合待完成。

工程只监听10080/10443默认端口，不写防火墙、不替换生产服务。主开关禁用/init stop先请求合作停止代理；卸载须证明代理及原ACME/DDNS会话静默。停止由仍存活且已核对的当前会话领导者向自身进程组发信号，绝不按存储PID或全局nginx名字杀进程。私有计划/URL/密钥均不返回网页或状态，临时请求体只在固定工程scratch目录；回收仅核对固定目录及有界数字文件，不递归删除未知状态。

原生回归使用固定 nginx1.30.6/PCRE2 10.47，在原单UID、cap-drop ALL的私有网络/文件系统中通过外部组件适配器设置 `master_process off`，不改业务配置、源绑定、锁或UID门禁。组件仅构建至 `/var/tmp`；未安装宿主系统，目标worker降权/进程数/ABI/资源、真实三包及生产接合均待验证。`health_checked=false`；运行标记不代表端到端健康。CN地址库、访问审计、防火墙链、证书热更新和完整生产接管仍待固定工作包后续完成。

组件核对来源：[nginx稳定版下载](https://nginx.org/en/download.html)、[代理模块](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)、[SSL模块](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)、[WebSocket](https://nginx.org/en/docs/http/websocket.html)。测试组件脚本 `scripts/prepare-nginx.py` 钉住两个源码归档SHA256；本地另有官方nginx签名核对，信任锚为官方HTTPS公钥，非独立身份审计。产品使用目标系统包，不自动下载或升级组件。


## r149 证书自动平滑重载（当前行为，替代上节证书变化停机说明）

代理发现原证书通道发布新pair后，借原业务锁核对源/意图、证书有效性与密封材料，生成候选配置；独立十秒进程族执行真实nginx配置检查，再向本次仍存活且出生标记/父子/组一致的master发HUP。新SNI逐一通过本地TLS握手和叶DER SHA256确认后才增加generation；通配探测选择不与精确规则冲突的一字符子域，保持域名长度约束。HTTP探测使用无法配置成DNS网站规则的IPv6字面Host，走默认404，不请求业务上游。每次检查/探测10秒，探测最多3次；停止会合作中断检查族。health_checked仍false，证书确认不等于全链路健康。

候选语法/材料失败保留旧服务；HUP后确认失败则恢复旧配置、重新HUP并确认旧指纹，不能确认则停止。相同候选失败退避60秒再试，新发布不必等待旧退避。配置/启用意图改变或旧证书失效仍停止。运行态只更新小型候选/确认记录，TLS配置引用已密封且保留的具体pair目录，不追随current、不额外积累私钥副本；原初始快照/历史保留及显式停止回收门禁保留。

实际回归使用真实master/worker验证保留旧WebSocket并连续替换证书。原单进程夹具无法正确初始化重载后的连接池，r149改为测试组件专属的同凭据适配库：仅对当前真实/有效UID/GID、请求GID及已有补充组全为0且名称root的冗余initgroups返回无操作；其他请求失败，完全不新增身份、组或能力。回归明确检查正负请求、身份/组不变及CapEff/CapPrm/CapBnd=0。仅在原单UID、cap-drop ALL私有环境加载；库由prepare-nginx.py的固定C源和独立SHA记录构建至私有测试目录，不进入产品包、不修改业务UID/锁/权限/签名检查。目标worker降权、ABI/资源仍未验证；不能将夹具的同UID worker视为目标安全模型已验收。

现有SDK三个固定位置只读核对未找到nginx配方/nginx-ssl元数据；目标匹配组件仍须落实，保守版本门禁未降低。本轮复用nginx原二进制，无环境重装、系统安装、目标出包或CI。CN库、访问审计、专属防火墙链及完整生产接管仍待后续固定工作包。


## r150 CN 地址库与最近访问（当前工程行为）

原生访问管理页可预览并确认手动 allow/deny 和 CN 选择，再显式启动代理的 allow 模式。deny 始终最高；allow 模式中手动白名单或 CN 命中任一即可，open 模式仍执行deny。IP/CIDR可用空格、英文逗号或分号分隔；页面换行和制表符规范为空格，再进入原公共配置校验。未提供有效双栈 CN 库时拒绝启动 CN 限制，不降级成允许全部。

`access-update --confirm` 后台检查/下载；有效库7天内直接复用，`access-refresh --confirm`强制更新，`access-status`查询，`access-stop --confirm`/`access-reap --confirm`仅操作本次缓存任务。固定APNIC HTTPS主源及RIPE HTTPS镜像、每源20秒、整族60秒，数据最多24MiB；全文件头记录数、各类汇总及CN allocated/assigned双栈有效网段均校验，IPv4非二次幂数量精确拆CIDR，拒绝溢出/未对齐/映射IPv6。头信息、网段和计数保存在单个原子发布的私有CN.cidr；失败/截断/非200/超长保留旧库。库是注册分配经济体信息，不能当终端实时地理位置。来源及格式：[APNIC统计格式](https://www.apnic.net/about-apnic/corporate-documents/documents/resource-guidelines/rir-statistics-exchange-format/)。

工程代理启动时将已验证库导出为私有不可变geo快照并密封；nginx按真实remote_addr匹配，不信任客户端X-Forwarded-For。运行中更新库不改变当前访问策略，停止/收起并重新启动后采用新库；证书热重载继续使用本会话同一CN快照。无有效库拒绝启动；可明确继续使用已验证旧库，状态给出stale，不悄悄放开。当前未接CN自动定时刷新/不经重启的策略切换，这些随完整生产生命周期接合；不把工程手动生命周期冒充全部生产验收。

最近访问通过nginx本地非阻塞syslog数据报和一个私有独立随机标记接入Lua/nixio接收器；会话公开token不能伪造该标记。最多64个来源IP+Host，重复合并计数，约100毫秒批量发布到私有运行态access.json；不记录路径、查询串、凭据、上游URL或私钥。只保留实际访问时判断，不宣称当前策略重评；跨工程会话保留运行态观察，重启系统不保留。审计为尽力观察，过载可能丢失，长连接在完成时记录；接收器退出可见audit_available=false，不能把历史文件或PID复用当存活。数据报不是放行凭证，不影响nginx准入；接收器异常不放开规则。syslog及geo能力复用：[nginx syslog](https://nginx.org/en/docs/syslog.html)、[geo模块](https://nginx.org/en/docs/http/ngx_http_geo_module.html)。

`access-recent`只读；`access-clear --confirm`/`access-clear-denied --confirm`排队清理全部/拒绝观察，需当前接收器可用。写入命令在真实控制锁下原子发布，clear_pending表示待处理，查询空/剩余记录才代表完成；不会修改allow/deny/CN，也不清系统日志。原生页面沿用认证/POST/CSRF/确认边界，状态和记录只输出字段白名单，文本通过textContent显示。接收器、nginx及原检查进程都在代理自己的进程族内，原合作停止/有限强制尾部/静默回收边界不变；系统init stop和卸载另请求CN下载停止并证明静默。

本轮原生测试使用私有APNIC HTTP响应夹具验证下载/错误/回退，实际nginx执行双栈准入、快照和日志，原UID/cap-drop/锁/时限不降。未向公网下载验收真实APNIC快照，未验证目标worker权限、nixio/ABI、资源或新IPK；仍复用r148/nginx及r149同凭据测试适配，不重装环境。专属防火墙、HTTPS字面IP的SAN等价支持、目标组件与完整生产接管仍待固定工作包。
