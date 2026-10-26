# DDNS 生命周期与候选 Shell CLI

r73 本地专项完成。候选入口不安装到正式包，生产门禁关闭，旧 Go CLI/procd/包生命周期继续保留原字节。

固定 root 入口 `homegate-cli.sh` 的 `ddns-sync [rule-id]` 使用现有明确授权，选定规则调用原带状态执行器；不选规则调用原默认全批协调器。只转换固定参数，不接受路径、地址、请求体或批次自动收尾选项。全量同步仍在首个持久变更屏障后阻止后续写入，unknown 从不自动重试。`native_cli_enabled=false` 和下游既有门禁必须分别启用，环境不能开启；CLI 命令本身不授予规则权限。

`ddns-status [rule-id]` 在共同双锁下读取已核实普通配置的最多32个规则，逐项复用原状态工具及严格行解析，排序后整体输出。授权已撤销时仍可观察 unauthorized；读取不采样、不发送HTTP、不创建状态缓存，任何一行损坏都拒绝整份输出，不发布部分规则前缀。API v1、prototype、write_ready:false 与原逐行字段保持明确；这是候选报告，尚未改动旧 LuCI/CLI 消费者，不宣称完整 M01 兼容验收。ddns-delete、daemon 和其余冻结命令仍未迁移，本候选拒绝这些命令。

`schedule-run --confirm` 用 exec 进入原有界前台调度；`schedule-status`、`schedule-stop --confirm`、`schedule-reap --confirm` 复用原控制语义。候选入口先关闭调用者 FD3～9，防止继承外来内部帧或借锁。停止只请求不再准入，不能把 stopping 当作已静止。四个缩权/观察入口不受候选功能门禁限制，原 root/文件权限检查继续生效。

新增 `schedule-quiescent` 只在检查时刻获取现有准入/控制锁和共同双锁，核实无活跃拥有者、合法控制记录、无外层工作且持久写守卫允许后报告 quiescent:true、point_in_time:true、write_ready:false。它不创建锁/会话、不发送信号、不回收任何记录，不保证返回之后无人重新启动，不表示旧生产服务或系统其他工作已停止。持久成功回执、unknown、损坏控制或未知工作继续拒绝。

既有冷准备 `homegate-lifecycle-prepare.sh prepare|resume` 先建立或核实同一私有空准入锁，持 FD9 后才取 FD6，贯穿原持久 bootstrap；复验锁 inode，拒绝链接、错误权限、非空锁、已占用锁、任意遗留调度目录或外层 DDNS 工作。有效停止后仍须明确 reap，再重新调用 prepare/resume，不能用静止观察取代持锁或显式回收。候选 `lifecycle-prepare|lifecycle-resume` 仅接到这两个原入口；不自动启动、恢复任务、清理原DNS证据、重写凭据、改 UCI 或操作真实服务。

新增4静态/23非root运行、受影响15静态/14运行、2root及11工程通过；不代表远端CI、生产接管、冷启动设备验收、SDK/ABI、同源三包或资源测量。正式服务所有启动、重载、网络事件和卸载入口的迁移仍须后续贯通并验证。

## r121 候选核心只读目录接合

候选入口新增 `dns-provider-catalog`、`acme-ca-catalog`，均只接受命令本身。固定 Lua 适配返回现行 Go 对照的 API v1、phase、四家 DNS 的名称/别名/能力/凭据字段，以及 Let's Encrypt 的 production/staging 两个独立目录；凭据只含输入定义，没有账户值。版本由唯一 VERSION/RELEASE 严格单行读取生成。非法参数退出2，身份/版本/适配失败统一脱敏退出7，不发布部分目录。

这两个元数据入口不依赖业务门禁，但保留 root、固定 PATH、Lua 环境清除和 FD3–9 关闭；不读 UCI/秘密、创建状态、调用供应商或执行服务操作。原 native_cli_enabled=false 及全部业务门禁保持。目录能力描述供应商合同，不能据此推断候选 ACME/生产业务已接通。旧 Go CLI、生产配方和消费者仍未切换。

对照样本 `scripts/fixtures/core-cli/catalogs.json` 来自当前 Go 定义的人工核对，并绑定三份参考源码 SHA；它不是运行 Go 的证据。新增专项 `核心目录CLI回归.py` 被原 DDNS生命周期CLI 的静态/运行分区分别纳入，不改变工作流组数、旧场景、25分钟限制或发布门禁。完整 M01 及生产接合/目标SDK/三包/实机仍按固定台账验收。

## r122 普通配置账户状态只读接合

候选 `dns-provider-status <account-id>` 经原 native_cli 门禁、独立 dns_status_cli 门禁和 root 检查进入固定适配器。在原 FD6/7 共同锁下读取普通已发布配置的来源绑定快照，选择账户供应商；固定协调器新增受 dns_status_read 门禁控制的只读普通代次分支，复用四家既有校验、真实签名、curl/TLS/CA、独立监督和错误分类。新入口不要求规则授权，不创建授权，也不提供调用者供应商、地址、凭据、路径或写操作选项。三个相关入口门禁在源码中均关闭。

返回旧 DNSProviderReport 的必需字段及安全附加的 prototype/effect/write_ready/configuration_revision。缺账户返回空 capabilities 和 not_found；业务失败保持安全分类/代码及 retryable，供应商文本不回显。网络请求前检查版本、账户/代次/普通来源和既有屏障；原协调器重新绑定同一普通来源，完成后再次检查锁身份及来源，最后严格校验结果的账户、供应商、代次、字段集合及退出码才整体输出。读取不修改配置/授权/DNS记录或关闭任何恢复屏障，失败不自动重试。

旧迁移读入口和写入/回执/恢复流程保持原分支；新分支仅固定 check 模式，不接受 --zones/--records 等额外参数。CLI 之外直接调用内部模式仍需固定源码门禁，账户供应商由私有帧二次核对，类似选项的账户名只作位置参数，不重新解释成内部选项。生产配方和旧 Go 核心未切换，完整 M01/M06、目标SDK/ABI、三包和实机仍待。

## r123 普通配置账户区域发现

候选 `dns-zones <account-id>` 复用 r122 的 root/来源/共同锁/结果绑定，仅增加固定 --zones 内部读模式。协调器只接受固定三参数的 --runtime-check-internal 或 --runtime-zones-internal，后者转换为原 --zones 分页入口，不接受调用者的供应商、地址、页码或写选项；原读门禁仍关闭，不开放记录写入或恢复/收集路径。r122 的仅check范围由本节明确扩展，旧账户状态接口不变。

四家继续使用既有分页/签名/curl/TLS/监督及错误语义。新适配器保留 DNSZonesReport 必需字段、空列表和错误省略语义，不输出 credentials_valid；域名是该命令明确请求的返回值，其他供应商元数据/凭据/端点不输出。后页失败只返回空 zones，不发布部分列表，不自动重试；完整汇总后复验同一来源和锁身份。

保持原供应商汇总字节上限：Cloudflare 14350512，其他三家65536；Cloudflare条数最多50000，其他原分页/字节/条数限制继续由原读取器校验。区域结果使用原JSON解析及精确重建原规范结果，拒绝错绑定、重复键、尾随文档、对象冒充数组、重复/无序/非法域名及错误中夹带部分列表。大列表不套用账户状态的小结果上限，也不放宽原上限。这里只验证宿主有界逻辑，不据此声称目标内存峰值已通过。生产核心/消费者/配方及完整M01/M06、SDK/ABI、三包和实机验收仍待。

## r124 普通配置网络诊断接合

候选 `network-resolve` 不接受额外参数。在原共同锁下读取普通已发布配置的 main.wol_interface（空值默认br-lan），复用wan6-plan的固定地址/路由/wan6采样及安全选择顺序，规范化IPv6显示；新增只读/sys/class/net下的配置桥成员采集，不接受路径或环境覆盖。root、固定PATH、FD3–9关闭及独立入口/worker/看门人门禁均保留关闭。

复用原独立会话看门人，网络分支5秒预算及原1秒终止宽限、族静止/进程身份/继承锁检查，原服务动作与DNS/DDNS超时不变。看门人持FD6/7直到工作族结束，网络工具不继承私有帧/锁。结束后复验配置来源、桥、锁身份及规范报告再输出；失败/调用者丢失不自动删除未知临时目录，新网络读取遇遗留目录拒绝，避免重复积累，不增加恢复协议。

保留network-resolver及WAN/LAN字段：WAN不可用保留合法默认路由/ubus设备诊断，LAN缺失保留空members，两个分量独立；合法ok:false诊断按旧CLI仍退出0，门禁/参数/锁/来源/未知工作失败另行拒绝。复用现有采样对ubus明确down的安全收敛，不将残留公网地址报告为可用；与旧Go忽略up字段的行为差异明确记录，不据此称完整M01通过。LAN默认/物理接口/隐藏成员及排序可核对；成员上限1024，超限/不可读报告LAN不可用，不返回截断前缀。命令输出/单份报告各上限65536，未测目标内存或真实sysfs布局。生产核心/消费者/配方仍未切换，完整M01/M08/M16、SDK/ABI、三包/实机仍待。

## r125：check 合同纠正与完整配置验证前置组件

旧Go的check调用App.Check→Status→Config.Reload及Runtime.Probe，返回健康报告，失败退出1；不是仅配置检查。早期homegate-prototype.sh check只检查main且complete_validation=false，writer-check也只是持久事务屏障。r125新增内部homegate-configuration-read.sh、homegate-configuration.lua及纯configuration-validation.lua，固定普通已发布来源、共同锁和代次绑定，无路径参数；未把该配置报告接到公共check，健康探测/运行状态报告仍待接合。

私有backup.private_configuration读取规范化前全部启用开关及访问开关；公开备份/迁移仍关闭开关并省略秘密，原private_ddns_switches合同不变。复用原六类完整schema及交叉引用校验，把秘密槽与私有快照精确绑定；补上启用Web规则的目标URL和HTTPS/HTTP代理端口约束。固定公开报告只含六类数量、固定错误枚举和边界字段，health_checked/external_resources_checked/write_ready均false、effect=none，配置不合法不作为健康结论。缺失/损坏来源或管道、来源变化和锁替换统一拒绝；重复验证完成前不输出部分报告，无秘密落盘和自动恢复。

固定目标URL语法限定http/https、主机/IPv4/IPv6及1–65535端口，拒绝userinfo、片段、反斜线/控制/空白字节，比旧Go的url.Parse更严格；现有公共schema也比旧Go对禁用规则/交叉引用更严格。保留既有迁移默认开关语义，不宣称任意旧UCI文本与旧Go逐字等价。验证配置结构和Web约束，不验证DNS凭据在线有效性、ACME/证书文件、设备/端口可用性、进程/服务健康或完整生产接管；这些仍待验收。内部源码门禁configuration_validation_enabled=false，生产配方/旧Go/公共CLI及原监督期限不变。

普通来源另外支持精确canonical公共配置形式：先绑定其完整结构到验证后的私有快照，再使用该快照内的秘密槽；不要求秘密回填UCI。旧UCI形式仍逐槽精确匹配。非规范公共字节不通过该分支。

共享codec更新同步生成Core参考桥内的Lua嵌入副本；原始LuCI控制器及路由表不变，Go实现和生产命令派发不变。

## r126：候选 status/check 健康报告

固定无额外参数的status/check复用r125完整配置模型、普通发布来源、共同锁和严格结果绑定。健康条件沿用旧Go：configured且无错误且enabled==running；status合法诊断退出0，check不健康退出1。坏UCI/来源不绑定时报告配置不可用；基础锁/目录/代次失败仍为候选拒绝码4/7，不当作合法业务报告。要求已有安全事务库与当前代次，不自动建立库或完成冷启动/生产切换。

固定读取/var/run/homegate/runtime.json与/proc/<pid>/stat/cmdline：原始状态文件仅root单硬链0600/0644、最多4096字节，拒绝符号链接与其他权限；报告和进程读取上限8192。合法缺文件为未运行，陈旧PID/ticks和Z/X进程为未运行；活进程需精确/usr/bin/homegate\0daemon\0命令及两次稳定起始ticks，没有历史ticks字段也不只凭PID判断。文件描述符身份/长度及重复原始内容、进程身份变化均检查。异常状态/权限/身份为未知错误，不默认为健康；不信调用者路径或环境。

比旧Go更严格的边界明确保留：拒绝重复/额外字段、尾随文档、无必需字段、非限定版本/RFC3339时间、PID范围外以及超出Lua安全整数的ticks；运行命令身份、僵尸和稳定观测要求也更严格。可选runtime元数据只发布固定规范字段，process_start_ticks为0时按旧omitempty省略。该结果不证明业务模块已应用、凭据在线有效、进程资源达标或目标设备兼容；规范普通投影的开关仍按既有禁用规范处理，生产启用及候选daemon持久状态写入仍待。

增加关闭的health_status_enabled门禁与既有watchdog固定health-status动作，预算5秒/原终止宽限1秒；其他动作/期限及业务门禁不变。调用者丢失仍由watchdog持锁监督自己的进程族，保持静默屏障；遗留.health-read-*证据拒绝自动清理/复用。私有配置只经管道，结果文件只有公开健康元数据。旧Go/生产配方、r125共享codec/嵌入副本及前端路由不变。

最终公开临时文件在发布前再次进行非空/大小/权限和完整规范报告复验，写入失败或截断不输出部分JSON。

运行JSON的pid及process_start_ticks同时校验整数值与原始整数文本；指数或小数写法不因JSON转数值而被接受，避免格式异常状态被当作停止且健康。

## r127：候选 recovery-status 只读恢复观察

固定无额外参数recovery-status保留旧报告api_version/ok/version/phase/degraded/modules及3类模块状态，合法诊断退出0。旧Go Read在缺文件、读错或坏JSON时返回Empty且正常，本次明确采用更保守语义：缺失/损坏/不安全记录显示requires_user_action/state_unavailable；可读旧记录不等于当前配置恢复完成。

固定读取/var/run/homegate/recovery.json，root单硬链0600/0644、最多65536字节，拒绝符号链接/过限/变化；公开报告最多8192字节。支持原5模块ddns/acme/firewall/proxy/access，去重排序，保留retrying/degraded/requires_user_action及有界整数次数、时间字段。原始错误消息不公开，未知错误类别映射unclassified；重复键、尾随文档、非法字段/模块/状态、非整数数字文本、无效时间或不一致重试元数据拒绝整份记录，不发布部分列表。上限、必需字段和一致性检查比旧Go更严格，明确保留差异。

当前来源读取复用r125/r126模型及既有runtime-ddns-recovery-snapshot-read，绑定版本、当前代次、私有库identity SHA及当前generation manifest SHA。新增可选私有source元数据schema=HGRECOVERYSOURCE1、configuration_revision、identity、generation；只有准确匹配当前来源才record_source_bound=true。旧记录缺source时仍可脱敏展示模块，但追加unbound_state；错代次/库/manifest为source_mismatch，旧软件版本为状态不可用。r127只实现消费合同，真实候选恢复状态生产者及迁移写入仍待，不伪造绑定记录。

叠加既有writer-check的clear/pending/unavailable及固定候选残留工作/调度/未完成缓存证据；不解析或清理未知DNS回执，不执行恢复/重试/停止。观察前后来源上下文、identity/manifest和屏障一致才发布；候选屏障使candidate模块要求检查。仅观察声明范围，ok=true表示来源绑定的有效记录和本次已检查范围没有待恢复项，observation_only=true、complete_recovery_verified=false、effect=none、write_ready=false；不代表完整生产、实机或业务恢复验收。

新recovery_status_enabled源码门禁关闭。复用原独立watchdog固定recovery-status动作预算5秒/原终止宽限1秒，保留共同FD6–7锁至自身进程族静默；其他动作/超时不变。旧残留不自动删除，诊断可以报告其存在；只清理本次已完整验证的公开结果文件，最终临时文件复验拒绝截断输出。基础目录/锁/代次失败保留候选2/4/7拒绝码，要求已有安全事务库，不做冷初始化。Go、生产配方、共享配置/健康模型及前端不变。

## r128：真实 DDNS 转换发布独立恢复贡献

新关闭门禁ddns_recovery_publish_enabled接入既有DDNS状态begin/finish/reset三处真实转换；只写root0600的/var/run/homegate/ddns-recovery.json，不覆盖全局recovery.json或其他模块。helper只接受固定publish-internal/inspect-internal，并验证借入的共同FD6–7锁/身份；环境不打开门禁。生产者复用普通恢复快照及现有HGDDNSSTATE1验证，聚合全部配置内DDNS规则（最多32）而不默默跳过缺失/陈旧/坏缓存；缓存目录最多192项，正常状态4096字节、阶段65536，输入262144和贡献8192字节上限。

贡献绑定版本、代次、库identity、generation manifest、boot和当前缓存原文/布局/时钟有效性摘要；缺失、异代次/boot、时钟反转、未知/处理中或阶段残留不清零。实际成功/无变化可清除DDNS范围内的故障；retry_wait仅输出degraded且retryable，不编造重试队列、最大次数、次数或墙钟重试时间；paused和unknown/inflight要求检查。观察更新时刻为生产者实际UTC时间，不把单调时钟数值当日期。仅表示当前配置内DDNS历史状态，不证明当前公网记录/WAN地址已收敛。

发布使用私有next和pending、严格规范结果校验、来源/缓存二次比较、原子rename与文件/目录fsync；失败保留旧记录/阶段或pending，不自动清理或重试业务。目标文件必须是本库本生产者已知格式，拒绝外来内容/链接。begin发布失败发生在DNS派发之前；finish失败不删除原DNS回执或未知屏障，reset后缺历史仍为未知。全局写入/授权/恢复策略和原供应商签名、TLS、超时保持。发布中断后的显式核对/收尾协议仍待，不声称已完成跨重启持久恢复。

独立ddns_recovery_read_enabled默认关闭；打开时recovery-status在观察前后只读计算当前输入摘要，worker比较贡献的来源及摘要后才采用，避免缓存已变化而旧贡献仍显示正常。DDNS贡献只替换聚合报告中的DDNS行，保留全局记录其他模块及未绑定/缺失提示；新增ddns_observation仅输出安全计数/状态，不输出规则ID、缓存原文、凭据或摘要绑定值。pending/阶段可见时不可确认。完整恢复仍observation_only=true/complete_recovery_verified=false；其他模块生产者和完整生产/目标验收继续待办。既有5秒观察预算/1秒终止宽限及其他动作期限不变。
