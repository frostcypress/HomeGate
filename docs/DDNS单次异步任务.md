# DDNS 单条规则异步任务候选协议

## 当前 r79：任务名额与防重放标识分开限额

本节替代下面历史版本的“本次启动最多8个标识”。最多8份尚未完成明确维护的任务；本次启动累计最多32个保留标识。只有列表在任务锁内严格核实HGDDNSUIMAINTAINED1与当前meta/result和archive/compact操作完全一致，且没有maintenance、maintenance.next、maintained.next等未完成成员时，才释放一个任务名额。预览、已用nonce、单纯raw删除或持久归档完成均不能单独释放名额；最终发布失败仍占原名额，需要新的预览与明确同意完成原协议。

释放名额不删除目录、meta、result、proof或原持久归档，不回收旧标识。相同标识/规则仍只读返回原摘要，改规则拒绝；即使达到32个标识，仍允许旧标识去重读取、列表和已知结果静止核查。第33个新标识拒绝，不通过重启建议、删除证据或自动重发绕过上限。pending/interrupted/unknown在任何历史记录数量下仍阻止新派发，维护不改变历史last_effect。

目录锁内先核实所有保留任务，再分别判断8份未维护与32个累计标识预算。列表有序、最多32项，保持原14字段任务摘要及7字段结果，不增加权限/动作或秘密字段；Lua策略、原生传输和共用页面一起更新。每任务11成员、文件64KB、摘要帧4KB上限和生产关闭门禁保留；此为静态资源边界，尚无目标设备内存/延迟测量。超出32个已有目录、损坏/链接最终标记或已维护记录附带未完成阶段时保留并拒绝。

r75 本地专项完成：18新增/6受影响非root、4新增/12受影响静态、10项Lua传输、双端17项浏览器（34组合）、2root及11工程通过。生产配方不安装 prototype，原 UI 四门禁及新增 ddns_ui_jobs_enabled 均为 false。此实现不代表目标 LuCI、rpcd、ucode、SDK、三包或真实路由器已验证。

候选页面增加“同步所选规则一次”，只允许一条规则并另行确认可能修改 DNS。浏览器使用 crypto.getRandomValues 生成 32 位小写十六进制标识。Lua 的 submit 必须 POST/当前会话 CSRF，jobs 只允许 GET；JS rpcd 的 read ACL 是 status/jobs，write ACL 是 preview/commit/revoke/submit。前端和传输复用 r74 的私有请求文件，不接受调用者命令或路径。

submit 精确请求为 action、job、rule、consent:"1"，jobs 请求只有 action。根用户固定后端 homegate-ddns-ui.sh 委派 homegate-ddns-job.sh submit JOB RULE --confirm 或 list。submit 外层 effect:unknown，表示接收请求可能已启动写操作；只读 jobs 外层 effect:none。报告本身的 effect:none 表示读取摘要，真实历史影响看 last_effect/result.effect；pending 或 interrupted 绝不能解释为成功。无结果用 result:false，避免 Lua 空表/null 兼容歧义。

任务固定保留于 /var/run/homegate/ddns-ui-jobs，私有目录 700、普通单链接文件 600；单文件不超过 65536 字节，摘要帧不超过 4096 字节，至多 8 个任务、每任务至多 6 个已知成员。新任务需无活动/未决/unknown 任务，且现有单规则状态 ready/stale。目录分配由独立空文件目录锁序列化；每任务空文件锁随父子继承。只读 list 不申请 frontend/supervisor 业务锁，不新建目录或锁，故实际操作期间仍能轮询。损坏、链接、未知成员或超过界限时整体拒绝，保留原字节。

先在原业务锁 6/7 内记录规则、供应商、配置版本、身份/代 manifest/授权文件摘要、boot、单调时刻及 300 秒启动期限。元数据为 HGDDNSUIJOB1 两行体加 SHA256 帧。父入口持有任务锁 8 后启动固定 setsid ash 子进程，关闭子进程的目录锁 9 和标准流，不等待。接受以后即保留记录；启动失败、进程中断、结果发布失败都不删除记录或尝试重新启动。无 PID 文件、无按存储 PID 发信号逻辑。

固定 work 内部命令必须继承与已验证文件 inode 相同的 6/7/8，且独占创建一次 start 文件。启动前重新检查摘要、boot 和期限；变化则保存 blocked/none 的已知未派发结果。实际仅调用已有 homegate-ddns-state.sh sync RULE --confirm，复用其来源/授权、状态间隔、供应商执行与 watchdog、持久回执屏障；不调用会关闭公共入口 FD 的 CLI，不增加采样、供应商代码或后台循环。结果通过已有 ddns-batch/ddns-sync 的严格规范响应转换为七字段脱敏行，再保存 HGDDNSUIRESULT1 SHA256 帧并原子发布。不能验证的执行响应记 failed/unknown，原持久记录保留。

list 返回按任务标识排序的最多 8 个精确摘要：job/rule/configuration_revision/pending/state/result/last_effect/reason 及公共固定字段。任务锁仍被持有即 pending；锁释放且无有效结果即 interrupted/unknown；有效结果才 finished，并展示 created/updated/unchanged/failed 或原状态。观察进程不自动等待、领养、重试、删除或收尾。相同标识/规则永远只返回已有摘要，改规则拒绝；满 8 份后需要后续明确维护。普通 CLI 仍受原全局持久写屏障；UI 额外拒绝未决任务。

生命周期 prepare/resume 在既有 admission 锁及业务锁内，对已存在任务目录执行不依赖 UI 门禁的 check-quiescent；schedule-quiescent 同样检查。未决/unknown 任务不能被空闲锁掩盖，无清理动作。RAM 记录随重启丢失，原持久回执仍由原机制核实；本协议没有可继承的收尾同意。保留任务的明确维护/回收、页面收尾与生产生命周期接管另行开发。

页面初次读取和手动刷新恢复保留摘要，不将任务标识或授权 nonce 放入 URL/浏览器存储。提交期间按钮锁定，相同按钮双击只发一次 submit；响应不确定后只读 jobs，找到原任务才消除提交不确定提示。pending 时 1 秒一次、最多 180 次自动只读轮询，达到上限或读取异常后暂停，用户手动刷新仍只读。轮询不重发 submit，不自动收尾。unknown、中断、满容量禁止新提交；confirmed 仍说明需要原入口明确收尾。

本地 Linux 采用现有非 root 四供应商 TLS/网络边界夹具，生产 root/owner 不改；浏览器实际 Edge，HTTP/RPC 为明确边界夹具。目标 ucode/rpcd 执行与设备权限尚待验证，不能由源码检查替代。本次不安装依赖、不运行远端 CI、不接真实供应商。


## r76 明确维护扩展

新增独立关闭门禁的维护预览与一次性确认，仅归档已绑定的 confirmed 原回执或释放 known-none 原明细，见 [DDNS明确维护](DDNS明确维护.md)。单次同步不会自动收尾，任务标识预算仍8，旧r75无proof的已确认任务不能补造来源。

## r78 观察与发布互斥

只读观察先验证不可变meta与私有任务锁的来源和inode。锁由工作进程持有时，只返回pending/unknown的保守摘要，不枚举或读取正在发布的raw/result等可变成员，不将部分文件当成完成结果。不能取得任务锁同样不能允许维护、新任务或生命周期静止结论。

取得任务锁后才按原白名单、11成员/64KB及帧4KB上限检查全部成员、有效result及维护标记。此时工作进程不能同时rename结果文件，避免枚举与发布之间的暂态错误；损坏、链接、额外成员或不完整结果继续拒绝或保守报告中断，原证据不清理。字段、ACL、POST/CSRF、去重、未知结果屏障和8标识预算均保持原协议。
