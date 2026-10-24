# DDNS 任务的明确维护候选协议

## 当前 r79：明确维护释放任务名额

r79将容量分为8份未维护任务和本次启动累计32个保留标识，替代下面r76/r78历史的8标识预算。新的维护动作、授权或自动收集器均未增加：仍须原来源预览、新nonce、单独同意和commit，完整发布且验证maintained后才释放一个名额。旧meta/result/任务标识以及confirmed的proof与原持久归档继续保留；旧标识不能重新派发。known-none仍只释放raw，confirmed仍只归档原回执。详见[任务容量约束](DDNS单次异步任务.md)。

仅预览、尚未发布maintained的commit中断、raw已删除或回执已归档但maintained尚未发布均不能释放名额。若确认响应丢失，仅刷新读取；已完整发布并能严格验证的最终标记可显示维护完成，不自动重发commit。已维护记录出现未完成maintenance/maintenance.next/maintained.next、损坏绑定或链接时拒绝容量准入并保留证据。pending/interrupted/unknown不接受维护、不自动清理，且继续阻止新任务。32个标识满后停止接受新标识，保留旧标识的被动查询和去重；不把删除或重启当作解除持久屏障的步骤。生产接管和真实设备验证仍待办。

r76 协议，r78 增加预览暂存帧的明确恢复；门禁关闭，不由生产配方安装。沿用单次异步任务的私有请求、业务锁与保留摘要。maintain_preview(job) 和 maintain_commit(job,confirmation,consent:"1") 均属写权限，Lua 要求当前会话 POST/CSRF，JS rpcd 使用独立 write ACL。两步分别请求，不继承授权或单次同步时的同意。

仅允许已经完成且历史影响已知的任务。confirmed 选择 archive：把本次任务对应的原持久回执归档到已有 dns-settled；none 选择 compact：仅释放该任务的 raw 明细，保留元数据、结果、锁与任务标识。pending、interrupted、unknown 均拒绝维护；不重试 DNS、不修复未知终态、不删除持久归档、不自动回收任务标识。本次启动累计 8 个任务标识预算不变。

新任务在持有原业务锁时，针对 confirmed 结果验证原供应商 manifest、canonical terminal 及本次 canonical DDNS 结果相等，记录原 account/job 与原 manifest/terminal 的 SHA256 帧 proof。没有此绑定的旧任务保留原数据，不能从相同规则或“当前看起来相同”的回执补造来源。

维护取得目录锁9、业务锁6/7、任务锁8，重核目录成员、普通来源、当前配置版本/身份/代manifest/授权摘要/boot；只读查询仍不取业务锁。预览将任务、meta/result/raw/proof 摘要、操作、boot 与内核随机 nonce、单调300秒期限绑定到 HGDDNSUIMAINTENANCE1 私有 SHA256 帧。新预览使旧 nonce 失效；commit 严格检查精确同意与全部绑定，并先把 nonce 移到 maintenance-used，不能因响应丢失再次使用。

archive 前验证当前 dns-operation 或已归档 dns-settled 的原始来源与本任务 proof 完全相等，再仅调用原 --runtime-collect-receipt-internal。原收集器继续独立验证来源、context/checkpoint/terminal、活跃请求与归档协议；无新的 HTTP。已归档时可用新的预览和同意继续确认结果发布，不把旧 nonce 当恢复许可。未完成 maintained.next 只在新的确认下、与当前 meta/result/操作完全一致时继续发布；损坏阶段保留并拒绝。

compact 只在已知 none 的结果上删除该任务的私有单链接 raw；若删除后最终摘要发布失败，可重新预览缺失 raw 的已知结果并另行确认。完成标记 HGDDNSUIMAINTAINED1 绑定 meta/result 和操作，列表分别显示 reason:archived 或 compacted，last_effect 仍保留历史 confirmed/none。相同任务标识不能重新派发，维护不清除原 provider/outer/state 屏障。

每任务最多11个成员，每成员沿用64KB上限，摘要帧4KB。页面只对已知完成任务显示“预览维护”；预览后必须重新勾选同意并点击确认，选择、刷新、关闭或异常使待确认 nonce 失效。动态值使用原生DOM文本，不进URL或浏览器存储；未知响应只读刷新，不自动重复维护。损坏原证据以及缺少 proof 的旧 confirmed 任务继续保留并拒绝维护。

## r78：维护预览发布中断

maintenance.next 可能在 fsync 或 rename 中断后保留。只读列表不改变它；只要存在此暂存成员，maintain_commit 就拒绝全部旧确认码，不能将尚未发布的 nonce 当成用户已收到的许可。

用户再次明确请求 maintain_preview 时，仍先取得原目录、业务和任务锁，验证已知结果、普通来源、当前配置/授权/boot，以及 confirmed 时的原回执 proof。存在的 maintenance 与 maintenance.next 必须都是完整 canonical SHA256 帧，精确匹配当前 job/meta/result/raw/proof/operation/boot；确认后缀必须与 nonce:start:finish 的重组串逐字相等，不能由 Shell 字段拆分忽略尾分隔符、空白或额外空字段。时间必须是规范非负整数，start 不早于任务创建、不晚于当前单调时间，finish=start+300。旧帧可以已过期，但不能来自未来、其他来源或另一任务。任一校验失败，全部原成员保留，不能靠重新预览覆盖损坏证据。

全部验证通过后，先把旧 maintenance 移至 maintenance-used 并同步，再把 maintenance.next 移至同一个已使用槽并同步，最后按原发布协议创建一个不同于这两帧的新随机 nonce，提供新的300秒预览。maintenance-used 只保留已失效的确认帧，从不作为提交许可。恢复移动/同步失败时，仍留下阻止旧提交的暂存帧，或已经没有已发布确认码；再次发布新帧失败同样保留暂存成员。用户必须重新取得成功的预览响应、重新勾选同意，再提交这个新 nonce。没有自动续做归档、DNS重发、删除未知证据或继承原同意。

此恢复只处置有完整当前绑定的预览确认帧，不修复损坏任务结果、原回执或缺失 proof，不回收任务标识。原 raw、meta、result、proof 与持久操作/归档在预览恢复阶段不变；known-none 压缩、confirmed 原回执归档仍只发生在随后新的明确提交中。原 maintained.next 的新同意发布续做协议继续有效。

候选协议不能代替真实 ucode/rpcd、目标 LuCI、SDK/ABI、同源三包或路由器验证。当前仍无任务标识回收、持久归档清除或生产接管权限。
