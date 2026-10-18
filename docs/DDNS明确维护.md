# DDNS 任务的明确维护候选协议

r76 候选，门禁关闭；不由生产配方安装。沿用单次异步任务的私有请求、业务锁与保留摘要。增加 maintain_preview(job) 和 maintain_commit(job,confirmation,consent:"1")，均属写权限，Lua 要求当前会话 POST/CSRF，JS rpcd 使用独立 write ACL。两步分别请求，不继承授权或单次同步时的同意。

仅允许已经完成且历史影响已知的任务。confirmed 选择 archive：把本次任务对应的原持久回执归档到已有 dns-settled；none 选择 compact：仅释放该任务的 raw 明细，保留元数据、结果、锁与任务标识。pending、interrupted、unknown 均拒绝维护；不重试 DNS、不修复未知终态、不删除持久归档、不自动回收任务标识。本次启动累计 8 个任务标识预算不变。

新任务在持有原业务锁时，针对 confirmed 结果验证原供应商 manifest、canonical terminal 及本次 canonical DDNS 结果相等，记录原 account/job 与原 manifest/terminal 的 SHA256 帧 proof。没有此绑定的旧任务保留原数据，不能从相同规则或“当前看起来相同”的回执补造来源。

维护取得目录锁9、业务锁6/7、任务锁8，重核目录成员、普通来源、当前配置版本/身份/代manifest/授权摘要/boot；只读查询仍不取业务锁。预览将任务、meta/result/raw/proof 摘要、操作、boot 与内核随机 nonce、单调300秒期限绑定到 HGDDNSUIMAINTENANCE1 私有 SHA256 帧。新预览使旧 nonce 失效；commit 严格检查精确同意与全部绑定，并先把 nonce 移到 maintenance-used，不能因响应丢失再次使用。

archive 前验证当前 dns-operation 或已归档 dns-settled 的原始来源与本任务 proof 完全相等，再仅调用原 --runtime-collect-receipt-internal。原收集器继续独立验证来源、context/checkpoint/terminal、活跃请求与归档协议；无新的 HTTP。已归档时可用新的预览和同意继续确认结果发布，不把旧 nonce 当恢复许可。未完成 maintained.next 只在新的确认下、与当前 meta/result/操作完全一致时继续发布；损坏阶段保留并拒绝。

compact 只在已知 none 的结果上删除该任务的私有单链接 raw；若删除后最终摘要发布失败，可重新预览缺失 raw 的已知结果并另行确认。完成标记 HGDDNSUIMAINTAINED1 绑定 meta/result 和操作，列表分别显示 reason:archived 或 compacted，last_effect 仍保留历史 confirmed/none。相同任务标识不能重新派发，维护不清除原 provider/outer/state 屏障。

每任务最多11个成员，每成员沿用64KB上限，摘要帧4KB。页面只对已知完成任务显示“预览维护”；预览后必须重新勾选同意并点击确认，选择、刷新、关闭或异常使待确认 nonce 失效。动态值使用原生DOM文本，不进URL或浏览器存储；未知响应只读刷新，不自动重复维护。未决预览阶段、损坏原证据以及缺少 proof 的旧 confirmed 任务继续保留，需后续明确恢复或原手动维护入口。

候选协议不能代替真实 ucode/rpcd、目标 LuCI、SDK/ABI、同源三包或路由器验证。当前仍无任务标识回收、持久归档清除或生产接管权限。
