# LuCI 与 Shell DDNS 明确维护链路验证

`scripts/luci-ddns-maintenance-regressions.py` 经真实Lua CGI会话、POST/CSRF、私有请求、Shell UI及原维护协议检查已知未派发任务的compact。原worker按来源变化生成meta/result及blocked/none；仅额外加入一份受控raw明细样本，验证确认前保留、确认后只释放明细。没有构造成功DNS结果或confirmed来源proof。

八项覆盖：预览/明确提交及保留任务标识；新nonce替换、独立同意和重放拒绝；raw/授权摘要及任务绑定；pending/interrupted/unknown拒绝；POST/CSRF和精确字段；目录/业务/任务锁忙及门禁；待发布确认帧要求新预览和新同意；损坏/链接阶段保留。维护成功保留meta/result/lock、历史last_effect:none和任务ID，旧ID不能重派发。

发布中断场景将原后端产生的确认帧移到原maintenance.next槽，模拟写入完成但未发布，不改帧内容。原协议必须拒绝旧提交，明确重新预览后生成新nonce，再由用户单独同意提交。损坏或链接阶段不得靠重新预览覆盖。测试不自动维护unknown，也不把只读刷新当作同意。

沿用非root外层、私有UID0及全零capabilities，只写夹具，保留原固定路径、权限、FD与锁。请求0700/0600并清理，秘密、会话和确认码不输出。每组保留90秒，HTTP沿用18秒。入口在已有原生UI专项，不新增自动CI或源码组负担。

confirmed原持久回执的archive接合、RPC维护、真实DNS、生产接管、目标SDK/ABI、三包及实机/资源仍待后续。实际本地与CI结果另存，文档不代替通过证据。
