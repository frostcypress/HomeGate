# HTTP/RPC 与 Shell DDNS 明确维护链路验证

`scripts/rpc-ddns-maintenance-regressions.py` 经真实HTTP会话ACL、rpcd参数检查、ucode/fs私有请求和原Shell维护协议，验证已知未派发任务的compact。七项复用Lua维护条件：明确压缩、nonce/同意与重放、来源绑定、pending/unknown拒绝、锁忙/门禁、预览阶段恢复和损坏/链接阶段保留。另四项检查RPC类型与明确同意、reader/匿名/销毁会话/会话字段注入拒绝、Bearer预览与旧式确认/重放、批量逐元素授权及nonce只消费一次。

无权请求不能进入私有后端或消费待确认帧；只读账号可以观察任务但不能预览/提交维护。HTTP成功、JSON-RPC权限错误、ubus参数错误及业务拒绝分别核对。成功只删除受控raw明细样本，保留真实原worker产生的meta/result、历史none、任务标识及维护完成标记，不启动新任务或DNS动作。

复用既有私有namespace与启动时序夹具；不伪造成功DNS结果、confirmed来源proof或原回执。会话/确认码/凭据不输出，私有请求0700/0600并清理，拒绝逐次核对原证据不变。三个namespace分别保留90秒，HTTP沿用18秒；原生产、候选门禁、ACL及配方保持原字节。

入口加入现有原生UI专项，不增加源码组负担或自动运行CI。confirmed原持久回执archive、真实DNS、生产接管、SDK/ABI、三包及实机/资源仍待分别验收，实际本地和CI结果另存。
