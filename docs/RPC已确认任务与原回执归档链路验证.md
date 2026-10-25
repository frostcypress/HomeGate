# RPC 已确认任务与原回执归档链路验证

`scripts/rpc-ddns-archive-regressions.py` 通过真实HTTP会话ACL、rpcd参数检查和候选ucode/fs私有请求调用原Shell任务与归档协议。原confirmed、持久回执和任务proof由固定curl7.83.1及回环TLS Cloudflare协议产生，不补造结果或替换归档器。

十个独立namespace中，六个复用Lua阶段的原始字节保留、nonce/来源绑定、锁/门禁、收集器拒绝、归档后完成标记中断及unknown拒绝场景；四个增加参数类型/明确同意、reader/匿名/失效会话/会话字段注入、Bearer预览与旧入口确认/重放、批量逐元素授权及同意仅消费一次。拒绝的身份不得进入后端或消费确认帧；已归档任务仍可只读观察，历史confirmed和原始证据保留，维护不得重新请求供应商。

只将已有RPC隔离夹具的ACL接线与HTTP启动提取为共享函数，既有只读启动顺序和超时不变；新链路复用18秒HTTP上限、90秒单场景上限。原业务代码、候选/生产开关、ACL与配方不变，仅临时副本开启必要开关。归档中断使用前阶段仅针对maintained.next的fsync失败夹具，其他fsync仍执行原BusyBox。

这是Cloudflare隔离宿主链路验证，不访问公网DNS，不自动退役原始归档。其他三家此链路、生产接合、目标SDK/ABI、真实三包和实机仍待验收；实际本地与CI结果分别记录。
