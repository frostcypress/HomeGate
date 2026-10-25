# RPC 已确认任务与原 Aliyun 回执归档链路验证

`scripts/rpc-ddns-aliyun-archive-regressions.py` 使用真实HTTP会话ACL、rpcd参数检查和候选ucode/fs私有请求执行Aliyun授权、任务与明确归档。原confirmed、HGALIJOURNAL1及task proof由真实任务、独立HMAC签名验证、固定curl7.83.1与回环TLS产生；不补造成功结果、proof或替换归档器。

十个独立namespace复用既有RPC归档合同：原始证据保留；nonce/来源绑定；锁和门禁；收集器拒绝后旧同意失效；归档后完成标记中断要求新预览/新同意；unknown拒绝；参数类型及明确同意；reader/匿名/失效会话/会话字段注入；Bearer预览与旧入口确认/重放；批量逐项授权及同意只消费一次。无权身份不得进入后端或消费待确认帧，reader可只读观察历史结果；原始字节、任务标识和历史confirmed保留，维护阶段不再请求供应商。

将原RPC夹具的传输方法及测试合同提取为共用基类，Cloudflare默认规则仍为ddns_1，Aliyun明确使用ddns_0。启动顺序、真实HTTP/RPC服务、18秒HTTP及90秒单场景上限保持；受影响Cloudflare正常归档和Bearer场景另做定向回归。原业务、候选/生产开关、ACL和配方字节不变，仅临时副本启用原必要开关，签名工具属主、FD、锁和TLS验证不放宽。

十项加入原receipts组，调度合同为12脚本/95场景；其他两组及每CI任务25分钟上限不变，后续累计耗时仍需按实际证据检查。本阶段仅隔离Aliyun HTTP/RPC宿主链路；生产接管、目标SDK/ABI、真实三包和实机仍待验收，不使用公网DNS或真实账号。
