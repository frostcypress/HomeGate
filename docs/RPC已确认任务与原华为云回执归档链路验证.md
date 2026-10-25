# RPC 已确认任务与原华为云回执归档链路验证

`scripts/rpc-ddns-huawei-archive-regressions.py` 经真实HTTP会话ACL、rpcd参数检查及候选ucode/fs私有请求执行华为云授权、任务和明确归档。原confirmed、HGHWJOURNAL1及task proof由真实任务、独立SDK-HMAC、固定curl7.83.1与回环TLS产生，不补造成功证据或替换归档器。

复用十项RPC合同：原回执/任务保留；nonce及原来源绑定；锁与门禁；收集器拒绝后旧同意失效；归档后完成标记发布失败需新预览/新同意；unknown拒绝；参数类型及明确同意；reader/匿名/失效会话/会话字段注入；Bearer预览与旧入口确认/跨入口重放；批量逐元素授权及同意仅消费一次。无权身份不得进入后端或消费确认帧，reader可以观察归档历史；原始字节、任务标识和历史confirmed保留，维护阶段不重新请求供应商。

启动器只组合既有RPC传输合同与实际华为云任务/归档夹具，明确规则ddns_3。共用传输和既有CF/Aliyun/DNSPod/华为云Lua脚本字节不变；原业务、候选/生产开关、ACL及配方不变，仅临时副本启用必要链路。保留18秒HTTP、90秒单场景上限，以及原root/owner、FD、锁、签名工具与TLS检查。

十项进入原receipts组，调度合同为18脚本/135场景。各CI任务25分钟上限保持，第10步须按累计用时拆分过大的receipts组并完成本地验证；之后下一轮单独投递CI。此阶段仅隔离华为云HTTP/RPC宿主链路；生产接管、目标SDK/ABI、真实三包和实机仍待验收，不使用公网DNS或真实账号。
