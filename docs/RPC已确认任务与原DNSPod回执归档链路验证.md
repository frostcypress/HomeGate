# RPC 已确认任务与原 DNSPod 回执归档链路验证

`scripts/rpc-ddns-dnspod-archive-regressions.py` 经真实HTTP会话ACL、rpcd参数检查及候选ucode/fs私有请求执行DNSPod授权、任务和明确归档。原confirmed、HGDNPJOURNAL1与task proof由真实任务、独立TC3、固定curl7.83.1和回环TLS产生，不补造结果或替换归档器。

复用十项RPC合同：原回执/任务保留；nonce及原来源绑定；锁/门禁；收集器拒绝后旧同意失效；归档完成但完成标记发布失败时需新预览/新同意；unknown拒绝；参数类型及明确同意；reader/匿名/失效会话/会话字段注入；Bearer预览与旧入口确认/跨入口重放；批量逐元素授权及同意仅消费一次。无权身份不得进入后端或消费确认帧，reader可以只读观察历史结果；维护不再次请求供应商，原始字节、任务标识和历史confirmed保留。

启动器只将既有RPC传输合同与DNSPod实际任务/归档夹具组合，规则明确为ddns_2。共用传输、原Cloudflare/Aliyun及DNSPod Lua任务/归档脚本字节不变；原业务、候选/生产开关、ACL、配方不变，仅临时副本启用必要链路。保留18秒HTTP、90秒单场景上限和原root/owner、FD、锁、签名工具及TLS检查。

十项加入原receipts组，调度合同为15脚本/115场景。各CI任务25分钟上限保持；下一次投递前须复核新增链路累计用时并拆分过大的receipts组。本阶段仅隔离DNSPod HTTP/RPC宿主链路；生产接管、目标SDK/ABI、真实三包及实机仍待验收，不访问公网DNS或真实账号。
