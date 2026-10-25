# LuCI 已确认任务与原 Aliyun 回执归档链路验证

`scripts/luci-ddns-aliyun-archive-regressions.py` 先用真实Lua任务、独立HMAC签名校验、固定curl7.83.1及回环TLS生成Aliyun confirmed、原HGALIJOURNAL1与任务proof，再通过Lua POST/CSRF预览与新同意归档。没有构造confirmed、proof或替换归档器。

复用已有六项归档合同：原始回执/任务保留；nonce及proof/raw/原manifest/terminal绑定；锁与维护门禁；收集器失败后原回执保留且旧同意失效；归档完成但maintained.next发布失败后不能冒称完成，必须新预览/新同意；unknown尝试拒绝维护。归档期间不再次请求供应商，原始字节、任务标识、历史confirmed保留，不自动退役归档。

共享夹具只提取归档开关与受控fsync失败点的启用函数，并让报告规则从测试类读取；默认Cloudflare仍使用原规则及原开关。Aliyun同时满足共用reconcile门禁和自身receipt/settlement/reconcile开关，CF receipt模式保持关闭；签名工具副本、私有属主/权限、FD、锁、CA/SNI和超时不放宽。受影响Cloudflare正常归档另作本地回归。

六项加入既有receipts组，调度合同为11脚本/85场景；其他两组、每任务25分钟及每场景90秒限制不变。本阶段仅Aliyun的Lua明确归档隔离宿主验证；RPC、生产接管、目标SDK/ABI、真实三包和实机仍待验收，不使用公网DNS或真实账号。
