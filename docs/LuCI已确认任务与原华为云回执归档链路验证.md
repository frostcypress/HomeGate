# LuCI 已确认任务与原华为云回执归档链路验证

`scripts/luci-ddns-huawei-archive-regressions.py` 先通过真实Lua任务、独立SDK-HMAC、固定curl7.83.1/回环TLS产生confirmed、原HGHWJOURNAL1及task proof，再通过Lua POST/CSRF明确预览和新同意归档，不补造成功证据或替换归档器。

六项复用既有合同：原回执/任务保留；nonce及proof/raw/原manifest/terminal绑定；锁与维护门禁；收集器失败后旧同意失效且原回执保留；归档完成但maintained.next发布失败后不得冒称完成，必须新预览/新同意；unknown拒绝。原始字节、任务标识和历史confirmed保留，维护不再次请求供应商，不自动退役归档。

共用归档夹具只增加huaweicloud的固定供应商选择，仍同时检查共用及自身reconcile门禁；既有Cloudflare、Aliyun、DNSPod选择与默认行为不变，定向回归Cloudflare/DNSPod正常归档。华为云任务夹具保持原字节，使用自身receipt/settlement和原配置校验，CF receipt关闭；root/owner、签名工具、FD、锁、CA/SNI及超时不放宽，故障点仍仅使当前maintained.next的fsync失败。

六项加入原receipts组，调度合同为17脚本/125场景；任务25分钟上限保持，下一次投递前必须按累计用时拆分过大的receipts组。本阶段只验证华为云Lua归档隔离宿主链路；RPC、生产接管、目标SDK/ABI、真实三包和实机仍待验收，不使用公网DNS或真实账号。
