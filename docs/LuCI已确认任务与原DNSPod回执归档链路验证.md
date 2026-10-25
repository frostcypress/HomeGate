# LuCI 已确认任务与原 DNSPod 回执归档链路验证

`scripts/luci-ddns-dnspod-archive-regressions.py` 通过真实Lua任务、独立TC3验证、固定curl7.83.1/回环TLS产生confirmed、原HGDNPJOURNAL1与task proof，再经Lua POST/CSRF明确预览和新同意归档。没有构造成功结果、proof或替换归档器。

复用六项既有合同：原回执/任务保留；nonce及proof/raw/manifest/terminal绑定；锁与维护门禁；收集器失败后旧同意失效、原回执保留；归档完成但maintained.next发布失败后不得冒称完成，必须新预览/新同意；unknown拒绝维护。原始字节、任务标识和历史confirmed保留，维护阶段不再请求供应商，不自动退役归档。

共用夹具仅增加DNSPod的reconcile开关选择，仍同时要求共用reconcile门禁；Cloudflare及Aliyun默认行为保持，并定向回归正常归档。DNSPod使用自身receipt/settlement，CF receipt模式保持关闭。原root/owner、签名工具、FD、锁、CA/SNI及超时检查不放宽；完成标记故障仍仅使当前maintained.next的fsync失败，其余调用原BusyBox。

新增六项纳入原receipts组，调度合同为14脚本/105场景；各任务25分钟上限保持，新增专项的累计耗时须在下一次CI投递前核对并必要拆组。本阶段仅DNSPod Lua归档的隔离宿主验证；RPC、生产接管、目标SDK/ABI、真实三包和实机仍待验收，不访问公网DNS或真实账号。
