# LuCI 已确认任务与原回执归档链路验证

`scripts/luci-ddns-archive-regressions.py` 先经真实任务、固定curl与回环TLS产生Cloudflare confirmed结果、原持久回执及任务proof，再通过真实Lua POST/CSRF预览和单独确认调用原archive协议。没有构造confirmed、补造proof或替换归档结果。

六项分别检查：原回执归档且保留任务/历史confirmed；新nonce与raw/proof/原manifest/terminal绑定；目录/业务/任务锁及维护门禁；收集器拒绝后旧同意失效、原回执保留且需新预览；归档已完成但maintained发布失败时不能冒称完成、需新同意完成原标记；unknown尝试始终拒绝维护。

中断夹具只对当前任务maintained.next的fsync注入失败，其他调用仍exec原BusyBox fsync。原协议实际完成dns-operation→dns-settled，测试核对原文件字节在归档中保留；重获预览/同意后完成标记，不重写原归档、不再调用供应商。保留meta/result/proof/raw及任务标识，last_effect仍为历史confirmed；未发布的完成标记不能释放名额或显示archived。

全部操作在一次性namespace，复用前阶段固定TLS传输及采样夹具；权限、来源、FD和锁不放宽。原业务/候选门禁、ACL和配方字节不变，仅副本开启必要归档开关。每个场景保留90秒上限；不访问公网DNS，不自动退役或删除原始归档。入口纳入已有原生UI专项，实际本地/CI结果另存。

本阶段仅Lua及隔离Cloudflare来源。RPC归档权限、其他三供应商此链路、生产接管、目标SDK/ABI、三包、实机与资源仍待后续。
