# LuCI 任务与原始华为云回执链路验证

`scripts/luci-ddns-huawei-jobs-regressions.py` 通过真实Lua任务、原work/状态协议、固定curl7.83.1及回环TLS产生华为云结果。独立Python SDK-HMAC-SHA256校验真实请求的方法、路径、查询、正文、固定Host、X-Domain-ID和X-Sdk-Date；私有认证头、正文和域标识不进入事件日志或公共任务摘要。

四项检查：相同值none且无持久尝试；创建confirmed及原proof；更新confirmed并保留description及其他recordset；写请求已改变夹具记录但响应失败时保持unknown、原回执且无proof，同ID/新ID不得重发。proof绑定dns_3原manifest/terminal SHA，原回执格式必须为HGHWJOURNAL1；202创建/更新响应需经原业务读回确认，不能直接构造confirmed。

共用签名夹具只增加固定华为云端点和对应门禁选择，Aliyun/DNSPod默认行为保留并定向回归。仅临时旧配置为华为云账户设置32位占位域标识和固定区域端点，再执行真实迁移/投影；不放宽原配置校验。原业务、ACL、配方和生产/候选开关字节不变，仅临时副本启用自身read/records/receipt/settlement并关闭CF receipt模式；root/owner、签名工具、FD、锁、CA/SNI和超时保留。

新增四项纳入原receipts组，调度合同为16脚本/119场景。每CI任务25分钟上限保持，下一次投递前须复核累计用时并拆分过大的receipts组。本阶段仅华为云Lua任务与原回执隔离宿主链路；明确归档、RPC、生产接管、目标SDK/ABI、真实三包和实机仍待验收，不使用公网DNS或真实账号，不自动重试或收集原回执。
