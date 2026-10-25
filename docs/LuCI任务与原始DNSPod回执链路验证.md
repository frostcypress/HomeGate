# LuCI 任务与原始 DNSPod 回执链路验证

`scripts/luci-ddns-dnspod-jobs-regressions.py` 使用真实Lua HTTP任务、原work/状态协议、固定curl7.83.1及回环TLS产生DNSPod结果。独立Python HMAC-SHA256按原始请求体、UTC日期、服务scope和固定host校验TC3签名，核对POST路径、Content-Type及X-TC版本；签名URL、认证头和请求体不进入测试事件日志。

四项检查：相同值none且无持久尝试；创建confirmed及原始proof；更新confirmed且保留Line/LineId、Weight、Remark和其他记录；写请求改变夹具记录但响应失败时保持unknown、原回执且无proof，同ID和新ID均不得重发。proof必须绑定dns_2的原manifest/terminal SHA，原回执必须为HGDNPJOURNAL1。

共享签名任务夹具只提取HTTP处理器工厂、规则/账号/回执格式属性和固定供应商端点选择；Aliyun默认行为保留并定向回归创建和归档。DNSPod启用自身read/records/receipt/settlement开关，CF receipt模式关闭；原业务、ACL、配方和生产/候选开关字节不变，仅在临时副本启用必要链路。签名工具副本、root/owner、FD、锁、CA/SNI、HTTP和任务超时均不放宽。

新增四项纳入原receipts组，调度合同为13脚本/99场景；其他组及每CI任务25分钟上限不变。本阶段仅DNSPod的Lua任务与原回执隔离宿主链路；明确归档、RPC、生产接管、目标SDK/ABI、真实三包和实机仍待验收，不访问公网DNS或真实账号，不自动重试或收集原回执。
