# LuCI 任务与原始 Aliyun 回执链路验证

`scripts/luci-ddns-aliyun-jobs-regressions.py` 使用真实Lua HTTP提交、原任务/work/状态协议、固定curl7.83.1及私有回环TLS生成Aliyun结果。独立Python HMAC-SHA1校验原Lua/openssl签名，核对固定版本、签名参数、唯一nonce与时间戳格式；不记录原始签名URL或凭据。

四个场景检查：相同值none且无持久尝试；创建confirmed及原始proof；更新confirmed且保留自定义Line、Remark、Weight及其他记录；写请求已改变夹具记录但响应失败时保留unknown、原回执且无proof，同ID/新ID均不得重发。confirmed proof必须与dns_0原manifest/terminal SHA一致，manifest必须为HGALIJOURNAL1，不能使用Cloudflare回执格式冒充。

复用此前隔离任务、固定采样和受限curl传输夹具，临时证书及固定connect-to目标改为alidns.aliyuncs.com。原URL/SNI、CA验证、超时、root/owner、FD、锁和来源约束保留；临时副本关闭CF receipt模式、仅启用Aliyun必要receipt/settlement开关。所有任务与回执保留到一次性namespace销毁，不调用收集器、不自动重试或归档退役。

新增四场景纳入已有receipts组；其他两组边界及任务25分钟上限不变，调度合同更新为10脚本/79既有与新增场景。实际本地/CI证据分开记录。本阶段只验证Aliyun的Lua任务结果与原回执，明确归档、RPC归档、生产接管、目标SDK/ABI、真实三包和实机仍待验收；不访问公网DNS或真实账号。

## r115 指定接口与混合授权任务

原任务脚本新增05–09：真实Lua/HTTP会话确认Aliyun/interface(ddns_0)+Cloudflare/auto(ddns_1)混合授权，仅执行选中Aliyun任务。指定接口与默认WAN地址不同；无变化不写、真实创建保留HGALIJOURNAL1及原task proof、接口缺失known-none且无请求/proof、CSRF与预览后接口变化拒绝、写后响应失败unknown不重试/不补造成功。

共用地址夹具只增加固定规则选择，Aliyun的独立HMAC-SHA1校验、真实签名工具副本、固定curl/TLS/CA/SNI、原worker与回执保持。新增场景纳入原Aliyun native组，仍18秒HTTP/90秒隔离上限；实际结果仅本地登记。Aliyun RPC指定接口、DNSPod/华为云指定接口Web链路、生产/目标SDK/三包和实机仍待独立验收。
