# LuCI 任务与原始供应商回执链路验证

`scripts/luci-ddns-provider-jobs-regressions.py` 使用真实Lua HTTP提交、原后台work/状态/调度与来源协议、固定curl7.83.1和独立回环TLS服务，验证Cloudflare协议的无变化、创建、更新及请求后未知结果。meta、result、raw、持久checkpoint/terminal及来源proof都必须由原业务产生，不手工构造confirmed或归档来源。

沿用既有Cloudflare隔离协议响应及保留字段条件。采样工具只返回夹具地址/路由；固定/usr/bin/curl传输夹具严格检查唯一原始HTTPS URL及受限配置文件，仅添加到本namespace回环端口的connect-to。原worker固定路径、root/owner、TLS校验、超时、锁和调用参数保持；CA只在夹具/etc内信任api.cloudflare.com测试证书，不使用insecure、不访问公网。curl本体为既有固定版本实际二进制，不替换HTTP结果。

四个独立namespace分别检查：无变化只读无持久尝试；创建后的原始持久回执/proof摘要与同任务绑定；更新保留无关字段；模拟服务已处理写入但返回失败时仍报告unknown、保留原回执且不重试。每个场景保留90秒总限，任务等待有界；只读重放不能改变原任务/回执或再次发请求。

原型代码仅在副本开启必要DDNS/Cloudflare开关，服务动作、其他供应商、维护与发布门禁不打开。保留私有UID0/零capabilities、原文件权限与来源验证。测试结束保留任务和回执直到整个一次性namespace销毁，不调用收集器伪装业务归档。报告不包含凭据、会话、确认码或私有请求正文。

本阶段只证明隔离Cloudflare协议及原始回执接合；公网DNS、其他三供应商的此链路、confirmed维护archive、生产接管、目标SDK/ABI、三包及实机仍待分别验收。实际本地和CI结果另存。

## r113 Lua/HTTP混合授权与指定接口任务

原Cloudflare任务脚本新增05–09独立隔离场景：真实Lua会话及POST/CSRF确认auto/interface混合授权；指定接口无变化只读、创建保留原回执及来源proof、接口缺失不后备到默认WAN、CSRF/接口变更拒绝确认、写后未知结果保留证据且不重试。实际任务仍只执行选中ddns_1，未执行混合授权中的其他供应商。

仅临时配置将Cloudflare规则设置为interface=odd-uplink，固定地址命令的夹具同时提供不同默认WAN地址；实际curl7.83.1、CA/SNI、原worker和原任务proof保持。各场景仍遵守18秒HTTP及90秒隔离上限。新增场景加入原receipts-cloudflare组，不改变其他组或SDK门禁。详细结果本地登记，不能据此标记RPC混合、其他供应商指定接口Web任务、生产/目标SDK/三包或实机通过。

任务结果的network_unavailable状态只接受effect=none、error_kind=network_unavailable、retryable=true、retry_in=0的规范组合。未知效果、错误类型、等待值及额外字段均拒绝；规范预检失败不再误报unknown。真实写后未知结果仍保持原回执/任务及拒绝重试屏障，不降为无变更。
