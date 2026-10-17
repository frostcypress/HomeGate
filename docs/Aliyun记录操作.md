# Aliyun 配置绑定 AAAA/TXT 操作

r44增加独立门禁的只读核对与变更前持久检查点，见 [Aliyun恢复与持久回执.md](Aliyun恢复与持久回执.md)。下文“仅同启动期”等段落描述r43阶段；当前仍没有Aliyun终态结算/解除屏障。

关闭门禁的未安装原型：`homegate-aliyun-read.sh ACCOUNT --records`，私有操作从 stdin 管道进入。入口、协调器、worker、监督器均要求 `aliyun_records_enabled=false` 的固定源码门禁显式开启；现有 DNS 记录门禁和读取门禁同时适用。生产安装配方不安装原型。环境变量不能启用，不接收外部 URL、命令、记录 ID、TTL、任意账户凭据或任意记录名称。

## 合同和范围

复用已验证 HGPRIVATE1、固定迁移来源复核、同代账户与凭据绑定、FD6/FD7 共锁和现有三十秒独立监督期限。原始操作管道单独传入 worker，读取也在期限内；最大4096字节，必须是既有 backup.json 规范 JSON 加 LF，拒绝重复键、NUL、额外字段或文档。

复用现有纯数据 `cloudflare-record-plan.lua` 的配置绑定和 IPv6 身份比较，不改动 Cloudflare 计划模块；只有传输和 AliDNS 记录数据适配不同。DDNS资源产生固定AAAA名称、区域、配置TTL；DNS01仅允许该证书配置中的域名，产生固定 `_acme-challenge` TXT、TTL600。删除AAAA空值必须显式 all=true；TXT必须指定非空精确值，其他挑战值保留。A、自动业务调度及生产LuCI入口未完成。

旧版以 DescribeSubDomainRecords 查找，AAAA已有任意等价值则 unchanged，否则更新 API 顺序首条；没有记录才新增。TXT已有相同值则 unchanged，不同值另建。旧实现没有完整分页，本原型补齐所有页后再决策，禁止截断后写入。

## AliDNS 请求和确认

[DescribeSubDomainRecords](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describesubdomainrecords) 明确传配置 DomainName/SubDomain/Type，100条每页。校验页码、页大小、稳定总数、对象/数组形状、记录ID重复及每条实际区域/相对RR/类型/值。最多1000页、十万原始行，私有记录及上下文序列化预算8MiB；单次响应及结束帧64KiB。全部分页共用总监督期限，容量/时间不足就失败，不静默截断。

[AddDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-adddomainrecord) 传配置区域/相对RR/类型/值/TTL和明确default线路。[UpdateDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-updatedomainrecord) 传已核对ID及原线路，避免省略Line后落入默认线路；不将Cloudflare的TTL=1自动语义套到Aliyun，按配置数值提交，由供应商套餐权限判定。更新前调用 [DescribeDomainRecordInfo](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomainrecordinfo) 对照同一ID、区域、RR、类型、值、线路、TTL和状态；锁定或停用记录拒绝写入。创建/更新后回读同一ID，核实值、线路、TTL及正常状态，再计为成功。

[DeleteDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-deletedomainrecord) 每次只删完整查询后按值匹配的ID，删除前逐条回读防止误删已变化记录；随后重新完整查询，确认该ID已消失后才累加affected。不根据未经核实的错误文本推断已不存在。没有供应商CAS，复核与写入之间仍有外部并发窗口，不承诺原子性、无并发竞争或DNS传播完成。

## 私有通道与未知结果

沿用r42固定HTTPS RPC v1签名、OpenSSL摘要及curl配置，不把AccessKey、签名URL、AAAA值或TXT挑战值放入argv/环境。所有RPC均按既有GET签名合同调用；以Action判断是否写入，不能因为HTTP方法为GET就判为只读。curl不重定向、不重试、不使用外部代理或安全路径覆盖。

操作增加input/context/attempt三个0600单链接槽位；原六槽仍在0700目录。变更前保存 `HGALIRECORD1` 私有计划/上下文，写 `HGALIATTEMPT1` 标记，再调用接口。已尝试变更后的签名、网络、HTTP、响应、回读或部分删除失败均为unknown，retryable=false，保留已确认数量并要求核对；原调用者被杀死也不擅自消除证据。父协调器同时复核规范公共结果、账户/代次/范围、实际attempt与affected一致性，防止伪造none/成功后删除未知证据。

本阶段的Aliyun未知证据仅在同一次启动期保存，阻止之后的所有DNS请求；没有Aliyun专属持久回执、明确核对/恢复或重启收集接口。Aliyun记录模式明确拒绝打开现有Cloudflare持久回执门禁，避免格式混用。完成这些缺口之前保持生产门禁关闭。大规模账户、目标OpenSSL/SDK ABI、同源三包、设备资源和真实供应商兼容仍待验收；本地详细验证记录不进入公开协议文档。
