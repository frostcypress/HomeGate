# Aliyun 未知结果核对与持久检查点

r45增加成功终态与受确认归档，见 [Aliyun终态与确认归档.md](Aliyun终态与确认归档.md)。下文“终态尚未接入”等描述为r44阶段；未知结果仍不能因观察而转为成功。

关闭门禁的未安装原型扩展。`ACCOUNT --reconcile JOB --confirm` 使用同启动期私有上下文；`ACCOUNT --reconcile-receipt JOB --confirm` 从持久检查点读取，包括临时目录已丢失的情况。两者只读观察，不重试变更、不清除屏障，不证明此前操作归属或DNS传播。入口、协调器、监督器、工作端的新 `aliyun_reconcile_enabled=false` 和 `aliyun_receipt_enabled=false` 均默认关闭；生产配方继续不安装原型。

## 只读核对

重新读取当前迁移代私有快照，将原规范操作绑定到账户、配置代次、资源、区域、名称、类型、TTL和目标值；恢复的字段白名单排除凭据、签名URL、headers、传输缓存和未知字段。AAAA更新要求原冻结首条ID，删除要求完整冻结记录集、当前位置、明确目标ID及已确认前缀计数一致。拒绝旧格式缺少原请求、未尝试变更、计划阶段、错代/错范围或伪造计数，不猜测修复旧证据。

复用固定DescribeSubDomainRecords签名通道，完整分页并校验每条记录后才生成观察；记录核对模式同时在数据驱动器和传输Action白名单中拒绝新增/更新/删除。原操作、未知attempt、回执和当前业务配置均保留。

upsert 只返回 desired-present / desired-absent；delete 观察冻结匹配ID，返回 planned-targets-present / planned-targets-absent，冻结ID的值或线路变化返回 conflict。未冻结的新记录不被纳入旧删除计划，TXT其他挑战保留。出错返回 incomplete，不发布前页部分观察。全部结果固定 effect=unknown、retryable=false、reconciliation_required=true；观察值存在不等于本插件创建，ID消失不等于本插件删除。

## 共用持久存储与供应商隔离

复用 `homegate-dns-receipt.sh`、固定 `/etc/homegate/transactions/dns-operation` 及既有全局写屏障，不另建日志目录或锁体系。Aliyun内部固定别名必须通过独立门禁，使用HGALIJOURNAL1/ HGALIRECORD1/ HGALIATTEMPT1；Cloudflare仍使用原格式和原入口，跨格式读取/续写拒绝。一次只允许一个未结操作，不能在两个供应商间绕过屏障。

Aliyun工作端仅在持久模式借用监督器已经持有的FD6/FD7，并逐inode/权限确认；固定检查点命令继承锁。curl和OpenSSL关闭所有私有与锁描述符，监督器持续持锁到整个工作族静止。临时context/attempt改经工作端已经核对的固定0700目录、0600单链接文件写入，避免将FD6/7同时用作文件和锁。

每次变更前：冻结原请求/完整记录集和目标位置 → 保存私有上下文并写attempt → 调用固定检查点 → 成功返回后才能发送RPC变更。首次建立回执即fsync父目录，不完整初始化同样阻止后续写入。两槽仍按 .prepare 写入、fsync文件/准备目录、rename到非当前槽、fsync目录、写并fsync .next、原子替换current并再次fsync目录/父目录的顺序发布；任何失败不发送本次变更，不回退或清理证据。

新上下文在实际迁移来源绑定的私有快照下重新验证；后续删除检查点还须在冻结请求/记录集不变的条件下单调推进位置和已确认计数。最多两份8MiB槽及一份暂存，不按每次删除无限增加目录。清单继续绑定完整HGSTORE1身份SHA、原boot、配置代次、账户、原工作编号、代manifest SHA、上下文SHA及规范LF帧SHA。

## 临时证据丢失与限制

内部 `migration-source-recovery-snapshot-read` 是有门禁的只读别名：保留原固定旧配置字节与内容复核，同时允许在DNS持久屏障下向继承管道输出私有帧；其余配置/应用/生命周期屏障继续适用。普通写入与普通快照入口不因此开放。

持久读取核对目录/文件权限、单链接、current、全部槽绑定及SHA，再在新鲜来源绑定快照下重建活动上下文。允许与当前boot不同的原boot作为历史证据，不把它当当前写入授权；不修改清单、代指针或原槽。错误格式、损坏、未知条目、残留.prepare/.next或错账户/代/任务拒绝加载。加载失败后本次分配的私有缓冲目录也可能保留，继续阻止请求，不做自动收集。

本阶段即使变更成功，也保留持久写屏障。Aliyun终态结算、明确确认后的归档/收集、异常暂存修复和解除屏障尚未接入；不能安装生产启用，也不将只读核对称为完整恢复。模拟boot变化和Linux临时目录丢失不是路由器真实重启或断电证据；目标SDK/OpenSSL ABI、同源三包、闪存写放大、峰值资源及设备验收仍待完成。详细验证记录仅本地。

接口合同沿用 [Aliyun记录操作.md](Aliyun记录操作.md) 中已核对的官方记录查询/变更文档；本步不新增供应商接口。日常High、约8个百分点进度与集中CI统一批次、最终Ultra提醒及有限终审规则继续适用。
