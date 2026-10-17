# DNSPod 持久检查点与只读核对

原型增加分别关闭的 `dnspod_reconcile_enabled=false` 和 `dnspod_receipt_enabled=false`，沿用原读取及记录门禁。源码常量不受环境启用；生产包不安装原型，没有新增正式授权界面。

## 固定确认入口

`homegate-dnspod-read.sh ACCOUNT --reconcile ORIGINAL_JOB --confirm` 使用原启动期私有工作目录；`--reconcile-receipt` 使用共享持久存储中的DNSPod检查点。均只允许固定读取API，不能重发写操作、指定URL/路径、修改原证据或清理工作目录。

协调器复用FD6/FD7，核对namespace/代次/其他应用屏障。恢复读取只绕过原DNS写屏障，当前迁移来源、私有快照和冻结请求仍须重新匹配。原任务之外的孤立工作继续阻塞。已丢失临时目录时可以从完整持久检查点观察；这不恢复或重发原变更。

## 写前持久化

固定内部别名 `homegate-dns-receipt.sh --dnspod-internal checkpoint` 复用两槽、`.prepare`、`.next` 和 `current`，使用独立 `HGDNPJOURNAL1`。不允许复用Aliyun或Cloudflare格式、标记或计划。

借用已校验锁后，检查点适配器经新私有快照重新绑定来源、账户、配置代及请求。`HGDNPRECORD1` 只持久保存规范白名单字段和冻结记录；不保存凭据、签名、HTTP请求配置。冻结记录重建数字ID、相对主机、类型、值、TTL、线路ID/名称、启停、权重与备注；ID仍要求Lua精确整数范围及规范十进制格式。

创建、更新检查点已影响计数必须为0；更新目标是冻结第一条AAAA，必须启用。删除目标须对应冻结位置，已确认计数严格等于此前匹配目标数。后续删除检查点只允许同一冻结计划向前移动，其余字段不变。

完整上下文与规范清单写入准备槽并同步文件/目录，才重命名到非当前槽；同步回执目录后发布唯一指针，再同步回执及父目录。成功返回后才允许云端变更。失败即保留屏障，不发送该次变更；第二次检查点失败保留前一个当前槽及已确认计数。第三次检查点复用非当前槽，不删除当前槽。

每个清单绑定存储身份、原boot、代次、账户、原任务、保留代清单和上下文SHA256，再验证LF规范帧SHA。加载时允许原boot与当前不同，所有现存槽仍须同属原boot及绑定身份；不据新启动重新生成证据。

## 只读观察

从原证据重新绑定冻结请求，完整读取配置域名的记录后再报告。AAAA/TXT upsert返回desired-present/desired-absent；删除只观察冻结目标ID是否仍在，值或线路ID变化返回conflict。API或分页失败返回incomplete，不返回部分结论。

任何观察都维持 `effect:unknown`、`retryable:false`、`reconciliation_required:true`，不表示原变更归属或成功结算；即使desired-present或planned-targets-absent，也不解除写屏障。父协调器再次按账户、代次、范围及规范JSON核对结果。

## 当前边界

成功变更也保留持久屏障；原成功终态和明确确认归档见《[DNSPod终态与确认归档.md](DNSPod终态与确认归档.md)》。退役以及准备文件和孤立工作维护仍待接入。`.prepare` / `.next` 等残留不自动修复或丢弃。关闭可选功能不能关闭已存在证据的写保护。

本协议只是隔离root CLI合同。目标SDK/OpenSSL ABI、同源三包、正式授权UI、真实路由器断电/重启及资源峰值分别验收；模拟boot变化不是设备证据。
