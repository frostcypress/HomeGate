# DNSPod 配置绑定记录操作

私有原型入口为 `homegate-dnspod-read.sh ACCOUNT --records`。入口、协调器、watchdog、worker均有独立 `dnspod_records_enabled=false`；原读取门禁和来源绑定继续适用。环境不能启用；生产配方不安装原型。

## 输入与读取范围

标准输入是最多4096字节、规范LF结尾JSON。复用 `cloudflare-record-plan.lua` 绑定同代配置：DDNS只接受配置规则的AAAA，DNS-01只接受配置证书中已声明域名的TXT；操作不能指定URL、凭据、RecordId、任意主机名或TTL。AAAA按值删除，空值删除必须明确all=true；TXT始终按挑战值匹配，不提供全部删除。

传输和TC3签名沿用《[DNSPod私有只读.md](DNSPod私有只读.md)》。记录模式仅允许固定DescribeRecordList/DescribeRecord/CreateRecord/ModifyRecord/DeleteRecord。签名、凭据、JSON值保存在私有文件与FD，不进入argv/env，父协调器重新验证公开结果。

使用配置域名的完整无筛选列表分页，每页100条，最多1000页/100000条，响应含尾部最多64KiB；按TotalCount收敛后才按主机和类型筛选。这样不依赖过滤后的计数含义。全部域内ID去重，计数变化、短页、坏结构等拒绝；相关规范记录和上下文预算8MiB。列表与详情使用各自官方字段，不能相互替代。

ID仅接受1至9007199254740991之间的整数，拒绝数字字符串及超过Lua精确整数范围的值；不通过舍入处理ID。记录值、TTL、线路名/ID、启停、权重及备注有界校验；AAAA按IPv6规范值比较。服务器原始响应和属性不公开反射。

## 创建、更新、删除与回读

完整列表已有相同值时不写，禁用记录不会被当成有效完成。AAAA无等价值时更新第一条目标记录；先读取详情并与冻结记录逐字段比较，保留线路名/ID、权重和备注。TXT没有相同挑战则新增，保留其他挑战。新增使用默认线路ID0及ENABLE；TTL来自配置绑定。

变更前先保存HGDNPRECORD1私有上下文，再写HGDNPATTEMPT1标记；同启动期证据仍保留；另行开启独立持久门禁时，须在HTTP变更前完成来源绑定检查点，见《[DNSPod恢复与持久回执.md](DNSPod恢复与持久回执.md)》。CreateRecord要求合法返回ID；ModifyRecord/DeleteRecord按固定请求目标处理，不要求接口未承诺返回的记录ID。每次创建/更新立即DescribeRecord核对目标、值、TTL、线路和状态；更新另核对保留属性。删除每个匹配目标前重新读详情，删除后完整列表确认该ID消失，才增加已确认计数。

公开结果为created/updated/deleted/unchanged和effect none/confirmed/unknown，包含有界已确认计数。回执缺失、索引延迟、回读不符、错误/超时、部分删除均不补造成功；发出变更后错误一律不可自动重试，保留原目录及未知标记，后续DNS请求受阻。curl不会自动跟随重定向或重试。

## 维护与后续边界

工作目录使用原九文件协议，0600文件、0700目录。正常完成仅删除本次固定文件，失败保留未知证据；独立监督保留共锁直到工作族静止。记录模式拒绝Cloudflare持久回执门禁，不能混写其他供应商格式。

DNSPod持久检查点及未知只读核对见上述独立协议；终态和明确确认归档见《[DNSPod终态与确认归档.md](DNSPod终态与确认归档.md)》，其余维护修复尚待接入；当前没有生产LuCI确认入口，也不代表完整DDNS/ACME或生命周期已迁移。真实账号、目标ABI、三包及设备重启/断电和资源验收另行完成。

## 官方依据

[列表](https://cloud.tencent.com/document/api/1427/56166)、[详情](https://cloud.tencent.com/document/api/1427/56168)、[数据结构](https://cloud.tencent.com/document/api/1427/56185)用于分别核实分页与记录字段。[创建](https://cloud.tencent.com/document/product/1427/56180)、[修改](https://cloud.tencent.com/document/product/1427/56157)、[删除](https://cloud.tencent.com/document/api/1427/56176)用于核实参数、属性及回执。官方提示新建记录可能有索引延迟；本实现保留未知状态，不按该提示自动重发写操作。
