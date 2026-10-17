# DNSPod 私有只读协议

固定原型入口为 `homegate-dnspod-read.sh ACCOUNT` 或 `ACCOUNT --zones`。四处源码门禁 `dnspod_entry_enabled=false` / `dnspod_read_enabled=false` 默认关闭，环境不能启用；不安装生产包，不接受记录写入、调用者请求体、URL 或路径。

## 官方接口与签名

仅使用腾讯云 DNSPod `DescribeDomainList`，固定 HTTPS 域名 `dnspod.tencentcloudapi.com`、POST `/`、版本 `2021-03-23`，Type 固定 ALL。参数与响应依据：[获取域名列表](https://cloud.tencent.com/document/product/1427/56172)、[DomainCountInfo/DomainListItem](https://cloud.tencent.com/document/api/1427/56185)。计数使用符合条件的 DomainTotal；域名优先使用 Punycode，再使用 Name。

TC3-HMAC-SHA256 按[官方签名 v3](https://www.tencentcloud.com/pt/document/api/1235/64588)构建规范请求、UTC 日期范围与派生密钥。签名覆盖 content-type、host 和实际 JSON 请求体；时间戳与日期来自同一次取时。SecretId 只允许非空 ASCII 字母、数字、下划线和连字符，上限4096字节；SecretKey 上限4096字节、禁止空白凭据，私有帧另有既有校验。长 HMAC 密钥先摘要。

复用既有纯字节 HMAC padding 与域名规范化函数，所有 SHA256 运算交给固定 `/usr/bin/openssl dgst -sha256 -binary`。秘密、派生密钥和签名经0700工作目录下0600文件及继承FD传递，不放入命令参数或环境；不使用带密钥参数的 OpenSSL 选项。curl 从固定私有请求配置读取认证头，请求体只含固定分页参数。

## 共有协调与限制

复用原DNS协调器、FD6/FD7锁、迁移来源绑定、HGPRIVATE1私有快照和独立工作族监督。获取共锁并复核原来源后才读取快照；来源变化、应用或DNS屏障、其他孤立工作均阻塞。读取模式的固定内部别名只允许check/zones，监督器和worker再次限制同样范围；不会调用Aliyun或Cloudflare的写入路径。

工作目录固定六文件：request/result/zones/state/sign-input/sign-output。正式端点只在源码中指定，默认系统CA，禁止代理、重定向跟随和自动重试；连接3秒、单请求10秒，整个工作族30秒，沿用既有期限后1秒终止宽限。不应将分页上限视作30秒内必能完成的容量承诺。

检查模式只请求一条，成功只表示可读取域名列表，不证明写权限。域名发现每页100条，最多1000页/100000条，响应含传输尾部上限64KiB，公开域名编码预算60000字节。总数跨页必须一致、行数严格收敛，短页/提前空页/越界/非法结构或域名拒绝；规范化、去重、排序后整体返回。发生任何错误不公开已取得的部分名单。

公共结果逐字节重新编码并核对供应商、账户、配置代和读取范围；只公开固定错误分类与白名单代码，不反射API Message、凭据、签名、请求配置或原始响应。HTTP200中的腾讯云Error同样按错误处理；原始未知代码归为固定provider_rejected。

完成后仅清理本次固定文件；调用者丢失后，独立监督仍保持共锁直到族内进程静止。原工作目录保留为阻塞证据，不自动清理未知文件。

## 尚待实现与验收

DNSPod AAAA/TXT变更的独立关闭原型见《[DNSPod记录操作.md](DNSPod记录操作.md)》，持久检查点与未知只读核对见《[DNSPod恢复与持久回执.md](DNSPod恢复与持久回执.md)》；终态与明确确认归档见《[DNSPod终态与确认归档.md](DNSPod终态与确认归档.md)》，其余维护尚待接入。华为云、完整DDNS/ACME/代理等业务替代仍按冻结范围推进。当前只读原型不证明生产接管、真实云账号、目标OpenSSL1.1.1x/SDK ABI、同提交三包或设备资源验收；宿主OpenSSL与回环TLS结果分别记录在本地。
