# Aliyun 私有只读与域名发现

未安装原型 `homegate-aliyun-read.sh ACCOUNT` 检查域名读取权限，`ACCOUNT --zones` 获取完整域名列表；`--migrated` 为同一迁移绑定的检查入口。源码中的入口、协调器、监督器和 worker 门禁均关闭；只读模式不接受环境开关、外部 URL 或记录写入指令，不加入生产安装配方。r43 的额外关闭门禁记录模式见 [Aliyun记录操作.md](Aliyun记录操作.md)，不改变本篇只读范围。

通过已有协调器、FD6/FD7 共享锁、固定旧配置迁移来源复核与私有快照读取当前账户。只接受仍与 `/etc/config/homegate` 字节和迁移内容一致的当前迁移代；普通后续代、错误 provider、未知账户、缺凭据、未完成应用及恢复屏障拒绝请求。不改变配置、凭据或业务状态。

## 接口合同与签名

沿用旧版 `project/core/src/internal/dnsprovider/aliyun.go` 的 AliDNS RPC v1 合同：固定 HTTPS `alidns.aliyuncs.com`，GET DescribeDomains，版本 2015-01-09、JSON、HMAC-SHA1/SignatureVersion 1.0。参数按名称排序，按 RFC3986 编码后组成规范查询；签名串为 `GET&%2F&` 加再次编码的规范查询，以 `secret + "&"` 作 HMAC 密钥，再 Base64 和 URL 编码。每页使用内核随机 UUID 和 UTC 时间，不接受外部签名参数。

依据：[官方 DescribeDomains 文档](https://www.alibabacloud.com/help/zh/dns/api-alidns-2015-01-09-describedomains)、[官方 SDK RPC 签名实现](https://github.com/aliyun/aliyun-openapi-python-sdk/blob/master/aliyun-python-sdk-core/aliyunsdkcore/auth/composer/rpc_signature_composer.py)、[官方 SDK HMAC-SHA1 实现](https://github.com/aliyun/aliyun-openapi-python-sdk/blob/master/aliyun-python-sdk-core/aliyunsdkcore/auth/algorithm/sha_hmac1.py)。独立实现协议，没有引入 SDK 依赖或复制 SDK 源码。HMAC-SHA1 用于兼容该 RPC 合同，不作为新增密码协议的选择。

Lua 仅处理既有私有帧、编码、HMAC 填充组合及官方 JSON 解析；摘要由固定系统 OpenSSL `dgst -sha1 -binary` 经继承文件描述符完成。密钥、填充材料和签名 URL 不进入 argv 或环境。0700 运行目录内六个固定单链接文件均为 0600；签名材料包含敏感内容，只在工作族静止后清理。签名实现不使用会将密钥放入参数的 `-hmac` 或 `-macopt`。

curl 7.83.1 可用参数：首项 --disable、固定 HTTPS/系统 CA、禁用代理与重定向、连接上限三秒和单次请求十秒。复用已有监督期限三十秒及终止宽限；整个分页受同一期限约束，不为大账户无限延长。中断后的私有孤立目录阻止新 DNS 请求，不擅自清理或绕过；该目录不等于持久 DNS 写回执。

## 完整列表和边界

检查每页一项；列表每页一百项，最多一千页和十万条原始行。验证页码、页大小、稳定总数、非提前空页、完整单 JSON、Domains 对象和 Domain 数组；拒绝重复解码键、NUL、尾随内容和异常类型。总数完成后统一返回，不因下一页失败公开已取得的部分列表。

域名去首尾空白、转小写、移除末尾点、验证标签、去重并排序。中文域名要求响应提供合法 ASCII PunyCode；没有引入新 IDNA 转换器，缺少该字段时拒绝整份列表。完整 HTTP 响应含结束帧限制 64 KiB，归一化域名编码预算 60000 字节，最终公共结果也须通过 64 KiB 复核。触及容量、分页或总期限边界时失败，不静默截断。高容量账户和实际设备网络/资源预算仍需验收。

只公开固定错误分类、重试属性及白名单代码，未知代码归一化；不回显供应商 Message、原始响应、签名 URL、AccessKeyId 或 secret。父协调器复核账户、配置代、请求范围、规范 JSON 与退出状态，拒绝以权限检查结果替代列表。

本步只涵盖读取权限检查和域名发现。AAAA/TXT 查询及写入、DDNS/DNS-01 完整迁移、生产接管、目标 OpenSSL/SDK ABI、三包和实机测试另行完成。宿主测试不代表目标固件兼容；详细验证材料仅保存在本地，不写入公开协议文档。
