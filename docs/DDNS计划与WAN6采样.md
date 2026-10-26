# DDNS 只读计划与 WAN6 采样

本阶段在独立原型中连接配置规则与本机 WAN6 采样，输出有来源和代次绑定的计划。所有 `ddns_plan_enabled=false` 保持关闭；生产 Makefile 不安装原型。它尚不调用供应商、写 DNS、调度或启用服务，不代表完整 DDNS 接管。

## 固定入口与配置来源

内部 `homegate-ddns-read.sh [RULE_ID]` 仅接受一个安全规则 ID，省略时处理该代所有 DDNS 规则。调用者不能传地址、URL、接口、供应商端点或 HTTP 方法。入口持有共用 frontend/supervisor 锁，已有 DNS 持久屏障及 DNS/DDNS 工作目录阻止运行；没有自动孤立清理。

配置事务新增独立关闭的 `ddns-plan-snapshot-read`：在配置锁内重新核实当前迁移代、原配置字节及凭据来源，拒绝后续未绑定代与投影代；HGPRIVATE1 配置通过管道传递。备份/迁移候选原有的默认禁用语义不变。为只读预检，新增 `private_ddns_switches` 从同一份已校验原配置提取规则启用意图，经私有 FD 写出 HGDDNSINTENT1（schema、revision、switches 三项）；完整解析、重复项和引用校验仍先执行。意图必须与快照代次、规则集合完全一致，不能据此恢复或启用服务，也不能直接作为未来写入授权。

仅启用的 AAAA/auto 或 AAAA/interface 规则进入地址预检。指定接口从同一份来源绑定配置读取 interface，只取该接口实际拥有的有效公共 IPv6；缺失或非法接口名拒绝采样，接口无可用地址报告 network_unavailable，不后备到其他 WAN、路由或 ubus。禁用规则、IPv4 和 URL 来源不触发采样，后两类仍报告 unsupported。Cloudflare、Aliyun、DNSPod、华为云账户分别保留自身绑定；同批固定地址命令只执行一次；自动来源共用其选择结果，指定接口按各自接口缓存结果（包括失败），不跨接口借用地址。一个规则失败不隐去其他规则的状态。

## WAN6 选择与期限

固定只读命令为 `/sbin/ip -6 -o addr show scope global`、`/sbin/ip -6 route show default`，必要时 `/bin/ubus call network.interface.wan6 status`。先取默认 IPv6 路由实际设备上的地址，避免 QWRT 报告下层 eth 但地址在 pppoe 设备的问题；其次匹配 ubus 的实际 l3_device，再按 pppoe-/ppp/wan/eth 顺序选择有地址的设备，不兜底到任意 LAN 桥。

显式 ubus `up:false` 在没有路由地址匹配时拒绝使用陈旧地址。这比归档 Go 解析器更严格；已有匹配路由地址时不查询 ubus。ubus 命令失败可按 WAN 名称后备，成功但格式错误则拒绝。过滤 unspecified、loopback、IPv4 mapped、ULA、link local、multicast 及 tentative/dadfailed/deprecated 地址；归一化 IPv6 用于去重，按设备及地址所有权选择，不凭接口名称推定地址有效。

单次命令输出最多 65536 字节、单行 4096 字节。独立 setsid watchdog 给整族 5 秒期限，保留共用锁到工作族静止；调用者消失也不取消期限。命令子进程关闭配置/计划/结果 FD，标准输入为 /dev/null；供应商凭据不进入 argv、环境或网络命令。命令诊断不向公共输出转发。

## 输出与后续边界

私有 HGDDNSPLAN1 保存 rule/provider/account、来源代次、WAN 设备与派生的 `upsert/ddns/resource/value`，仅在私有临时工作目录中传递。公共规范 JSON 仅有配置代次、规则 ID、供应商、状态及错误类型，不包含地址、域名、设备、原配置路径或凭据；固定 `effect:none`。父进程重建规范结果并核对代次、选择器和退出状态，篡改结果不发布。

成功或可解释的规则失败在确认整族静止后只移除本次四个固定临时文件；不确定失败保留原工作并阻塞后续预检。现阶段不提供孤立工作收集，不能手工据此推断 DNS 成功。下一步接入固定规则的供应商执行、结果归属与持久屏障，仍需独立写入授权和完整业务验收。指定接口只读预检及单规则候选授权/同步现已接合（见《DDNS单规则同步与持久结果.md》）；混合多规则授权/切片见《DDNS全批协调与共享采样.md》，既有自动来源写入合同不变。main/服务启用状态、生产周期调度、URL/IPv4、指定接口生产混合批次/实机写入、真实路由器及目标 ABI 均不在本次通过范围内。

本地回归使用真实 BusyBox 1.33.2、Lua 5.1、配置事务和一次性 ip/ubus 夹具；地址均为文档示例，未访问或修改真实 DNS。详细设备、宿主、日志和验证记录只保存在本地，公开仓库仅包含必要源码、该协议和测试。

手动确认的单规则供应商派发与持久结果已另行接入，见《[DDNS单规则同步与持久结果.md](DDNS单规则同步与持久结果.md)》；上述只读预检入口本身仍不写DNS。
