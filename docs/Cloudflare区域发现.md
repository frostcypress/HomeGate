# Cloudflare 区域分页发现（r29）

在既有 Cloudflare 私有读取、固定 curl/TLS 与独立监督内增加固定 `account --zones`；没有第二套凭据读取器或监督器。原型不安装，所有生产门禁关闭。请求通过同代 HGPRIVATE1 核实账户/代次，沿用 FD6/7 共锁、持久写屏障与孤儿拒绝；不修改配置或凭据。

## 分页和结果合同

- 固定 GET `/client/v4/zones?page=<1..1000>&per_page=50`，数字页码由 Shell 递增；API 返回值不能指定 URL、路径、账户、命令或 CA。
- 沿用原版每页 50/最多 1,000 页的范围；最多 50,000 行、私有区域数据 14,350,000 字节，整项独立监督预算 30 秒、单次 curl 最多 10 秒。达到时间或容量限制返回失败，不截断后宣称成功。该理论上限不是已测资源预算，QWRT 实测仍待执行。
- `result_info` 在官方接口中可选。有正 `total_pages` 时读取全部页；页码、per_page、count（若提供）必须匹配请求；已经提供的总页数/总条数不能在后页变化或消失，最后条数须吻合。无总页数时完整 50 条页必须继续，短页/空页才结束；空中间页拒绝。该快照不能证明供应商在读取期间未变更集合，生产调用仍须处理并发变化。
- 每页整个 HTTP/transport 帧最多 64 KiB，沿用官方 jsonc 单文档与递归重复键拒绝。页列表必须是数组、最多 50 条，ID 必须 32 位小写 hex，名称须有效 ASCII DNS 标签（IDNA 的 punycode 可用）。不接受 HTTP 重定向、不信任环境代理/CA 或 curlrc。
- 私有 0700 工作目录、四个 0600 单链接槽位：request（仅凭据/固定请求配置）、result、zones（仅校验后的 ID:名称）、state（小型分页账本）。curl 的 zones 配置**不写 URL**，命令每次仅提供一个固定 URL，避免 curl 多 URL 累加重复请求。凭据不进入 argv/env/stdout。
- 只有全部页完成后才核对跨页重复 ID、总行数，名称去空白/末尾点、转小写、去重并排序。公共结果仅名称数组及固定 schema/账户/代次/错误分类；不返回 ID、供应商消息、账户元数据或 Token。故障结果 `zones=[]`，不会泄漏首批名称或误报完整成功。
- 协调器再次校验完整 canonical 结果与退出状态、账户/代次、排序/去重/名称；完成后先清理自己的工作槽，最后才输出。被 SIGKILL 后由原独立监督收束家庭并释放锁，遗留槽继续阻止下一次 DNS 请求；自动冷启动收集仍未实现。

## 既有凭据检查修正

现行官方 List Zones 说明 `per_page` 最小 5、最大 50；r28 使用 1 只在离线夹具验证，本轮将其改为 5，允许最多 5 条校验结果。凭据检查仍只证明 Zone Read，不能证明 DNS Edit。r28 记录保持其真实历史来源；本轮工作流重跑全部既有检查。

## 阶段验证

3 项新增本地通过；15 项新增 Linux 及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38507733599)；实际源码 `c37dd57f4b993f9b897dc3fe88b44d2ce40ff940`，67 个关键文件逐字节核对，SDK/发布跳过。新用例包括完整多页、大小写/末尾点去重排序、无可选元数据的满页后续请求、空账户、总量/页码异常、重复 ID、无效名称/JSON、限额/超大 chunked、后页鉴权/限流/服务错误与超时、写屏障、父调用 SIGKILL 后独立监督、伪造公共结果和关闭门禁。真实 HTTPS/curl/BusyBox/Lua51/jsonc/进程与锁；监督故障例使用明确夹具包装器，不将其当成供应商请求成功证据。

详细证据、当前三份 MD 和完整接续 ZIP 仅本地。未连接真实 Cloudflare、未修改任何 DNS；AAAA/TXT 写入删除、四家完整迁移、ACME/代理/WOL/防火墙、生产确认迁移/生命周期/冷启动、SDK ABI/三包/实机/资源仍未完成。High 开发计划继承；符合终审前置条件才提醒用户切换 Ultra，并遵守一次终审与有限局部优化边界。

## 官方依据

[Cloudflare List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)：分页参数、可选 result_info、名称上限；[curl 手册](https://curl.se/docs/manpage.html)：多个 URL 累加、配置/TLS/协议与超时。参考实现为 project/core/src/internal/dnsprovider/cloudflare.go 的 ListZones（50/1000、归一化、去重排序）；对可选分页缺失改为完整页继续，防止旧版 total_pages=0 提前结束。
