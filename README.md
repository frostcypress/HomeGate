# HomeGate 1.3.0-r29 规范迁移草稿

本目录是按《OpenWrt 通用插件开发标准 V2.0》整理的工作源码。**这不是已完成 Shell/C 核心迁移的可安装发行版。** 目标为 Zyxel Armor G5 (NBG7815) 的 QWRT R26.3.8 / QSDK 12.5、aarch64_cortex-a53、IPK + Lua LuCI。型号与运行库/组件报告已收，SDK 链接兼容与实机验收仍未完成。用户确认按 1.3.0-10 重构，设备上的优化版 1.3.1-1 作废，不要求当前降级。

本轮已落实源码分层、唯一版本入口、概览/设置/维护导航、维护四分区、默认不导出凭据、目标核实清单、SDK 构建门禁、包元数据检查和可接续草稿。project/core/src/ 保留完整 Go 核心作为迁移对照；该项不符合最终核心要求，正式构建入口会拒绝它。

新增隔离 BusyBox ash 原型，覆盖公共配置检查、8 项任务队列、互斥与代次/token。3 项静态检查通过，10 项 Linux 执行回归已在 Actions 通过；详情见 project/core/prototype/README.md。生产配方不安装原型。

project/core 保存核心配方、安装文件和完整对照实现；project/luci/lua、js、common 分离两套前端与公共翻译。scripts 保存校验与生成程序；targets 保存逐台设备证据；.github/workflows 是当前流程，.github/reference 的历史 Go 流程不会自动运行。

本轮完整接续文档与详细验证记录仅随本地接续包保存；仓库根目录的接续/校验文档保留上一阶段记录。当前实现范围见本文与原型说明。完整历史合同见 docs/历史接续_1.3.0-10.md，其中的旧测试结果不能作为本版验收。

## 本地检查

Python 3.12+，Lua 回归另需 lupa==2.8；浏览器回归需 playwright==1.63.0、Node 和 Chromium/Edge。Shell 静态检查需要 tree-sitter==0.25.2 与 tree-sitter-bash==0.25.1，执行检查需要带必要 applet 的 Linux BusyBox。

    python3 scripts/project.py --check
    python3 scripts/重构回归.py
    python3 scripts/Shell原型回归.py --static
    python3 scripts/导航安全回归.py
    python3 scripts/frontend-source-regressions.py
    python3 scripts/native-ui-regressions.py

只修改 VERSION 和 RELEASE，随后运行 python3 scripts/project.py --sync。homegate-version.mk 和独立对照安装/校验脚本的版本默认值均由此同步，禁止手工维护第二套版本。规范版本为 1.3.0-r29；Go 对照接口仍使用旧格式 1.3.0-29，不冒充已统一的新 SDK 安装包。

修改 Lua Controller/HTM 后运行 sync-frontend.py 和 build-js-views.py；生成副本由 CI 核对。概览不轮询，使用手动刷新。各设置页的旧只读地址保留为兼容入口。

## 目标与构建

初次核实使用 scripts/核实设备.sh 与 scripts/补充核实设备.sh，用户已回传两份报告，无需重复运行。当前目标档案为 targets/qwrt-r26.3.8-ipq807x.json；SDK 已获用户允许使用 ImmortalWrt 21.02 或尝试 24.10，候选与动态库差异见 docs/目标兼容性报告.md。候选公布 SHA 不等于已下载验证或已兼容。下一步按 docs/Shell原型方案.md 验证完整业务与总占用，再冻结 A/B。

新工作流默认仅检查源码。Lua/JS 与 IPK/APK 分开选择，目标/核心/包名迁移未完成时构建失败。目标SDK构建.py 使用匹配 SDK；检查三包.py 读取控制元数据并要求准确版本、架构和 Core 依赖。APK3 解码需要支持 adbdump --format json 的官方 apk-tools，具体目标工具尚待验证。

用户指定仓库 [frostcypress/HomeGate](https://github.com/frostcypress/HomeGate)，完整源码已展开提交，Linux 源码回归已通过。一次性导入工作流完成后已移除；常规工作流所有作业均只有 contents:read。详细验证记录随本地接续包保存。

历史 build-release.py 和 build-apk.py 只能显式设置 HOMEGATE_ALLOW_LEGACY_GO=1 后用于迁移对照，其结果不能通过新三包检查。包名仍为旧 homegate，改名升级与 FULL PURGE 生命周期未完成前保留原业务合同。正式 GitHub Release 当前禁止。

## 配置导出

默认导出白名单 UCI 字段，不包含 DNS key/token/账户标识、私钥、未知字段、上游 URL 或 DDNS URL。备份总开关关闭，恢复后先补齐凭据和地址再启用。此备份不承担完整敏感备份功能。1.3.0-r14 已接入六类公共配置的严格格式/字段/引用校验及 Lua/JS 服务端预览，移除旧直接覆盖并应用的导入路径。当前只开放预览，配置不会更改；完整 UCI 确认提交、持久回滚和生产凭据迁移仍未完成，见 [公共配置预览说明](docs/公共配置预览.md)。

## 可接续快照

    python3 scripts/生成接续包.py --target pending --stage 规范迁移 --draft

草稿仅含完整源码、许可、工作流、历史合同和三份接续文档，不附旧包。完整快照必须在迁移完成且具备真实三包后生成。

上一阶段 1.3.0-r12 Linux 回归证据：[源码检查运行](https://github.com/frostcypress/HomeGate/actions/runs/38127877469)；实机业务/SDK 构建仍未执行。

1.3.0-r13 增加隔离配置事务原型 `homegate-config-prototype.sh`：严格的公共字段预览、128 位随机确认句柄、失效/重放拒绝、整代配置和私有凭据原子发布、祖先代次回滚。仅覆盖 `main-public-v1`，没有接入生产 UCI 或 LuCI 导入按钮；14 项真实 Linux 事务回归已通过 [本轮运行](https://github.com/frostcypress/HomeGate/actions/runs/38138863941)。见 [配置事务原型说明](project/core/prototype/配置事务说明.md)。

1.3.0-r14 本地通过 17 项 Lua 配置检查、12 组预览几何和 9 项行为合同；Linux 源码 CI 已通过 [本轮运行](https://github.com/frostcypress/HomeGate/actions/runs/38144574657)。仅预览不是完整配置事务，完整 SDK/实机验收仍未完成。

1.3.0-r15 将同一六类公共 UCI schema 接入隔离配置/凭据代次存储，增加基线/启动/有效期绑定及检查 fsync 返回值的发布流程。生产维护页仍只预览；[完整配置事务说明](docs/完整配置事务.md)解释隔离范围和同步失败语义。本轮 Linux 源码回归已通过：[运行记录](https://github.com/frostcypress/HomeGate/actions/runs/38146374894)；新模式 20 项真实执行、4 项适配器检查及官方 UCI 读取检查通过。

1.3.0-r16 增加旧 UCI 迁移候选：DNS 凭据、DDNS URL 和代理目标移入同一私有代次，保留原始副本并绑定一次性确认；生产读取端和共锁切换尚未完成，不能安装替换。详见[旧配置迁移与写入口合同](docs/旧配置迁移.md)。新增 6 项 Lua 检查及 12 项真实 Linux 迁移执行通过[本轮 Actions](https://github.com/frostcypress/HomeGate/actions/runs/38185891624)；既有 20 项完整事务、14 项旧事务、10 项控制和页面回归通过。详细记录和当前三份接续 MD 仍仅本地保存。

1.3.0-r17 新增同代配置与私有凭据读取端，沿用事务 flock，通过继承的私有管道发送有界二进制快照；公开返回值不含凭据。6 项 Lua 检查和 8 项真实 Linux 私有读取检查通过[本轮 Actions](https://github.com/frostcypress/HomeGate/actions/runs/38187732623)；既有事务、迁移、页面和工程检查通过。生产业务读取端、保存协调和应用失败恢复仍待接入；不是可安装版。详见[私有读取合同](docs/私有配置读取.md)。

1.3.0-r18 增加配置应用日志、写入屏障、原代次恢复和工作端 ACK 协议；发布配置与业务应用成功分开。新增 15 项真实 Linux 协调恢复检查及既有事务/读取/迁移/页面回归通过[本轮 Actions](https://github.com/frostcypress/HomeGate/actions/runs/38189061222)；业务执行端为显式 ACK 夹具。实际业务工作端/监督器、生产保存入口/持久目录和启动恢复未接入。详见[配置应用恢复合同](docs/配置应用恢复.md)。

1.3.0-r19 接入固定工作端监督、独立看门期限、私有工作记录和停止/静默核实；只生成隔离派生回执，不执行真实业务。新增 1 项静态审计、18 项真实 Linux 监督用例及全部既有回归通过[本轮 Actions](https://github.com/frostcypress/HomeGate/actions/runs/38205254898)；原生 sh/BusyBox ash 语法通过，业务仍为隔离回执。生产服务/意图基线、全部写入入口和持久路径仍待接入；详见[工作监督合同](docs/工作进程监督.md)。

1.3.0-r20 增加独立服务开机/运行意图与 boot 绑定、双状态观察 ACK 和旧回执隔离；目前只有协议层，没有实际采样或服务启停。新增 16 项服务意图用例及全部既有 Linux/页面/工程回归通过[本轮 Actions](https://github.com/frostcypress/HomeGate/actions/runs/38207827999)；服务状态和观察值为显式夹具。详见[服务意图合同](docs/服务意图绑定.md)。

1.3.0-r21 增加固定 init/procd/proc 服务采样、同锁意图提交及独立期限监督；13 项 Linux 采样、2 项静态及全部既有回归通过[本轮 Actions](https://github.com/frostcypress/HomeGate/actions/runs/38209902644)。端点为明确夹具，未实测路由器、未接入生产启停。详见[固定采样适配器](docs/固定服务采样.md)。

1.3.0-r22 增加源配置绑定、公共 UCI 文件发布/读回及私有原文件恢复，完成确认取自实际服务采样。15 项 Linux 发布、2 项静态及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38332273913)。生产写入固定关闭，Lua 共锁迁移、持久存储、实际启停与新核心业务仍未完成，没有三包。详见[源配置发布协议](docs/源配置发布.md)。

1.3.0-r23 增加 17 个原生 Lua 写处理器的整次请求协调、私有请求传输及固定 Shell flock runner，对照桥接复用原有事务锁。8 项本地检查通过，12 项 Linux、对照桥接和全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38336189603)。原生写入及发布生产门禁固定关闭，持久屏障、独立期限及业务恢复尚未接入；没有三包。详见[原生写入协调](docs/原生写入协调.md)。

1.3.0-r24 增加固定持久目录、存储身份和独立应用写入凭据，原生 17 个写入口在同一共享锁内检查屏障后才创建配置游标。3 项本地检查通过，21 项 Linux 屏障及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38338971798)。持久、原生与发布门禁固定关闭，初始化迁移、独立监督、孤立凭据协调与实际业务仍待完成；没有三包。详见[持久事务屏障](docs/持久事务屏障.md)。

1.3.0-r25 增加生命周期专用持久空基线初始化、同目录阶段发布及显式恢复；复用实际引擎检查，重复执行不替换锁和身份，不覆盖旧配置；发布同步不确定保留初始化屏障，拒绝网页写入。3 项本地检查通过，23 项 Linux 初始化及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38359802398)。生产门禁固定关闭，旧配置/秘密迁移及独立监督仍待完成；没有三包。详见[持久存储初始化](docs/持久存储初始化.md)。

1.3.0-r28 复用固定监督器并接入持久身份、共享 FD6、独立期限和 HGWORKER2 记录；活动凭据之前保存同 boot 恢复锚点，缺日志时保留原意图并要求受监督恢复 ACK。4 项本地检查通过，23 项 Linux 持久监督及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38365719694)。仅隔离回执业务，生产门禁关闭；真实服务/冷启动/迁移/SDK/三包仍待完成。详见[持久监督恢复](docs/持久监督恢复.md)。

## 固定服务动作阶段

r27 在门禁关闭的持久引擎中增加 service-apply/service-recover，仅绑定 HGAPPLICATION3。固定 UCI 解析/依赖预检后按实测状态停服，再发布受绑定配置；恢复仅按原运行意图启动，开机链接保持不变。命令退出成功仍须观察核实，失败保留写屏障；新增 20 项 Linux 固定服务动作及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38373836096)。详情见 docs/固定服务动作.md；init/ubus 是隔离夹具，不能冒充 QWRT/procd 实测或业务预检通过。

## Cloudflare 私有只读业务阶段

r28 增加与旧 ValidateCredentials 同方向的区域读取校验：持久同代快照、受限临时 curl 配置、固定 HTTPS/系统 CA、独立超时和有界响应；令牌不进入 argv 或由应用加入环境，原始供应商消息不公开。新增 20 项 Linux、5 项本地及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38503054242)。详情见 docs/Cloudflare私有只读.md。只访问隔离 HTTPS 夹具，未用真实账号验证，也未迁移完整区域发现、AAAA/TXT 或其他三家服务商。生产门禁关闭，没有三包。

## Cloudflare 区域发现阶段 r29

新增固定 `--zones` 私有读通道，逐页读取、校验页码/总量，完整结束后归一化、去重和排序，只返回区域名称。中途 HTTP/TLS/超时/分页异常不输出部分列表；凭据和账户元数据不输出。旧版每页 50、最多 1,000 页范围保留，响应与总任务有界。现行 API 最小 `per_page=5`，只读凭据检查同步修正。15 项新增 Linux、3 项本地及全部既有回归通过[Actions](https://github.com/frostcypress/HomeGate/actions/runs/38507733599)。生产门禁关闭，只用本地 HTTPS 夹具；AAAA/TXT 写入删除、另外三家与后续完整业务仍待实现，没有三包、目标 ABI 或实机结论。详情见 docs/Cloudflare区域发现.md。
