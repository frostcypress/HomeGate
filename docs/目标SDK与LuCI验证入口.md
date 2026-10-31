# 目标 SDK 与 LuCI 验证入口

## r170 当前构建选择与只读依赖核对（2026-10-31）

用户明确固定按包格式选 SDK：**IPK 使用 ImmortalWrt 24.10 系列，APK 使用 25.12 系列**，见 `targets/sdk-selection-policy.json`；后续不重复询问 SDK 系列。当前目标为 IPK，沿用 24.10.6。APK 的 25.12 系列选择已记录，尚未为未指定的 APK 目标下载或编造 SDK URL/摘要。用户报告 24.10 SDK 构建的其他插件已在其路由器成功运行。当前沿用已校验字节和缓存的 24.10.6 SDK，不再以寻找同分支 QWRT SDK 作为构建前置。目标清单记录该候选选择及摘要，`verified=false`、`abi=null` 与实际组件/设备验收状态保持。

历史目标报告给出的内核为 5.4.213、libc 为 1.1.24-2；候选完整 SDK 依赖闭包含内核 6.6.133 和 libc 1.2.5。闭包是工程导出，不是实际路由器安装计划：应核对并复用满足依赖的已安装系统提供者，不能将整个 SDK 内核模块闭包照搬到目标。历史 `libopenssl3` 包的版本为 1.1.1w-1，不能只凭包名判断它提供 `libssl.so.3`／`libcrypto.so.3`。

已获准访问目标后，运行新的只读入口，保存完整输出到本地即可；脚本不连接远端、不安装 readelf、不导出 UCI/凭据/私钥、不运行 HomeGate 或启停服务：

```sh
sh scripts/核实原生ABI.sh
```

该入口收集固定公开系统库路径的哈希、64 字节 ELF 头及可用时的 SONAME/NEEDED/指定动态符号。没有 readelf 时明确缺少动态元数据，后续可用可信宿主工具检查公开库文件副本；不要为采集单独安装工具。命令返回 0 只表示清单收集完成，非 OpenWrt/opkg 环境返回 2；不表示兼容验收通过。

离线比对入口如下，`--inventory` 可重复指定主报告、补充报告和新输出。`--closure` 接受候选 `dependency-closure.json` 或带闭包的构建证据；这些详细输入仅本地使用：

```sh
python3 scripts/native-target-audit.py --target targets/qwrt-r26.3.8-ipq807x.json --candidate targets/native-candidate-24.10.6-ipq807x.json --closure /path/to/dependency-closure.json --inventory /path/to/device-report.txt
```

工具仅输出带输入摘要的具体差异/缺项，不写入任何输入，不授予安装/发布权限。其退出码 2 表示诊断仍不构成目标验收；其他插件的运行经验支持 SDK 选择，本项目实际 NGINX/WOL 的动态库、符号和目标功能/异常/资源仍需独立验证。以下 r137 及更早说明为历史背景。

## r137 工程构建已落实（2026-10-27）

已校验官方24.10.6 SDK字节并实际构建独立Shell/Lua工程三包，完成包内入口和模板验证，详见[工程验证三包](工程验证三包.md)。工程manifest及构建入口与正式目标清单/发布门禁分开；不将QWRT verified或ABI改成已通过，不以独立只读包代替完整产品。以下原正式构建关口继续适用，历史“本阶段不构建”描述不否认r137工程产物。

本阶段把已有证据和可执行入口连起来，提前确认后续三包与生产接管的约束。目标仍以 `targets/qwrt-r26.3.8-ipq807x.json` 为准，`verified=false`，SDK 与 ABI 未冻结。宿主 Linux、模拟 TLS 或浏览器通过不构成目标兼容结论。

## 当前关口

| 范围 | 已有依据 | 仍需完成 |
| --- | --- | --- |
| 设备与前端 | 目标兼容性说明；详细设备资料只在本地保存 | 实际设备的 Lua/JS、模块接口、文件方法和安装路径核实 |
| SDK/ABI | 已有候选方向 | 官方 SDK 字节摘要、固件分支/定制来源、ELF 解释器、SONAME/符号及依赖匹配；不能由相同 CPU 架构推定兼容 |
| Lua 候选页面 | 本地 Lua 传输与浏览器夹具 | 真实 HTTP 会话、GET/POST、CSRF、nixio 文件方法及原生模板渲染 |
| JS 候选页面 | 本地页面与边界夹具 | 实际 ucode 模块导入、rpcd 加载、会话 ACL 与拒绝路径 |
| 生产与三包 | 发布条件检查会拒绝当前草稿 | Shell/C 完整迁移、Core 包名/升级契约、生产配置及生命周期接管，再从同提交构建 Core/LuCI/中文三包 |

`project/core/Makefile` 仍构建 Go 对照核心并声明旧 Core 包名，生产 LuCI 配方不安装 `project/luci/prototype`；不能仅填 SDK URL、安装候选文件或打开门禁就绕过这些条件。

## 目标设备上的只读核实

在已经获准访问的实际目标上运行以下入口，输出保存在本地详细验证资料中。入口本身不建立远程连接，不导出 UCI、凭据、会话值或私钥，也不执行 HomeGate 后端、安装软件或启停服务。

```sh
sh scripts/核实设备.sh
sh scripts/补充核实设备.sh
sh scripts/核实LuCI运行接口.sh
```

新入口只核实候选代码直接依赖的 Lua 模块/函数、ucode `fs` 命名导入、固定安装路径和两个 ubus 对象的**方法签名**。它不调用 `session list`、`access` 或任何 HomeGate 方法。非 OpenWrt 主机返回 2 并标明 `target-required`；在 OpenWrt 上返回 0 仅表示清单收集结束，缺项仍会列出，`acceptance=false`、`production_ready=false` 不变。命令存在或模块可导入不证明真实会话授权、并发文件语义或写入行为已通过。

## 宿主与构建入口

只读核实当前构建阻断原因，不下载 SDK：

```sh
python3 scripts/project.py --check
python3 scripts/检查发布条件.py --target targets/qwrt-r26.3.8-ipq807x.json --luci lua --format ipk
```

当前第二条应返回 2。目标/ABI/资源、SDK、完整核心及包名条件缺失时继续拒绝；失败不是通过，也不应通过修改 `verified` 或省略检查恢复准入。`scripts/目标SDK构建.py` 是已有正式构建入口，只有这些前置条件具备后才执行；本阶段不构建或发布。

`scripts/check-ucode.sh` 从 r81 起同时保留生产 JS 编译，并运行 DDNS 候选的真实宿主语法/导入、签名及关闭门禁响应检查，见[候选 ucode 宿主验证](DDNS候选ucode宿主验证.md)。r82 的 `scripts/check-rpcd.sh` 增加[隔离真实 rpcd 与会话 ACL 验证](DDNS候选rpcd与会话ACL验证.md)。固定运行时可按摘要复用；r83 的 [HTTP 会话授权入口](DDNS候选HTTP会话授权验证.md) 验证宿主 uhttpd 的会话授权；r84 的 [Lua LuCI 宿主入口](LuaLuCI会话与CSRF宿主验证.md) 覆盖固定官方基线的真实CGI会话/POST/CSRF/nixio权限。目标记录09ae68b尚未映射官方源码，目标兼容性、TLS和设备仍须独立验证。目标当前采用 Lua 候选，JS 是独立待验分支，宿主检查不替代目标能力核实。

## 下一步

先以目标只读输出确认实际接口缺口，冻结可信 SDK 与 ABI 验证路线；随后推进完整业务/生产读取端、秘密和生命周期接管，并准备真实会话与目标三包验证。门禁、未知结果屏障、旧生产配方与回执证据继续保留。详细 SDK 候选、原始设备信息和逐次结果仍只在本地保存。
