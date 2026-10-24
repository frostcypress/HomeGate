# HomeGate

基于 1.3.0-10 进行规范迁移的 OpenWrt 插件。当前为开发草稿，生产门禁关闭，尚无可安装的新三包；完整 Shell/C 业务迁移、目标 SDK/ABI、实机与资源验收仍未完成。

目标候选为 Zyxel Armor G5 (NBG7815) / QWRT R26.3.8 / aarch64_cortex-a53 / IPK / Lua LuCI。候选 SDK 不代表已经兼容，见 [目标兼容性说明](docs/目标兼容性报告.md)。

## 源码结构

- `project/core/`：新核心原型、配方及迁移对照；`src/` 中的 Go 实现用于保留业务合同和对照测试，不作为最终核心。
- `project/luci/`：Lua、JS 前端与公共中文语言源；沿用原生 LuCI 和 Bootstrap。
- `scripts/`、`packaging/`：必要的构建、校验、打包与回归工具及夹具。
- `.github/workflows/`：活动工作流，默认仅检查源码；目标构建和发布受门禁控制。
- `docs/`、`targets/`：有效接口、迁移及目标兼容信息；[历史功能合同](docs/历史接续_1.3.0-10.md)保留基线范围，旧测试不代表本版通过。
- `LICENSE`、`THIRD_PARTY_NOTICES`、`legal/`：本项目及第三方许可。

## 开发与检查

Python 3.12+；Lua 回归需 `lupa==2.8`，页面回归需 `playwright==1.63.0`、Node 和 Chromium/Edge。Shell 执行检查需要 Linux BusyBox；完整依赖和命令见工作流。

```sh
python3 scripts/project.py --check
python3 scripts/重构回归.py
python3 scripts/导航安全回归.py
python3 scripts/frontend-source-regressions.py
```

只编辑 `VERSION`、`RELEASE`，随后运行 `python3 scripts/project.py --sync`。修改 Lua Controller/HTM 后运行 `scripts/sync-frontend.py` 和 `scripts/build-js-views.py`，由 CI 检查生成副本。

配置备份只导出允许的公共字段，排除凭据、私钥和带认证地址；恢复后总开关关闭。生产配置迁移与完整生命周期仍需完成，见 [重构设计](docs/重构设计.md)。

目标设备的只读接口核实、SDK/ABI 与真实 LuCI/rpcd 的验证边界见 [目标验证入口](docs/目标SDK与LuCI验证入口.md)。

`sh scripts/check-luci.sh` 验证固定宿主的真实会话、POST/CSRF，以及 LuCI HTTP 到 Shell DDNS 状态/任务只读链路；依赖已准备的 BusyBox 1.33.2。所有原候选门禁保持关闭，详见 [只读链路边界](docs/LuCI与ShellDDNS只读链路验证.md)。

同一入口还验证 [HTTP/rpcd 到 Shell 只读链路](docs/HTTPRPC与ShellDDNS只读链路验证.md)，包括只读角色、旧式RPC及Bearer会话授权；临时夹具开启候选副本不表示生产接入完成。

## 构建与分发

工作流从同一提交检查源码；只有目标 SDK、ABI、核心和包名迁移满足门禁时才允许构建 Core、LuCI、中文语言三包。Lua/JS 与 IPK/APK 分开按目标选择。历史 Go 打包工具仅用于显式启用的对照验证，不能作为新三包交付。

公开仓库与源码产物只包含 `公开文件清单.json` 列出的必要文件。新增文件须审查用途和内容后更新该清单；CI 核对 Git 跟踪文件与清单完全一致。

```sh
python3 scripts/生成接续包.py --target pending --stage 源码检查 --public-source
```

公开源码包附逐文件 SHA256，不包含本地接续文档、详细验证、原始设备报告、截图或完整接续 ZIP。上述资料在本地完整保留；本地接续草稿仍使用 `--draft`，需要三份真实接续文档。公开源码包不等同于完整接续交付或已验收安装包。
