# LuCI 与 Shell DDNS 只读链路验证

`scripts/luci-ddns-read-regressions.py` 在真实 uhttpd CGI、固定 Lua LuCI、rpcd 会话和 nixio 之上，执行原候选 Lua 模型的私有请求传输，再由真实 Shell DDNS UI、CLI、状态/任务后端与原 Lua 合同校验响应。它已接入 `scripts/check-luci.sh`，与原有十一项会话/CSRF检查分别运行。本轮九项只读检查通过；本地结果不代表远端 CI 已运行。

## 真实实现和夹具范围

复用 [r84 固定宿主基线](LuaLuCI会话与CSRF宿主验证.md)、既有 rpcd/uhttpd 及 BusyBox 1.33.2。外层 UID 非零，经独立 user/mount/PID/network namespace 映射为内部 UID 0，实测全部 capabilities 为零。只读挂载源码/运行时；仅夹具自有的 `/etc/config`、`/etc/homegate` 可写，运行状态在私有 `/var`；不接触宿主配置。共用隔离器拒绝把夹具目录之外的路径作为新增可写源。

原候选页面、模型及所有 Shell 门禁保持 false。临时副本仅改显式布尔开关，不改固定路径、UID检查、锁与文件描述符验证，也不替换状态/任务 JSON。Shell 所需 `ash/fsync` 来自原已验证的 BusyBox；`lua` 适配器固定使用已验证的 Lua 5.1及原生 LuCI 模块路径，不改变业务代码。入口薄包装只 stat 请求0700/0600权限、追加常量计数，再 exec 原 Shell UI，不读取或构造业务响应。

测试初始化通过真实 bootstrap、旧源迁移、预览、投影发布和完成命令建立普通事务代际，保留四供应商私有凭据用于检验脱敏。初始化的服务观察只使用夹具的“停用/无实例”响应，不运行服务动作、不代表目标 procd/生命周期验收。读取阶段核对该观察计数未增加。授权辅助门禁保持关闭，因此初始四供应商状态均为 unauthorized，不声称授权、供应商 API 或 DNS 执行通过。

任务元数据及历史 unknown 缓存由夹具按规范构造，未提交真实任务、未执行 DNS。任务 pending 使用真实跨进程 flock，interrupted 保留 unknown；历史未知状态保持 reconciliation_required，未完成文件使状态 blocked。HTTP 报告 effect:none 只描述本次读取，无权把历史未知效果解释为未发生写入。

## 九项检查

- 真实登录后四供应商有序、脱敏状态与空任务列表；空读取不新建状态缓存/任务目录。
- 同一规范任务在锁被占用和释放后分别报告 pending/interrupted，保留 last_effect:unknown，不重试或补写。
- 公共写锁或监督锁忙时整份状态拒绝，不返回部分规则。
- 原配置内容变化或权限不安全时拒绝，不自动修正。
- 状态缓存损坏、符号链接或目录权限不安全时拒绝。
- 任务目录锁忙、结果/元数据损坏时拒绝并保留证据。
- 只读方法拒绝 POST、额外业务字段或未知字段，且不进入 Shell 后端。
- 无/无效 Cookie 拒绝；恢复原关闭模型后仍精确503，不能靠已有会话开门禁。
- 规范历史 unknown 缓存仍需核对；未完成缓存使状态 blocked，不释放写权限。

每次读取前后比较私有配置/状态的字节、权限、inode、链接数；私有传输文件必须清理。报告及日志不保存真实会话/token或凭据；失败断言也压制私有快照。私有网络中只有宿主验证所需回环 HTTP/RPC，PATH中的 curl/wget 检出工具若被调用即失败。

## 尚待验证

本轮只覆盖 Lua HTTP 到 Shell 的读取接合；JS/rpcd 到真实后端、权限提交/撤销、异步任务提交和明确维护的完整业务接合继续待办。目标 LuCI 短提交来源、SDK/ABI、HTTPS、多角色 Lua菜单 ACL、真实三包、设备异常/资源和最终终审均未验收。生产配方不安装原型，原业务字节和发布门禁不因本轮检查改变。
