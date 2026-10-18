# DDNS 普通来源的明确确认收尾

内部协调器新增三个固定 root 别名：

- `--runtime-collect-orphan-internal PROVIDER ACCOUNT ORIGINAL_JOB --confirm`
- `--runtime-collect-receipt-internal PROVIDER ACCOUNT ORIGINAL_JOB --confirm`
- `--runtime-retire-archive-internal PROVIDER ACCOUNT ORIGINAL_JOB --confirm`

仅允许四个既有供应商、当前普通配置来源、规范账户/任务号与明确确认，不接受路径、地址、请求体或任意动作。协调器、临时工作收集器、持久回执工具和归档退役工具均有独立 `ddns_closeout_enabled=false` 门禁。原有 DDNS 和供应商门禁仍须分别满足；生产配方不安装原型，没有新增 Web/RPC、周期任务或自动收尾。

## 来源与确认边界

全部操作保有现有 frontend/supervisor 锁，使用 `runtime-ddns-recovery-snapshot-read` 重新校验普通来源、当前配置/凭据及完整私有帧。存在 `source.conf` 的普通代不会在读取失败后回退到旧迁移来源。当前主服务仍保持禁用；收尾不要求旧写授权继续有效，也不会生成新写授权。

任何尚存的 `.ddns-plan-*` 外层工作均先阻止这些维护动作。已确认外层工作按既有 `--collect-work ORIGINAL_JOB --confirm` 另行收集；unknown、缺失归属或不完整成功不能由本通道清理。不存在通过“当前云端值已正确”补造原成功的路径。

## 复用原持久协议

临时工作收集继续使用既有供应商孤立计划：必须有绑定正确的原终态、请求和冻结 context，原 PID 已静止、同 boot、固定成员权限/单链接/长度/哈希正确，计划发布后才逐项删除。部分删除只按有效计划明确续作；原检查点和终态保留，不归档、不重发请求。

回执归档继续使用原 `collecting → dns-settled → settled` 协议。四家均先按当前普通来源重新核实原检查点；原始成功、配置代、账户、任务和字节校验必须一致。完整终态以原字节移入一份有界归档；rename/fsync 中断保留写屏障，只有后续明确确认才续作。归档守卫不依赖新门禁，关闭功能也不能放行损坏证据。

归档退役继续使用既有固定成员哈希计划、`dns-retiring` 和有界完成凭据；不删除另一笔活动操作。检查模式保留在门禁之外，半完成退役仍阻止写入。每次退役都需明确确认，不能为了腾容量自动删除旧归档。

所有维护响应不授予 DDNS 运行许可；普通来源归档响应也保持 `write_ready:false`。持久写守卫恢复可用不等于当前规则已获授权，下一次写入仍须当前授权、来源、规则及所有屏障检查；托管入口另遵守现有间隔/退避。

## 仍未接入

本阶段是普通来源的明确维护通道，不是全批协调器：不自动串联清理、归档或退役，不处理无终态的未知操作，不增加恢复格式或第二套云协议。后续全批协调仍需多规则许可、单次采样、结果隔离及托管状态消费。正式 CLI/UI、生产生命周期、目标 SDK/ABI、真实三包和设备/资源验收继续独立待办。
