# Aliyun 终态结算与确认归档

关闭门禁的原型扩展。入口、协调器和共用恢复工具新增固定 `aliyun_settlement_enabled=false`；原读取/记录/核对/持久门禁及引擎恢复读门禁仍适用。环境不能开启；生产配方不安装原型。未发布生产LuCI确认界面，当前确认仅隔离root CLI合同。

## 成功才能写终态

协调器等独立工作族静止，重新验证规范公共结果及实际attempt后，才调用固定内部settle。只接受原次操作的ok=true、effect=confirmed、created/updated/deleted，无错误、不可重试、无需核对；账户/配置代一致。创建或更新须对应最后检查点的AddDomainRecord/UpdateDomainRecord且affected=1；删除须对应DeleteDomainRecord、最后一个冻结匹配目标、最终计数等于检查点已确认数+1且等于冻结匹配总数。unchanged、失败、部分删除、unknown或观察报告不能写终态。

终态验证继续使用Aliyun规范结果编码，白名单私有检查点及原哈希绑定。terminal保存原公共成功报告；HGALITerminal1另绑定完整存储身份SHA、原boot、代次、账户/任务、保留代manifest SHA、最后检查点manifest SHA和terminal SHA，再校验规范LF帧SHA。仅原boot的原次成功工作可settle，不能重启后从当前观察补造成功。

准备terminal和meta后先fsync，再分别rename，最后fsync回执目录与存储父目录。任一失败不向调用者返回成功，保留检查点、私有工作与未知屏障；部分文件不自动修复。成功终态也不会立即解除屏障。

## 明确确认后收集

固定 `ACCOUNT --collect-receipt ORIGINAL_JOB --confirm`，不接收路径或URL。没有任何临时孤立工作后，重新核对当前配置代、身份、完整检查点/终态和迁移来源绑定。无terminal的unknown即使只读观察满足目标也不能收集；源配置变化、错误账户/任务、损坏、悬空链接或准备残留拒绝。

共用恢复工具新增固定Aliyun别名；Aliyun使用HGALIJOURNAL1/HGALITerminal1/HGALICollection1，与Cloudflare原格式分开校验。共用dns-operation、dns-settled和dns-collection，不另建锁/归档框架。两个供应商不能混用证据或绕过共同写屏障。

先持久发布绑定terminal-meta SHA的collecting凭据，再将固定dns-operation重命名为dns-settled并同步父目录，最后发布settled凭据。保留全部原文件，不递归删除。移动前已提交collecting凭据，或移动后父同步失败时，恢复工具只在下一次明确确认后复核继续；残留指针准备文件不会被擅自清除。重复已完成确认不改归档内容。

## 后续写入守卫

引擎每次写入仍调用同一archive-check，按已核对的检查点格式选择固定验证器；Aliyun入口门禁关闭也不能关闭此守卫。验证终态、全部槽、存储身份、保留历史代manifest及settled凭据，并重新fsync完成凭据/归档/父目录，失败继续阻止写入。配置代次后续改变时，仍核对被保留的原代证据，不把旧归档绑定到新的操作。

持久只读核对可读取完整终态的检查点；依旧只报告当前观察并保留归档/屏障。没有远端新增API或额外请求，凭据、签名和挑战值不进入公开报告。

归档容量仍固定一份：后续可以出现新的活动回执，但不能覆盖旧归档。后续明确确认退役、已有完整终态文件对修复及九文件孤立收集见《[Aliyun归档与中断维护.md](Aliyun归档与中断维护.md)》；完整检查点发布中断的明确恢复见《[Aliyun检查点中断恢复.md](Aliyun检查点中断恢复.md)》，不完整或损坏残留继续保留并阻塞。当前生产门禁继续关闭，SDK/OpenSSL ABI、同源三包、真实路由器重启/断电、权限/UI及资源峰值仍待验收。模拟boot变化不能代替设备证据。详细测试记录与接续ZIP仅本地；约8个百分点统一进度/CI批次及High/Ultra有限终审规则继续适用。
