# DNSPod 终态结算与确认归档

本原型增加独立关闭的 `dnspod_settlement_enabled=false`，入口、协调器及共用恢复工具均须具备；读取、记录、核对、持久回执及恢复读门禁继续适用。环境不能启用，生产配方不安装原型，没有正式LuCI确认入口。

## 原次成功与最后检查点

协调器等独立工作族静止，核对规范公开结果及实际attempt后才调用固定内部settle。只接受账户/配置代一致的ok=true、effect=confirmed、不可重试、无需核对的created/updated/deleted。创建或更新对应最后CreateRecord/ModifyRecord检查点，计数为1；删除对应DeleteRecord检查点，须位于最后冻结匹配目标，最终计数等于此前已确认数+1且等于全部匹配目标数。

未知、失败、部分删除、unchanged或只读观察不产生终态。即使当前查询满足目标，也不能把原unknown改成成功；不会重发变更。

terminal保留原规范成功报告。HGDNPTerminal1绑定存储身份SHA、原boot、代次、账户/原任务、保留代清单、最后检查点清单及终态SHA，再校验LF规范帧SHA。写终态要求仍是原boot的原次成功，不能启动后从当前观察重建。

准备文件对先同步，再分别重命名，最后同步回执和存储父目录。任一步失败不报告成功，保留持久和临时证据；部分准备文件不自动修复。完整终态也保留活动写屏障。

## 明确确认的归档

固定入口 `homegate-dnspod-read.sh ACCOUNT --collect-receipt ORIGINAL_JOB --confirm`，不接收路径、URL或请求体。要求没有临时孤立工作，重新核对当前来源绑定、配置代、完整检查点与终态。缺终态、错误账户/任务、来源变化、哈希损坏、链接、权限或准备残留均拒绝。

复用 `dns-operation` / `dns-settled` / `dns-collection` 和现有锁，不建立另一套框架。使用DNSPod独立HGDNPJOURNAL1、HGDNPTerminal1、HGDNPCollection1，不能套用Aliyun或Cloudflare证据。

先持久发布绑定terminal-meta SHA的collecting凭据，再将活动目录原子移动为归档并同步父目录，最后持久发布settled。归档保留全部原字节，不递归删除。已发布collecting后发生重命名或同步中断时，只有下一次明确确认并复核实际状态才继续；残留凭据准备文件不自动清理。重复已完成确认不修改归档。

## 写入守卫与边界

写入守卫按完整检查点格式选择固定验证器；DNSPod门禁关闭后仍验证归档、各槽、原身份/代清单、终态与settled凭据，并重新同步，失败继续阻塞。后续配置变化时保留并核对原历史代绑定，不把旧归档当成新配置证据。

完整终态仍允许只读核对，返回观察并保留屏障。归档容量为一份，新活动记录不能覆盖旧归档。退役、已有完整终态对的中断修复和原孤立工作受控收集见《[DNSPod归档与中断维护.md](DNSPod归档与中断维护.md)》。完整检查点中断恢复见《[DNSPod检查点中断恢复.md](DNSPod检查点中断恢复.md)》；未知证据继续保留。

协议仅为隔离root CLI合同。真实SDK/OpenSSL ABI、同源三包、生产授权UI及设备功能、断电/重启和资源峰值须另行验收，模拟boot变化不能代替设备证据。
