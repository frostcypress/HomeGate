# DDNS 生命周期与候选 Shell CLI

r73 本地专项完成。候选入口不安装到正式包，生产门禁关闭，旧 Go CLI/procd/包生命周期继续保留原字节。

固定 root 入口 `homegate-cli.sh` 的 `ddns-sync [rule-id]` 使用现有明确授权，选定规则调用原带状态执行器；不选规则调用原默认全批协调器。只转换固定参数，不接受路径、地址、请求体或批次自动收尾选项。全量同步仍在首个持久变更屏障后阻止后续写入，unknown 从不自动重试。`native_cli_enabled=false` 和下游既有门禁必须分别启用，环境不能开启；CLI 命令本身不授予规则权限。

`ddns-status [rule-id]` 在共同双锁下读取已核实普通配置的最多32个规则，逐项复用原状态工具及严格行解析，排序后整体输出。授权已撤销时仍可观察 unauthorized；读取不采样、不发送HTTP、不创建状态缓存，任何一行损坏都拒绝整份输出，不发布部分规则前缀。API v1、prototype、write_ready:false 与原逐行字段保持明确；这是候选报告，尚未改动旧 LuCI/CLI 消费者，不宣称完整 M01 兼容验收。ddns-delete、daemon 和其余冻结命令仍未迁移，本候选拒绝这些命令。

`schedule-run --confirm` 用 exec 进入原有界前台调度；`schedule-status`、`schedule-stop --confirm`、`schedule-reap --confirm` 复用原控制语义。候选入口先关闭调用者 FD3～9，防止继承外来内部帧或借锁。停止只请求不再准入，不能把 stopping 当作已静止。四个缩权/观察入口不受候选功能门禁限制，原 root/文件权限检查继续生效。

新增 `schedule-quiescent` 只在检查时刻获取现有准入/控制锁和共同双锁，核实无活跃拥有者、合法控制记录、无外层工作且持久写守卫允许后报告 quiescent:true、point_in_time:true、write_ready:false。它不创建锁/会话、不发送信号、不回收任何记录，不保证返回之后无人重新启动，不表示旧生产服务或系统其他工作已停止。持久成功回执、unknown、损坏控制或未知工作继续拒绝。

既有冷准备 `homegate-lifecycle-prepare.sh prepare|resume` 先建立或核实同一私有空准入锁，持 FD9 后才取 FD6，贯穿原持久 bootstrap；复验锁 inode，拒绝链接、错误权限、非空锁、已占用锁、任意遗留调度目录或外层 DDNS 工作。有效停止后仍须明确 reap，再重新调用 prepare/resume，不能用静止观察取代持锁或显式回收。候选 `lifecycle-prepare|lifecycle-resume` 仅接到这两个原入口；不自动启动、恢复任务、清理原DNS证据、重写凭据、改 UCI 或操作真实服务。

新增4静态/23非root运行、受影响15静态/14运行、2root及11工程通过；不代表远端CI、生产接管、冷启动设备验收、SDK/ABI、同源三包或资源测量。正式服务所有启动、重载、网络事件和卸载入口的迁移仍须后续贯通并验证。
