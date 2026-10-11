# 隔离 Shell 控制原型

这是新核心的第一段可审查源码，只覆盖公共配置读取与事件控制。生产配方不安装此目录；它不能替换 `/usr/bin/homegate`，没有 DNS、ACME、代理、WOL 或防火墙工作进程。

版本跟随根目录 VERSION/RELEASE。输出 JSON 始终带 `prototype: true`；`check` 还带 `complete_validation: false`，不能把公共字段检查当成完整业务验收。

## Linux 离线使用

需要 BusyBox ash、flock、stat、expr 等 applet，以及读取合成配置时的 UCI。先从源码根目录执行版本查询。下面的状态命令只写显式私有 `/tmp` 目录，不需要 root，也不访问现有 HomeGate 服务。

```sh
busybox ash project/core/prototype/homegate-prototype.sh version
export HOMEGATE_PROTO_STATE="$(mktemp -d /tmp/homegate-prototype-XXXXXX)"
busybox ash project/core/prototype/homegate-prototype.sh submit startup
busybox ash project/core/prototype/homegate-prototype.sh next
# 用 next 返回的 token 调用 complete；不要照抄固定 token。
busybox ash project/core/prototype/homegate-prototype.sh state
busybox ash project/core/prototype/homegate-prototype.sh advance
```

`check` 另需显式 `HOMEGATE_PROTO_CONFIG_DIR`，其中 `homegate` 是 UCI 文件，存在名为 main、类型为 homegate 的节。不提供默认 `/etc/config`，不写配置。输出只含开关、日志限制、续期天数、DDNS 间隔和端口；账号、密钥及邮箱不会输出。字段数值目前限九位十进制，尚未与旧核心全部输入边界对齐。

## 状态与错误合同

- 队列最多 8 项，待处理事件去重，先进先出；允许正在处理的事件再排一次。11 种事件名称与 Go 对照调度器一致。
- 一个活动任务；领取产生 `g<代次>s<序号>` token。`advance` 清空活动任务和队列、增加代次；旧 token 和重复完成请求被拒绝。`complete` 目前只确认队列任务，不提交业务结果。
- 状态目录及 `/tmp` 以下父目录必须属于当前 UID 且为 0700；锁/状态文件为 0600、单硬链接。拒绝符号链接、不安全父目录、损坏状态、未知事件及越界计数。
- 用 `flock -n` 互斥。一个状态文件通过同目录私有临时文件加 rename 发布，避免代次与队列跨文件不一致。尚无 fsync/断电持久化；状态在 `/tmp` 中，不能承担生产配置回滚。
- 退出码：0 成功；1 数据/文件错误；2 参数错误；4 锁忙、队列满或任务忙；5 token 已过期。计数耗尽返回错误，不回绕。

## 回归范围

```sh
python3 scripts/Shell原型回归.py --static
python3 scripts/Shell原型回归.py --runtime
```

静态模式需要固定版本 tree-sitter 解析库，检查语法树、隔离边界和事件名称。执行模式必须在 Linux 上使用真实 BusyBox ash，覆盖配置、队列、重放、代次、权限、损坏状态、真实锁冲突和 18 次并发提交；只模拟 UCI 外部接口，不模拟 Shell 或文件系统。

本机 Windows 已通过 3 项静态检查；10 项执行回归已在中文 GitHub Actions 通过。实际 UCI 解析、目标 BusyBox 构建选项、服务生命周期和资源峰值另需验证。

Linux 回归证据：https://github.com/frostcypress/HomeGate/actions/runs/38127877469；实机业务/SDK 构建仍未执行。
