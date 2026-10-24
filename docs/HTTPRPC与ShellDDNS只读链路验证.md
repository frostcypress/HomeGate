# HTTP/RPC 与 Shell DDNS 只读链路验证

`scripts/rpc-ddns-read-regressions.py` 使用真实 HTTP 客户端、固定 uhttpd ubus 插件、rpcd 会话 ACL、原候选 ucode 的原生 fs 私有传输，再经真实 Shell UI/CLI/状态/任务后端返回脱敏结果。原候选 gate 仍为 false，只在独立 namespace 中开启临时副本。入口接入 `scripts/check-luci.sh`，与原有 LuCI11项、Lua/Shell只读9项分别运行。

## 十一项检查

前七项复用 [r85 的真实 Shell 读取场景](LuCI与ShellDDNS只读链路验证.md)，改由真实 HTTP/RPC 传输：四供应商脱敏有序状态/空任务、pending/interrupted任务、公共/监督锁忙、源配置内容/权限变化、损坏或链接缓存、目录锁忙及损坏任务、历史unknown/未完成缓存。它们验证同一后端在另一入口下的接合，不重复算作新的供应商业务实现。

另四项验证完整权限路径：

- 只读会话六个写方法在uhttpd授权阶段拒绝；匿名/无效/销毁会话的八方法均拒绝，不进入私有后端。
- 读取方法夹带规则/未知字段由真实rpcd参数校验拒绝；参数中的会话字段不能替代或提升HTTP会话权限。
- reader/writer在旧式RPC和现代Bearer入口获得一致的只读结果；现代入口拒绝reader写入及无/无效Bearer。临时Shell副本的gate重新关闭后，已授权会话仍得到精确业务拒绝对象。
- 批量请求逐元素授权，仅两个合法读取进入真实后端；写入和无效会话元素被拒绝。

HTTP200、ubus参数错误、HTTP会话ACL拒绝和候选业务拒绝分别核对，不能把HTTP200当业务成功。读取前后比较私有配置/状态字节、权限、inode和链接数，私有请求0700/0600并清理，curl/wget检出工具不被调用。随机会话/token和秘密不写入报告或断言正文。

## 边界

复用r79业务依赖及r81–r84固定宿主运行时，不增加软件或改宿主配置。外层非root映射到私有UID0，全部capabilities为零，源码/运行时只读，只有本次夹具的配置/事务目录可写。真实HomeGate RPC ACL逐字保留；只添加测试登录/退出所需session.login/destroy权限。初始化服务响应为“停用/无实例”夹具，任务元数据和unknown缓存为规范种子，未运行真实服务或DNS任务。

本轮只读结果初始为unauthorized，授权辅助门禁保持关闭；不执行writer业务请求，不验收JS页面交互、权限提交/撤销、异步提交/维护、HTTPS、目标LuCI源码/SDK/ABI、三包或实机资源。全部project/生产及候选字节、路由、ACL和配方不因本轮改变。集中CI结果需在远端终态后另行记录。
