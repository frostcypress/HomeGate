# DDNS 原生授权与状态候选页面

r74 本地专项完成。候选源码位于 project/luci/prototype，生产 LuCI/核心配方不安装，四个新门禁默认关闭。旧控制器、42条路由、Go桥接、生产菜单与ACL保持原字节，不能将本地候选称为完整生产UI或目标LuCI验收。

Lua LuCI 页面使用受会话保护的 GET 状态和 POST 授权入口；模型重新校验POST和当前CSRF令牌，不能由请求自报已授权。JS LuCI 使用独立 homegate_ddns rpcd 服务：read ACL仅status，write ACL仅preview/commit/revoke；HTTP入口须在派发前核实rpcd会话权限，直接本地ubus不会自动执行这项检查。候选安装时需分别放置控制器/模型/模板、共享脚本和JS view/rpcd/ACL；生产安装与菜单切换待后续统一，不自动启用候选。

两端共用原生DOM紧凑列表及Bootstrap组件类，显示普通配置最多32条规则标识、供应商、状态和等待秒数。只读刷新不采样、不访问供应商、不创建调度缓存。选择规则后先POST预览，再核对绑定配置版本及完整规则集合，勾选同意并确认才提交原32位确认码。授权不会立即更新DNS、启动服务或打开旧UCI开关。多规则提交替换完整许可，规则以外的成员不会自动加入。明确撤销只调用原撤销入口，不替代正在进行的操作的停止或原持久收尾。

改变选择、刷新、关闭预览或响应异常立即失效本页待确认状态；旧异步响应不得重新启用确认。请求未确认时提示先刷新，不自动重试写入。确认码仅保存在当前页内存和受限请求中，不进入URL、本地存储或日志；规则/错误内容使用textContent。界面无DNS同步、删除、长时间调度、自动收集/归档/退役按钮；这些动作需继续沿用已有明确入口与屏障。

固定root后端 homegate-ddns-ui.sh 仅接收 /tmp/homegate-ddns-ui-32hex/request：700目录、600单链接普通文件、4096字节、FD绑定。严格JSON解析拒绝重复键、NUL、外来字段、任意命令/路径/地址及缺失明确同意。所有外来FD先关闭；仅转发原CLI状态及授权preview/preview-rules/commit/revoke四种固定动作。完整配置/凭据来源、授权摘要、时效和boot仍由原协议检查。原成功回执、unknown或恢复屏障存在时权限变更继续拒绝，不清理原DNS证据。

返回只允许已核实的公共状态/授权字段，绑定操作及预览规则集合，effect:none、write_ready:false；错误统一脱敏。Lua传输和独立rpcd传输都建立唯一私有请求目录，并在完成/失败后清理自身请求文件，不触碰业务证据。rpcd真实加载、目标浏览器/LuCI、安装布局/权限与生产接管仍待目标环境验证。

17新增/6受影响非root运行、4新/11受影响静态、7新/5受影响传输、双端10项页面（20组合）、2root及11工程通过；不代表CI、真实供应商、目标SDK/ABI、三包或实机资源验收。


## r75 扩展

r74 描述为授权/状态基线。当前候选额外支持明确单条同步与异步只读结果，见 [DDNS单次异步任务](DDNS单次异步任务.md)，并支持明确维护。当前read ACL为status/jobs，write ACL为preview/commit/revoke/submit/maintain_preview/maintain_commit；候选门禁均关闭。r81 增加[真实宿主 ucode 检查](DDNS候选ucode宿主验证.md)，r82 增加[隔离真实rpcd及会话ACL检查](DDNS候选rpcd与会话ACL验证.md)；r83 增加[宿主HTTP会话授权检查](DDNS候选HTTP会话授权验证.md)。r84 增加[固定官方Lua LuCI的真实CGI会话与POST/CSRF宿主入口](LuaLuCI会话与CSRF宿主验证.md)，并修正nixio私有权限参数。目标LuCI源码/兼容性、TLS、设备及生产安装仍未验收。
