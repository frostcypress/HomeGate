# LuCI 与 Shell DDNS 异步任务链路验证

`scripts/luci-ddns-jobs-regressions.py` 使用真实 Lua CGI 会话/POST/CSRF、私有传输、Shell UI 及原异步任务后端。经真实授权预览/确认后提交任务，任务目录、元数据、锁和结果帧均由原协议创建，未构造替代任务JSON。入口加入既有原生UI专项的 `check-ddns-authority.sh`，不追加到接近时限的源码组。

七项检查覆盖：真实持锁pending时的相同标识去重/新任务拒绝/可读观察；启动失败后的interrupted/unknown保留和不重发；来源变化后的真实worker发布blocked/none；POST、CSRF、明确同意和输入校验；损坏或链接的真实结果保留并拒绝；原任务门禁关闭；目录锁忙及只读刷新不分配/重发。重复提交外层仍为effect:unknown，读取外层effect:none只描述读取，不改变历史last_effect。

启动时序夹具只包装固定setsid入口，保留原FD6/7/8与锁来源：默认模拟启动失败，或在FIFO上持有真实锁，测试明确释放后再exec系统setsid及原work命令。来源变化场景由夹具修改自身授权文件摘要，原worker据此生成已知未派发结果。没有替换业务响应、root检查、路径或锁协议；不是成功DNS更新验收。服务观察沿用停用/无实例夹具，curl/wget检出工具不得调用。

只写本次namespace夹具，外层非root、内部UID0且capabilities全零，源码和运行时只读。会话/token/确认码和凭据不写报告，任务读取拒绝时逐次比较原字节/权限/inode/链接；只有测试结束且原任务锁释放后，才清理本测试创建的RAM任务目录。每组仍受90秒约束，HTTP/CGI使用既有18秒边界。

真实供应商请求、已更新DNS的成功结果、RPC任务提交、维护接合、生产安装、目标SDK/ABI、三包及实机/资源仍待分别验收。实际本地及CI结果以独立记录为准。
