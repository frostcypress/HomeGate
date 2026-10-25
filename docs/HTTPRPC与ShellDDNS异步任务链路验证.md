# HTTP/RPC 与 Shell DDNS 异步任务链路验证

`scripts/rpc-ddns-jobs-regressions.py` 经真实HTTP会话ACL、rpcd参数检查、ucode/fs私有传输及原Shell任务后端执行。六项复用Lua任务场景，覆盖pending/相同标识去重、启动失败unknown、来源变化后原worker发布未派发结果、损坏/链接结果保留、门禁和目录锁。另四项验证参数/明确同意、reader/匿名/销毁会话及会话字段注入拒绝、Bearer提交与旧式重放共享同一任务、批量请求逐元素授权/去重。

写入账号必须通过真实权限检查；只读账号可以观察任务但不能提交。JSON-RPC拒绝、ubus类型错误和HTTP200内的业务拒绝分别验证。相同任务经Bearer/旧式或批量重复提交只启动一次；中断继续保留interrupted/unknown。读取effect:none不覆盖原任务last_effect，未授权请求不能进入私有后端。请求实测0700/0600并清理，随机会话/确认码和凭据不输出。

启动时序控制复用Lua夹具：只包装固定setsid入口、保留原FD/锁，真实任务元数据及结果帧由原后端生成；没有替代结果JSON。所有作用域均在私有namespace内，外层非root、内部UID0、capabilities全零。真实供应商、DNS成功结果、生产接管、目标SDK/ABI、三包及实机资源仍未验收。

三个独立namespace分别保留90秒上限，HTTP采用既有18秒边界。入口加入现有原生UI专项的`check-ddns-authority.sh`，不增加源码组耗时或自动运行CI。实际本地及CI结果另行记录。
