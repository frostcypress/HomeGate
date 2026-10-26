# HTTP/RPC 与 Shell DDNS 异步任务链路验证

`scripts/rpc-ddns-jobs-regressions.py` 经真实HTTP会话ACL、rpcd参数检查、ucode/fs私有传输及原Shell任务后端执行。六项复用Lua任务场景，覆盖pending/相同标识去重、启动失败unknown、来源变化后原worker发布未派发结果、损坏/链接结果保留、门禁和目录锁。另四项验证参数/明确同意、reader/匿名/销毁会话及会话字段注入拒绝、Bearer提交与旧式重放共享同一任务、批量请求逐元素授权/去重。

写入账号必须通过真实权限检查；只读账号可以观察任务但不能提交。JSON-RPC拒绝、ubus类型错误和HTTP200内的业务拒绝分别验证。相同任务经Bearer/旧式或批量重复提交只启动一次；中断继续保留interrupted/unknown。读取effect:none不覆盖原任务last_effect，未授权请求不能进入私有后端。请求实测0700/0600并清理，随机会话/确认码和凭据不输出。

启动时序控制复用Lua夹具：只包装固定setsid入口、保留原FD/锁，真实任务元数据及结果帧由原后端生成；没有替代结果JSON。所有作用域均在私有namespace内，外层非root、内部UID0、capabilities全零。真实供应商、DNS成功结果、生产接管、目标SDK/ABI、三包及实机资源仍未验收。

三个独立namespace分别保留90秒上限，HTTP采用既有18秒边界。入口加入现有原生UI专项的`check-ddns-authority.sh`，不增加源码组耗时或自动运行CI。实际本地及CI结果另行记录。

## r114 指定接口与混合授权真实任务

`rpc-ddns-provider-jobs-regressions.py`复用原RPC传输夹具与原供应商worker，在临时auto+Cloudflare/interface混合授权下只提交指定规则。8个独立场景覆盖：真实无变化、原成功回执/proof及重放屏障、接口缺失known-none、写后未知屏障、类型/同意及接口/地址覆盖参数拒绝、reader/匿名/失效身份和会话注入拒绝、Bearer提交与旧入口重放/reader观察、批量逐元素ACL和重复ID只执行一次。

任务与公网接口地址不同，公开RPC结果不得泄漏地址或设备；未授权请求必须止于后端之前。仍用固定运行时、curl7.83.1、真实回环TLS、原root/文件描述符/锁约束及18秒HTTP、90秒场景上限。新增入口纳入原Cloudflare native组，旧脚本顺序与场景保留；实际结果另存本地。其他供应商指定接口Web链路、完整生产、目标SDK/ABI/三包及实机仍须独立验收。

## r116 Aliyun指定接口真实任务

新增Aliyun RPC启动器复用其原HMAC-SHA1签名器、真实worker及HGALIJOURNAL1/proof，验证与Cloudflare同样的8项合同：无变化、原成功回执、缺失接口known-none、写后unknown、类型/同意与地址接口覆盖拒绝、身份ACL/reader观察、Bearer与旧入口重放、批量逐元素ACL/重复提交只执行一次。

共用RPC传输夹具只按固定TASK_RULE构造测试请求，Aliyun使用ddns_0与Aliyun记录格式；Cloudflare仍为ddns_1。原权限、CA/SNI、签名工具所有权、锁与超时保持。仅临时配置与真实本地TLS；其他供应商Web指定接口、生产/目标SDK/三包与实机仍待独立验收。实际结果单独本地记录。

## r117 DNSPod Lua指定接口真实任务

真实Lua会话与POST/CSRF确认DNSPod/interface(ddns_2)+Cloudflare/auto(ddns_1)混合授权，只提交DNSPod任务。新增5场景验证：指定接口无变化、真实CreateRecord与原HGDNPJOURNAL1/task proof及重放屏障、缺失接口known-none不回退WAN、CSRF与预览后接口变化拒绝、写后响应失败unknown保留证据且不重试。默认WAN地址与指定接口不同，实际请求仍经独立TC3验证、原OpenSSL和固定curl/TLS传输。

共用授权夹具仅接受固定规则组合，保留Cloudflare/Aliyun原选择；CSRF拒绝请求与确认预览使用实际供应商选择。仅临时本地TLS验证，DNSPod RPC、华为云、生产/目标SDK/三包及实机仍待；实际通过结果单独本地记录。

## r118 DNSPod RPC指定接口真实任务

新增RPC启动器复用DNSPod真实Lua任务、独立TC3签名验证及原worker/HGDNPJOURNAL1/proof，8项覆盖指定接口无变化、真实创建与原回执、缺失接口known-none、写后unknown不重试、类型/同意和地址/接口覆盖拒绝、身份ACL与reader观察、Bearer/旧入口重放、批量逐元素ACL及重复ID单次执行。混合授权仍为Cloudflare/auto(ddns_1)+DNSPod/interface(ddns_2)，公开任务结果不泄露地址和设备。

共用RPC传输代码与全部project业务/候选代码保持r117字节；旧DNSPod归档场景单独回归。仅临时本地TLS，华为云指定接口Web及生产/目标SDK/三包/实机仍待。第10开发步只做本地冻结，下一轮单独准备和投递CI。

## r119 华为云Lua指定接口真实任务

真实Lua会话、POST与CSRF确认Cloudflare/auto(ddns_1)+Huawei/interface(ddns_3)混合授权，只提交华为云指定接口任务；默认WAN与指定接口地址不同。新增5场景覆盖指定接口无变化、真实POST创建与原HGHWJOURNAL1/task proof及重放屏障、缺失接口known-none不回退WAN、CSRF及预览后接口变化拒绝、写后unknown保留原证据且不重试。

保留原独立SDK-HMAC签名验证、固定region/domain ID来源、真实OpenSSL和固定curl/TLS/CA/SNI；混合任务公开结果也拒绝泄露DOMAIN/HOST/凭据标记。全部project业务/候选代码和共用测试传输不变；仅临时本地TLS，华为云RPC指定接口任务与生产/目标SDK/三包/实机仍待，实际本地结果单独记录。

## r120 华为云RPC指定接口真实任务

新增华为云HTTP/rpcd启动器，复用原SDK-HMAC签名验证、真实worker及HGHWJOURNAL1/task proof；授权组合为Cloudflare/auto(ddns_1)+Huawei/interface(ddns_3)，只执行选中华为云指定接口任务。8项覆盖无变化、真实创建与原回执、缺失接口known-none、写后unknown不重试、类型/同意及地址接口覆盖拒绝、身份ACL/reader观察、Bearer/旧入口重放、批量逐元素ACL及重复ID单次执行。

所有RPC任务结果同时检查地址、设备、Huawei domain ID、endpoint和凭据标记不外泄。共用RPC传输及全部project业务/候选代码保持r119字节；原Huawei RPC回执归档另做兼容回归。至此四家指定接口Lua/RPC隔离合同均已覆盖；生产接合、目标SDK/ABI、三包、实机和公网验收仍单独进行，本地结果不替代其完成条件。
