# CI 私有隔离与 AppArmor 前置

CI63在Ubuntu24.04的bwrap0.9.0-1ubuntu0.3建立私有loopback时返回EPERM，rpcd用例未启动。相同bwrap在现有WSL可运行，WSL不暴露AppArmor非特权userns限制。因此不能把本地通过当成runner策略已验证。

`scripts/prepare-ci-isolation.py`先以非root用户运行真实bwrap探测：私有user/PID/mount/network namespace，外层用户仅映射内部UID0，CapEff/CapPrm/CapBnd均0，源码只读，私有loopback实际连接成功。原rpcd、HTTP、LuCI及Shell读取检查保持原隔离和验收条件。

探测通过则不调整任何策略。只有探测精确复现RTM_NEWADDR的EPERM、内核AppArmor限制为1、且处于GitHub提供的临时runner时，才从固定Ubuntu官方软件包提取并加载bwrap专用配置。自托管runner或其他错误直接拒绝，不修改本机或全局userns/AppArmor开关，不共享宿主网络。

固定包为`apparmor-profiles_4.0.1really4.0.1-0ubuntu0.24.04.9_all.deb`，官方源`https://archive.ubuntu.com/ubuntu/pool/main/a/apparmor/`，包SHA256为`90b02aa006eea7702cd4e851343e469e41365dda42145a3cb035de1d6c773b8c`；提取`usr/share/apparmor/extra-profiles/bwrap-userns-restrict`，配置SHA256为`11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9`。只解包这一个资料包，不安装或加载其余策略；本地可用现有apparmor_parser离线校验，`--skip-kernel-load`不加载内核策略。

Ubuntu配置允许bwrap构造namespace，子进程转入拒绝capabilities的unpriv_bwrap配置；加载后必须重新证明私有网络、实际loopback、只读源码和全部零capabilities，确认全局限制值未变且子进程标签包含unpriv_bwrap，才继续真实业务回归。摘要和前后探测写入非公开build目录；不打印凭据或配置数据。发行版策略加载分支仍须由真实runner结果核实，本地无AppArmor限制时不能冒称已验证该分支。

依据：[Ubuntu bwrap配置机制](https://documentation.ubuntu.com/release-notes/25.04/)、[AppArmor官方配置源](https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor/profiles/extras/bwrap-userns-restrict)、[GitHub runner环境变量](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)。实际采用已核验的Ubuntu24.04软件包配置字节，不直接使用滚动master。
