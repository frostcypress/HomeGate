# HomeGate 私有代理组件

当前配方 `1.30.6-r3` 使用所选 SDK 的 OpenSSL/PCRE2 静态归档，将它们链接进专用 NGINX；运行时保留 libc/libgcc 依赖，不安装共享 TLS/PCRE2 库、不覆盖路由器系统库。`PKG_BUILD_DEPENDS` 保留实际源码构建依赖，运行依赖不再声明系统 OpenSSL/PCRE2。缺少静态归档或首次配置探测失败时停止，不回退到系统动态库；编译后再检查 ELF，出现 TLS/PCRE 动态依赖则拒绝打包。SDK 中其余包（例如 curl）的 TLS 依赖仍独立存在，本修复不表示全项目依赖已与目标兼容。

专用 TLS 初始化关闭外部 OpenSSL 配置加载，避免加载系统旧 ABI 的配置/engine/provider。原有 IP SAN 补丁、证书链/有效期/DNS 与 IP 身份校验和 worker 默认身份不变。静态依赖的原始许可证随组件安装，源码及本地补丁摘要见 `sources.json`。更换 SDK 或归档需重新记录实际版本/哈希，静态组合更新后必须重新构建本组件。

2026-10-31 用户提供库的离线证据显示 `.so.3` 实为 OpenSSL 1.1 SONAME，缺当前候选的五个 TLS 符号；PCRE2 固定路径亦未找到。新实际 AArch64 IPK 的 NEEDED 仅 libc/libgcc，静态符号覆盖不等于目标实际加载、TLS 功能或资源验收。`scripts/native-component-probe.sh` 供固定哈希的临时版本探测包使用，不是安装器；从r173起附带专用静态执行器，以每个10秒有界执行 `-V`/`--version`，不依赖目标timeout命令，不启动服务或发送WOL。见`docs/原生组件版本探测.md`。

以下为历史背景；原“目标动态 TLS/PCRE 待落实”由上述私有静态配方替代，实机验收仍待完成。

固定 nginx 1.30.6 官方归档与 SHA，保留 TLS、PCRE2、geo、map、rewrite、proxy 和 WebSocket 所需能力。仅安装 `/usr/libexec/homegate-nginx/nginx` 及许可证，不安装系统 nginx 服务或配置，不覆盖 `/usr/sbin/nginx`。核心显式依赖 `homegate-nginx`，审计显式依赖 `luci-lib-nixio`。

四个交叉补丁来自 ImmortalWrt packages 固定提交 `fce1553dac2d00c0b0f66647d8a9bd102b73e49c` 的 `net/nginx/patches/nginx`，来源和逐文件 SHA 见 `sources.json`，GPL-2.0 许可全文见源码 `legal/immortalwrt-packages-LICENSE`。不使用上游配方“忽略未知 configure 选项”的补丁，配置错误仍须失败。

r152 增加项目 BSD-2-Clause 补丁 `105-ip-san.patch`，组件修订为 `1.30.6-2`。字面 IPv4/IPv6 上游用 `inet_pton` 转为网络字节序后调用 OpenSSL `X509_check_ip`，只接受 iPAddress SAN，不把数字 DNS SAN 或 CN 当作 IP 身份；域名仍走原 `X509_check_host`。证书链、有效期、用途及 CA 校验保持 nginx 原路径。IPv6 的 `proxy_ssl_name` 保留方括号，避免 nginx 将冒号当作端口分隔，并由原路径禁止字面 IP 的 SNI。API 合同依据：[OpenSSL X509_check_host/X509_check_ip](https://docs.openssl.org/3.0/man3/X509_check_host/)。

目标配方与原生验证构建都必须应用同一补丁并携带 `homegate-ip-san-v1` build 标识；代理启动拒绝没有该标识的组件，不能把仅同版本的系统 nginx 当成支持 IP SAN。`prepare-nginx.py` 校验归档、补丁、构建标识及二进制哈希，输入变化须用新运行时目录，保留旧缓存。原生编译及流量验证不等于完整目标 TLS 组件、worker/ABI 或实机通过。

必要构建时，`scripts/工程三包构建.py` 会将本组件复制到同一 SDK 的独立 package 目录，先核实目标依赖配方，再编译此原生依赖与工程三包。依赖 IPK 单独放在 `runtime-dependencies`，不把宿主夹具或原生二进制塞进 `all` 架构核心包。配方缺失、编译失败或没有实际原生 IPK，均阻止声称完成三包构建。匹配的 libopenssl/libpcre2/luci-lib-nixio feed 尚需落实；不通过全环境重装或放宽门禁解决。

r151 复用旧工具链的验证只覆盖：四个补丁零 fuzz 应用、交叉 configure/尺寸/字节序探测、禁用 HTTP/TLS/PCRE 的最小 AArch64 ELF 编译与只读检查。这不是完整 TLS 组件构建或实机运行证据。目标动态加载、TLS/PCRE、nixio API、nobody/nogroup worker、临时文件权限及资源仍待完整组件和实机验证。`sources.json` 中目标通过标记继续为 false。

平时不构建三包，第10步也不固定构建。仅实机验证前或具体问题必须通过构建验证时，记录必要性后按需执行。
