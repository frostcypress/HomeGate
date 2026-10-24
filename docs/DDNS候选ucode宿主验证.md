# DDNS 候选 ucode 宿主验证

候选 rpcd 脚本是 `project/luci/prototype/js/homegate-ddns.uc`。生产配方仍不安装它，`native_ddns_rpc_enabled=false` 保持不变。本入口运行真实 Linux 宿主 ucode，覆盖编译、fs 命名导入、导出签名和关闭门禁响应；不启动 rpcd、不连接 ubus、不访问真实 DNS，也不表示目标设备或会话 ACL 已通过。

## 执行入口

Linux 上需要 C 编译器、make、CMake、pkg-config、json-c 开发库及 Python 3.12+。脚本只下载固定源码并构建本地工具，不安装系统软件。以普通用户执行：

```sh
sh scripts/check-ucode.sh
```

默认工作目录为 `build/ucode`。已有匹配运行时可以显式复用：

```sh
sh scripts/check-ucode.sh /absolute/path/to/retained/ucode-runtime
```

`prepare-ucode.py` 沿用既有入口固定的提交 `85922056ef7abeace3cca3ab28bc1ac2d88e31b1`，源码 SHA256 为 `54dda1e8a2757710c285659e42336f5054f1825f20d01a4016245bbf877f6da7`。准备完成后记录解释器、fs 模块和 libucode 的逐文件摘要，后续复用先核对；损坏、未完成或没有来源记录的旧构建不能仅凭文件存在冒充通过。可以为未完成尝试选择新目录，原证据保留。

## 验证内容

先保留生产 JS 适配文件的编译检查，再执行 `ucode-ddns-regressions.py` 的七项宿主检查：

- 从真实原生 fs 模块导入候选所需的五个函数。
- 编译并加载原候选源码及字节码，核实八个方法的参数签名和回调类型。
- 在源码和字节码两种形式下，八个方法分别接收六种正常/异常参数形状，必须返回精确的拒绝对象；submit 保留 `effect:unknown`，其余为 `none`，均 `write_ready:false`，不泄漏哨兵字段。
- 使用会立即抛错的 fs 测试模块，确认关闭门禁的原候选不会调用其导入的 mkdir/open/unlink/rmdir/popen。
- 直接触发一次受控 fs 操作，证明测试模块确实能够发现调用。
- 只在临时副本中打开门禁，确认同一测试模块会捕获后续调用；原候选始终不改，测试不执行真实写入路径。
- 修改运行时缓存副本中的 fs 模块，确认摘要校验会在执行前拒绝复用；原运行时保持不变。

直接触发 fs 和临时打开门禁两项用于证明夹具检出能力，不表示开启后的生产链路通过；缓存损坏控制只验证运行时完整性。请求对象由宿主测试提供，只模拟 rpcd 传入的 `args` 属性；真实 rpcd 的脚本加载、参数过滤、会话权限与 HTTP CSRF 仍需独立验收。

源码 CI 作业已接入相同入口，按项目集中 CI 周期执行，本地通过不能继承成新的远端通过。宿主构建使用的系统库也不代表 QWRT 目标的 ABI。

r82 增加了独立的[真实 rpcd 与会话 ACL 验证入口](DDNS候选rpcd与会话ACL验证.md)。本页七项仍只报告 ucode 宿主范围，真实总线与权限结果以该入口为准；HTTP/LuCI 与设备验收不在两者范围内。

接口依据：[ucode 的命名导入](https://ucode-lang.org/ucode/module-fs.html)、[编译与模块搜索参数](https://ucode-lang.org/ucode/tutorial-01-usage.html)、[loadfile](https://ucode-lang.org/ucode/module-core.html)、[rpcd 官方插件示例](https://github.com/openwrt/rpcd/blob/master/examples/ucode/example-plugin.uc)。
