#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo '请通过 root SSH 执行'; exit 1; }
VERSION=1.3.0-27
. "$ROOT/arm64-profile.sh"
[ "$(uname -m)" = aarch64 ] || { echo "需要 ARM64 系统，实际为 $(uname -m)"; exit 1; }
if command -v apk >/dev/null 2>&1 && ! command -v opkg >/dev/null 2>&1; then
 hg_apk_arch || exit 1
 ARCH=$HG_ARCH
 echo "APK 架构来源：$HG_ARCH_SOURCE；工具默认架构：$HG_DEFAULT_ARCH"
 MANAGER=apk
elif command -v opkg >/dev/null 2>&1; then
 ARCH=$(opkg print-architecture | awk -v supported="$(hg_architectures)" '$1=="arch" && index(" " supported " ", " " $2 " ") {if ($3+0>priority) {priority=$3+0;arch=$2}} END{print arch}')
 MANAGER=opkg
else echo '未找到支持的包管理器'; exit 1;fi
hg_supported_arch "$ARCH" || { echo "未支持的包架构：$ARCH";exit 1; }
echo "系统 ARM64，包管理器 $MANAGER，自动选用架构 $ARCH，版本 $VERSION"
if [ "$MANAGER" = apk ];then
 DIR="$ROOT/packages/modern-apk/$ARCH"
 [ -d "$DIR" ] || { echo "缺少架构目录：$DIR";exit 1; }
 (cd "$DIR" && sha256sum -c SHA256SUMS)
 APK_VERSION="${VERSION%-*}-r${VERSION##*-}"
 set -- "$DIR/homegate-$APK_VERSION.apk" "$DIR/luci-app-homegate-$APK_VERSION.apk" "$DIR/luci-i18n-homegate-zh-cn-$APK_VERSION.apk"
 for package in "$@";do [ -s "$package" ] || { echo "缺少组件：$package";exit 1; };done
 echo "包目录：$DIR；先模拟解析三个组件与依赖"
 task_preflight=$(mktemp /tmp/homegate-install-XXXXXX)
 trap 'rm -f "$task_preflight"' EXIT HUP INT TERM
 if ! apk --simulate add --allow-untrusted --force-non-repository "$@" >"$task_preflight" 2>&1;then
  cat "$task_preflight"
  if grep -Eiq 'uninstallable|arch:' "$task_preflight";then echo '架构或安装约束错误：停止安装，不强制绕过'
  elif grep -Eiq 'unexpected end|network|Failed to|fetch|repository.*(unavailable|error)|temporary error' "$task_preflight";then echo '索引/联网错误：请核实原有网络和软件源'
  else echo '依赖/约束解析失败：请核实固件的软件源与依赖提供者';fi
  exit 1
 fi
 cat "$task_preflight"
 apk add --allow-untrusted --force-non-repository "$@"
else
 DIR="$ROOT/packages/legacy-ipk/$ARCH"
 [ -d "$DIR" ] || { echo "缺少架构目录：$DIR";exit 1; }
 (cd "$DIR" && sha256sum -c SHA256SUMS)
 opkg install "$DIR/homegate_${VERSION}_${ARCH}.ipk" "$DIR/luci-app-homegate_${VERSION}_all.ipk" "$DIR/luci-i18n-homegate-zh-cn_${VERSION}_all.ipk"
fi
echo '安装完成，重新登录 LuCI。自动验收：sh verification/offline-verify.sh'
