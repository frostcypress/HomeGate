#!/bin/sh
# Shared by installer/verifier. APK 3.0.5 database.c reads etc/apk/arch;
# --print-arch reports its compiled default, not the configured database.
hg_architectures() { printf '%s\n' 'aarch64 aarch64_generic aarch64_cortex-a53 aarch64_cortex-a72'; }
hg_supported_arch() {
 case "$1" in aarch64|aarch64_generic|aarch64_cortex-a53|aarch64_cortex-a72) return 0;; *) return 1;; esac
}
hg_apk_arch() {
 HG_ARCH= HG_ARCH_SOURCE= HG_DEFAULT_ARCH=
 task_arch_file=${HOMEGATE_APK_ARCH_FILE:-/etc/apk/arch}
 task_release_file=${HOMEGATE_RELEASE_FILE:-/etc/openwrt_release}
 HG_DEFAULT_ARCH=$(apk --print-arch) || return 1
 task_arches=
 if [ -e "$task_arch_file" ];then
  [ -r "$task_arch_file" ] || { echo 'APK 架构文件不可读' >&2;return 1; }
  # Do not execute firmware metadata. Validate every nonempty architecture.
  task_arches=$(awk 'NF {if(NF!=1 || $1 !~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/) exit 1;print $1}' "$task_arch_file") || { echo 'APK 架构文件格式无效' >&2;return 1; }
 fi
 if [ -n "$task_arches" ];then
  for task_arch in $task_arches;do
   if hg_supported_arch "$task_arch";then HG_ARCH=$task_arch;break;fi
  done
  [ -n "$HG_ARCH" ] || { echo "APK 注册架构无支持项：$task_arches" >&2;return 1; }
  HG_ARCH_SOURCE=$task_arch_file
 else
  hg_supported_arch "$HG_DEFAULT_ARCH" || { echo "APK 默认架构未支持：$HG_DEFAULT_ARCH" >&2;return 1; }
  task_release_arch=
  if [ -r "$task_release_file" ];then
   task_release_arch=$(awk -F= '$1=="DISTRIB_ARCH" {n++;v=substr($0,index($0,"=")+1);gsub(/^[\047\042]|[\047\042]$/,"",v);if(v !~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/)exit 1;print v} END {if(n>1)exit 1}' "$task_release_file") || { echo '固件架构元数据无效' >&2;return 1; }
  fi
  if [ -n "$task_release_arch" ] && [ "$task_release_arch" != "$HG_DEFAULT_ARCH" ];then
   echo "APK 未配置架构，默认 $HG_DEFAULT_ARCH 与固件 $task_release_arch 不一致；请核实 /etc/apk/arch，停止安装" >&2;return 1
  fi
  HG_ARCH=$HG_DEFAULT_ARCH;HG_ARCH_SOURCE='APK default (no configured architectures)'
 fi
}
