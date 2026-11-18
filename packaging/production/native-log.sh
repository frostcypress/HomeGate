#!/bin/sh
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C TZ=UTC0
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-

log=/var/log/homegate.log
lock=/var/run/homegate/native-log.lock
limit=1048576
file() {
 [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]
}
level=INFO
reason_text() {
 case "$1" in
  proxy_start_failed) printf '%s' 'HTTPS 代理启动失败';;
  proxy_stopped) printf '%s' '检测到代理进程停止';;
  firewall_apply_failed) printf '%s' 'IPv6 防火墙规则应用失败';;
  source_changed) printf '%s' '运行配置已变更';;
  source_unavailable) printf '%s' '无法读取运行配置';;
  ddns_stopped) printf '%s' 'DDNS 调度已停止';;
  ddns_resume_failed|ddns_pause_unknown) printf '%s' '未能确认 DDNS 调度切换';;
  authorization_required|ddns-authorization) printf '%s' 'DDNS 授权未确认';;
  certificate_failed|certificate_start_failed|certificate_unavailable|certificate_unknown) printf '%s' '证书处理失败或结果未确认';;
  certificate) printf '%s' '证书正在办理';;
  certificate_retry) printf '%s' '证书任务将在稍后重试';;
  stop_unknown|runtime-quiescent) printf '%s' '未能确认代理、防火墙和后台任务均已收尾';;
  runtime-stop|runtime-disable|runtime-boot-disable) printf '%s' '停用步骤未完成';;
  runtime-admission|runtime-start) printf '%s' '未能验证服务启动';;
  boot-enable) printf '%s' '未能确认开机自启';;
  editor-busy|dns-busy) printf '%s' '配置或 DNS 正被后台任务使用';;
  editor-check|editor-preview) printf '%s' '配置校验未通过';;
  editor-commit) printf '%s' '配置提交未完成';;
  access-region-transport) printf '%s' '无法下载地区数据';;
  access-region-invalid_data) printf '%s' '下载的地区数据校验失败';;
  access-live-reload) printf '%s' '未能确认代理加载访问规则';;
 esac
}
case "${1:-}" in
 service)
  [ "$#" = 3 ] || exit 2
  case "$2" in
   starting) message='HomeGate 启动条件已通过，正在初始化服务';;
   running) message='HomeGate 已运行，运行状态已通过校验';;
   stopping) message='HomeGate 收到停止请求，正在停止代理和后台任务';;
   stopped) message='HomeGate 已停止，代理、防火墙和后台任务已确认收尾';;
   renewing) message='ACME 正在处理证书签发或续期';;
   restart_required) level=WARN;message='HomeGate 需要重新启动';;
   failed) level=ERROR;message='HomeGate 运行失败';;
   *) exit 2;;
  esac
  case "$3" in ''|*[!a-z_]*) exit 2;;esac
  [ "${#3}" -le 64 ] || exit 2
  detail=$(reason_text "$3")
  if [ -n "$detail" ];then message="$message，$detail ($3)"
  elif [ "$level" != INFO ];then message="$message ($3)";fi;;
 web)
  [ "$#" = 4 ] || exit 2
  case "$2" in
   save_service) message='保存服务设置';;
   enable_service) message='在服务概览启用 HomeGate';;
   disable_service) message='在服务概览停用 HomeGate';;
   save_public) message='保存公网服务配置';;
   apply_public) message='保存并应用公网服务配置';;
   save_dns_account) message='保存 DNS 账户配置';;
   account_delete) message='删除 DNS 账户';;
   service_delete) message='删除公网服务';;
   ddns_sync) message='手动同步 DDNS';;
   cert_renew) message='手动续期证书';;
   cert_delete) message='删除证书';;
   certificate_apply) message='保存证书设置';;
   access_update) message='access 更新地区数据';;
   edit_access) message='access 修改自定义访问规则';;
   deny_access) message='access 拒绝来源访问';;
   allow_access) message='access 允许来源访问';;
   access_delete_rule) message='access 删除访问规则';;
   access_delete_entry) message='access 删除访问记录';;
   access_delete_all) message='access 清空访问记录和手动规则';;
   wol_apply) message='保存网络唤醒设置';;
   wake_host) message='WOL 发送网络唤醒请求';;
   save_maintenance) message='保存运行日志设置';;
   apply_maintenance) message='保存并应用维护设置';;
   config_reset) message='恢复默认配置';;
   config_import) message='导入插件配置';;
   update_url_save) message='保存插件更新地址';;
   *) exit 0;;
  esac
  case "$3" in
   stopping) detail='正在停止当前服务';;
   starting) detail='配置已提交，正在启动并校验服务';;
   restoring) detail='正在恢复操作前的服务';;
   disabled) detail='服务及开机自启已停用';;
   running) detail='配置已应用，服务已确认运行';;
   proxy_applied) detail='规则已保存并加载到代理';;
   saved_stopped) detail='配置已保存，服务已停止，等待重新应用';;
   region_published) detail='新地区数据已写入缓存';;
   region_running) detail='新地区数据已写入缓存，服务已按新数据启动并通过校验';;
   region_cached) detail='地址范围没有变化，沿用现有缓存';;
   region_limited) detail='达到当天更新次数上限，沿用现有缓存';;
   certificate_pending) detail='服务已确认运行，证书正在后台签发';;
   certificate_unknown) level=WARN;detail='服务已确认运行，证书签发结果待核对';;
   certificate_retry) level=WARN;detail='服务已确认运行，证书签发稍后重试';;
   restored) level=WARN;detail='操作失败，原有服务已恢复运行';;
   saved_failed) level=WARN;detail='配置已保存，后续操作失败';;
   unknown) level=WARN;detail='操作结果待核对';;
   failed) level=WARN;detail='操作失败';;
   ok)
    case "$2" in
     ddns_sync) detail='DNS 同步已完成';;
     cert_renew) detail='续期任务已完成，请查看证书状态';;
     wake_host) detail='唤醒报文已发出';;
     *) detail='操作已完成';;
    esac;;
   *) exit 2;;
  esac
  message="$message，$detail"
  case "$4" in
   none) ;;
   ''|*[!a-z_-]*) exit 2;;
   *) [ "${#4}" -le 64 ] || exit 2
      detail=$(reason_text "$4")
      message="$message${detail:+，$detail} ($4)";;
  esac;;
 package)
  [ "$#" = 2 ] || exit 2
  case "$2" in
   upgrade) message='软件包升级，正在停止 HomeGate 以替换程序';;
   reinstall) message='同版本重装，正在停止 HomeGate 以替换程序';;
   restore) message='软件包安装完成，正在恢复安装前的运行状态';;
   *) exit 2;;
  esac;;
 clear) [ "$#" = 1 ] || exit 2;;
 *) exit 2;;
esac

[ -d /var/run/homegate ] && [ ! -L /var/run/homegate ] || exit 7
if [ ! -e "$lock" ] && [ ! -L "$lock" ]; then (set -C; : > "$lock") || :; fi
file "$lock" && [ "$(stat -c %s "$lock")" = 0 ] || exit 7
exec 8>>"$lock"
flock -n 8 || exit 4
[ "$(stat -Lc '%d:%i' /proc/self/fd/8)" = "$(stat -c '%d:%i' "$lock")" ] || exit 7
if [ ! -e "$log" ] && [ ! -L "$log" ]; then (set -C; : > "$log") || exit 7; fi
file "$log" || exit 7
if [ "$1" = clear ]; then : > "$log";exit 0;fi

configured=$(uci -q get homegate.main.log_level 2>/dev/null) || configured=info
case "$configured:$level" in error:INFO|error:WARN|warn:INFO) exit 0;;esac
lines=$(uci -q get homegate.main.log_max_lines 2>/dev/null) || lines=1024
case "$lines" in ''|*[!0-9]*|0*) lines=1024;;esac
if [ "${#lines}" -gt 5 ] || [ "$lines" -lt 64 ] || [ "$lines" -gt 20000 ]; then lines=1024;fi
size=$(stat -c %s "$log")
if [ "$size" -ge "$limit" ] || [ "$(wc -l < "$log")" -ge "$lines" ];then
 pending=$(mktemp /var/log/.homegate.log.XXXXXX)
 trap 'rm -f "$pending"' EXIT
 # Drop the first line after the byte cut when that cut may split a line.
 if [ "$size" -ge "$limit" ];then
  tail -c "$((limit/2))" "$log" | sed '1d' | tail -n "$((lines-1))" > "$pending"
 else
  tail -n "$((lines-1))" "$log" > "$pending"
 fi
 mv -f "$pending" "$log"
fi
printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$log"
