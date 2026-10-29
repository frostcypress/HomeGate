#!/bin/sh
# Certificate-scoped DNS-01 hook. Never guesses ownership or retries unknown writes.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
acme_dns_hook_enabled=false
[ "$acme_dns_hook_enabled" = true ] && [ "$#" -eq 1 ] && [ "$(id -u)" = 0 ] || exit 2
HG_ACTION=$1;case "$HG_ACTION" in add|remove) ;;*) exit 2;;esac
HG_JOB=${HOMEGATE_ACME_JOB:-};HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
. "$HG_DIR/homegate-acme-common.sh"
if [ "$HG_ACTION" = remove ];then hg_source_guard || exit 1;else hg_guard || exit 1;fi
lua "$HG_DIR/homegate-acme.lua" dns-input "$HG_JOB" "$HG_ACTION" || exit 1
HG_SUM=$(lua "$HG_DIR/homegate-acme.lua" dns-tuple "$HG_JOB" | sha256sum) || exit 1;HG_KEY=${HG_SUM%% *};hg_hex "$HG_KEY" 64 || exit 1
HG_STATE=none
if hg_exists "$HG_PATH/challenges/$HG_KEY.json";then
 hg_file "$HG_PATH/challenges/$HG_KEY.json" 4096 || exit 1
 HG_STATE=$(lua "$HG_DIR/homegate-acme.lua" challenge-state "$HG_JOB" "$HG_KEY") || exit 1
fi
if [ "$HG_ACTION" = add ];then
 case "$HG_STATE" in owned|preexisting) exit 0;;none) ;;*) exit 1;;esac
else
 case "$HG_STATE" in preexisting|removed) exit 0;;owned) ;;*) exit 1;;esac
fi
hg_publish_challenge() {
 lua "$HG_DIR/homegate-acme.lua" challenge-write "$HG_JOB" "$HG_KEY" "$1" &&
 fsync "$HG_PATH/challenges/$HG_KEY.next" "$HG_PATH/challenges" &&
 mv -f "$HG_PATH/challenges/$HG_KEY.next" "$HG_PATH/challenges/$HG_KEY.json" &&
 fsync "$HG_PATH/challenges/$HG_KEY.json" "$HG_PATH/challenges"
}
hg_publish_challenge prepared || exit 1
HG_PROVIDER=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" provider) || exit 1
HG_ACCOUNT=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" account) || exit 1
HG_REVISION=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" revision) || exit 1
lua "$HG_DIR/homegate-acme.lua" dns-request "$HG_JOB" > "$HG_PATH/dns.request" || exit 1
cat "$HG_PATH/dns.request" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- | ash "$HG_DIR/homegate-cloudflare-read.sh" --acme-records-internal "$HG_PROVIDER" "$HG_ACCOUNT" --confirm > "$HG_PATH/dns.result" 2>/dev/null & HG_PID=$!
HG_RC=0;wait "$HG_PID" || HG_RC=$?
HG_OUT=$(lua "$HG_DIR/homegate-acme.lua" dns-result "$HG_JOB" "$HG_RC" < "$HG_PATH/dns.result") || { hg_publish_challenge unknown;exit 1; }
# A confirmed operation must retain its original, validated checkpoint before
# the explicit issue workflow acknowledges that one successful transition.
if [ "$HG_OUT" = owned ];then
 HG_RECEIPT=$HG_PATH/receipts/$HG_KEY-$HG_ACTION
 ! hg_exists "$HG_RECEIPT" && mkdir "$HG_RECEIPT" || exit 1
 HG_JOURNAL=$HG_STORE/dns-operation
 hg_dir "$HG_JOURNAL" && hg_file "$HG_JOURNAL/current" 2 && hg_file "$HG_JOURNAL/terminal" 4096 && hg_file "$HG_JOURNAL/terminal-meta" 512 || exit 1
 for HG_SLOT in 1 2;do
  if hg_exists "$HG_JOURNAL/slot-$HG_SLOT";then
   hg_dir "$HG_JOURNAL/slot-$HG_SLOT" && hg_file "$HG_JOURNAL/slot-$HG_SLOT/context" 8388608 && hg_file "$HG_JOURNAL/slot-$HG_SLOT/manifest" 512 || exit 1
   mkdir "$HG_RECEIPT/slot-$HG_SLOT" || exit 1
   for HG_MEMBER in context manifest;do cp "$HG_JOURNAL/slot-$HG_SLOT/$HG_MEMBER" "$HG_RECEIPT/slot-$HG_SLOT/$HG_MEMBER" && fsync "$HG_RECEIPT/slot-$HG_SLOT/$HG_MEMBER" || exit 1;done
   fsync "$HG_RECEIPT/slot-$HG_SLOT" || exit 1
  fi
 done
 for HG_MEMBER in current terminal terminal-meta;do cp "$HG_JOURNAL/$HG_MEMBER" "$HG_RECEIPT/$HG_MEMBER" && fsync "$HG_RECEIPT/$HG_MEMBER" || exit 1;done
 printf '%s\n' "$HG_PROVIDER" "$HG_ACCOUNT" "$HG_REVISION" "$HG_PID" > "$HG_RECEIPT/origin"
 fsync "$HG_RECEIPT/origin" "$HG_RECEIPT" "$HG_PATH/receipts" || exit 1
 # Both handlers rebind the original provider/context/source and PID. Unknown
 # results never reach this branch and retain the global DNS writer fence.
 ash "$HG_DIR/homegate-cloudflare-read.sh" --runtime-collect-receipt-internal "$HG_PROVIDER" "$HG_ACCOUNT" "$HG_PID" --confirm >/dev/null 2>/dev/null || exit 1
 ash "$HG_DIR/homegate-cloudflare-read.sh" --runtime-retire-archive-internal "$HG_PROVIDER" "$HG_ACCOUNT" "$HG_PID" --confirm >/dev/null 2>/dev/null || exit 1
fi
[ "$(hg_binding)" = "$(cat "$HG_PATH/binding")" ] || exit 1
if [ "$HG_ACTION" = remove ];then HG_OUT=removed;fi
hg_publish_challenge "$HG_OUT"
