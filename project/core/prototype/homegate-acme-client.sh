#!/bin/sh
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES RANDFILE HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
[ "$#" -eq 1 ] && [ "$(id -u)" = 0 ] || exit 2
HG_JOB=$1;HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
. "$HG_DIR/homegate-acme-common.sh"
hg_guard || exit 1
HOMEGATE_ACME_JOB=$HG_JOB;export HOMEGATE_ACME_JOB
HG_VENDOR=/usr/libexec/homegate/acme
HG_PIN=$(sha256sum "$HG_VENDOR/acme.sh") || exit 1
[ "${HG_PIN%% *}" = c7d68b021cfd6380ea83a82962abde5b484779fee0b97d38681dfa1396bbc8d7 ] || exit 1
HG_ENV=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" environment) || exit 1
HG_CA=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" ca) || exit 1
HG_CERT_ID=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" id) || exit 1
HG_ACCOUNT_HOME=/etc/homegate/acme/accounts/$HG_CA-$HG_ENV
if [ "$HG_CA" = zerossl ];then
 HG_EAB=$(lua "$HG_DIR/homegate-acme.lua" eab-read) || exit 1
 HG_EAB_PROFILE=${HG_EAB##* }
 HG_EAB=${HG_EAB% *}
 [ "$HG_EAB_PROFILE" = original ] || HG_ACCOUNT_HOME=$HG_ACCOUNT_HOME-$HG_EAB_PROFILE
fi
for HG_PARENT in /etc/homegate/acme/accounts "$HG_ACCOUNT_HOME";do
 if ! hg_exists "$HG_PARENT";then mkdir "$HG_PARENT" && fsync "$HG_PARENT" "${HG_PARENT%/*}" || exit 1;fi
 hg_dir "$HG_PARENT" || exit 1
done
# Existing client state is root-private and contains no symlinks. Never import
# an external account.conf or caller-supplied hook/reload command.
hg_account_check() {
 for HG_ENTRY in "$1/"* "$1/".[!.]* "$1/"..?*;do
  hg_exists "$HG_ENTRY" || continue
  if [ -d "$HG_ENTRY" ] && [ ! -L "$HG_ENTRY" ];then hg_dir "$HG_ENTRY" && hg_account_check "$HG_ENTRY" || return 1
  else hg_file "$HG_ENTRY" 262144 || return 1;fi
 done
}
hg_account_check "$HG_ACCOUNT_HOME" || exit 1
HOME=$HG_ACCOUNT_HOME;export HOME
HG_EMAIL=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" email) || exit 1
HG_DOMAINS=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" domains) || exit 1
HG_SERVER=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" directory) || exit 1
# Upstream POSIX shell intentionally uses unset variables. This does not permit
# caller-controlled options: every invocation below is constructed from scope.
LE_WORKING_DIR=$HG_VENDOR;LE_CONFIG_HOME=$HG_ACCOUNT_HOME;ACCOUNT_CONF_PATH=$HG_ACCOUNT_HOME/account.conf;CERT_HOME=$HG_PATH/issued;HTTP_HEADER=$HG_PATH/http.header
set +u
. "$HG_VENDOR/acme.sh" '' >/dev/null
HTTP_HEADER=$HG_PATH/http.header
AUTO_UPGRADE=0;ACME_HTTP_NO_REDIRECTS=1;DEBUG=0;LOG_FILE='';SYS_LOG=0;HTTPS_INSECURE='';ACME_USE_WGET=0
HG_HTTP() {
 HG_METHOD=$1;HG_URL=$2
 lua "$HG_DIR/homegate-acme.lua" transport "$HG_JOB" "$HG_METHOD" "$HG_URL" || return 1
 HTTP_HEADER=$HG_PATH/http.header
 HG_STATUS=$(
  exec 9>&1
  { /usr/bin/curl --disable --config "$HG_PATH/http.curl" --proto '=https' --proto-redir '=https' --proxy '' --noproxy '*' --connect-timeout 3 --max-time 10 --cacert /etc/ssl/certs/ca-certificates.crt --silent 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;printf '%s\n' "$?" >&9; } |
      lua "$HG_DIR/homegate-acme.lua" bounded-response "$HG_JOB" > "$HG_PATH/http.response"
 ) || return 1
 case "$HG_STATUS" in
  ''|*[!0-9]*) return 1;;
  *)
   if [ "$HG_STATUS" != 0 ];then
    printf 'HomeGate ACME curl_exit=%s\n' "$HG_STATUS" >&2
    if [ -x /usr/libexec/homegate/native-log.sh ];then
     ash /usr/libexec/homegate/native-log.sh certificate-transport "$HG_CERT_ID" "$HG_STATUS" >/dev/null 2>&1 || :
    fi
    case "$HG_STATUS" in 6|7|18|28|52|55|56|92) return 75;; *) return 1;; esac
   fi;;
 esac
 hg_file "$HG_PATH/http.header" 65536 || return 1
 [ -s "$HG_PATH/http.header" ] || return 75
 cat "$HG_PATH/http.response"
}
_get() { if [ -n "$2" ];then HG_HTTP HEAD "$1" </dev/null >/dev/null && cat "$HTTP_HEADER";else HG_HTTP GET "$1" </dev/null;fi; }
_post() {
 HG_POST_METHOD=${4:-POST};HG_POST_URL=$2;HG_POST_B64=$3
 if [ -n "$HG_POST_B64" ];then HG_ENCODED=$(printf '%s' "$1" | HG_HTTP "$HG_POST_METHOD" "$HG_POST_URL") || return $?
  printf '%s' "$HG_ENCODED" | _base64
 else printf '%s' "$1" | HG_HTTP "$HG_POST_METHOD" "$HG_POST_URL";fi
}
_hg_acme_validation_status() {
 case "$code" in 2[0-9][0-9]) lua "$HG_DIR/homegate-acme.lua" validation-status "$HG_JOB";; *) return 1;; esac
}
# acme.sh calls neither installer nor cron here. CA, paths and DNS hook are fixed.
set -- --issue --force --dns dns_homegate --server "$HG_SERVER" --home "$HG_VENDOR" --config-home "$HG_ACCOUNT_HOME" --cert-home "$HG_PATH/issued" --keylength ec-256 --dnssleep 60 --no-color --syslog 0
if [ "$HG_CA" = zerossl ];then
 set -- "$@" --eab-kid "${HG_EAB%% *}" --eab-hmac-key "${HG_EAB#* }"
 unset HG_EAB
fi
[ -z "$HG_EMAIL" ] || set -- "$@" --accountemail "$HG_EMAIL"
HG_FIRST=
while IFS= read -r HG_DOMAIN;do [ -n "$HG_DOMAIN" ] || exit 1;[ -n "$HG_FIRST" ] || HG_FIRST=$HG_DOMAIN;set -- "$@" -d "$HG_DOMAIN";done <<EOF
$HG_DOMAINS
EOF
main "$@" || exit 1
main --install-cert --ecc -d "$HG_FIRST" --server "$HG_SERVER" --home "$HG_VENDOR" --config-home "$HG_ACCOUNT_HOME" --cert-home "$HG_PATH/issued" --key-file "$HG_PATH/issued/privkey.pem" --fullchain-file "$HG_PATH/issued/fullchain.pem" --no-color --syslog 0 || exit 1
hg_account_check "$HG_ACCOUNT_HOME" || exit 1
for HG_FILE in "$HG_PATH/issued/fullchain.pem" "$HG_PATH/issued/privkey.pem";do hg_file "$HG_FILE" 65536 && fsync "$HG_FILE" || exit 1;done
fsync "$HG_PATH/issued" "$HG_ACCOUNT_HOME" "$HG_PATH"
