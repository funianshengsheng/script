#!/usr/bin/env bash
set -euo pipefail

############################################################
# Aether TW IPv6 DDNS 脚本
# 支持：配置向导 / 控制台 / Cloudflare DDNS / TG 通知 / 卸载
############################################################

CONFIG_FILE="/etc/twip-cf-ddns/config"

############################
# 默认配置
############################

API_URL="https://billing.aethercloud.io/api/dynamicv6/vm/status"
VM_UUID=""
TARGET_WG_INTERFACE="tw"

CF_API_TOKEN="填你的CF_API_TOKEN"
CF_ZONE_ID="填你的CF_ZONE_ID"
CF_RECORD_NAME="填你的DDNS域名"
CF_TTL=120
CF_PROXIED=false

TG_BOT_TOKEN="填你的TG_BOT_TOKEN"
TG_CHAT_ID="填你的TG_CHAT_ID"

DISPLAY_TZ="Asia/Shanghai"

ENABLE_AUTO_TIMER=1
TIMER_INTERVAL_MINUTES=5

ENABLE_CONNECTIVITY_TEST=1
PING_COUNT=2
PING_WAIT=3
PING_TARGETS=(
  "2400:3200::1"
  "2001:4860:4860::8888"
  "2606:4700:4700::1111"
)

STATE_DIR="/var/lib/twip-cf-ddns"
LAST_IP_FILE="${STATE_DIR}/last_tw_ipv6"
ALERT_STATE_FILE="${STATE_DIR}/last_alert_state"

SCRIPT_INSTALL_PATH="/usr/local/bin/twip-cf-ddns.sh"

VERBOSE=1
LOG_DIR="/var/log/twip-cf-ddns"
LOG_FILE="${LOG_DIR}/twip-cf-ddns.log"
LOG_MAX_SIZE_MB=10
LOG_RETENTION_DAYS=7
ENABLE_LOG_ROTATE=1
LOG_CLEANUP_STAMP_FILE="${STATE_DIR}/last_log_cleanup"
LOG_CLEANUP_INTERVAL_SECONDS=86400

ENABLE_COLOR=1

CURL_CONNECT_TIMEOUT=6
CURL_MAX_TIME=20
CURL_RETRY=2

############################
# 内部变量
############################

SERVICE_FILE="/etc/systemd/system/twip-cf-ddns.service"
TIMER_FILE="/etc/systemd/system/twip-cf-ddns.timer"

############################
# 颜色 / 图标
############################

if [[ -t 1 && "${ENABLE_COLOR}" == "1" ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_MAGENTA=$'\033[35m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_MAGENTA=""
  C_CYAN=""
fi

ICON_INFO="ℹ"
ICON_STEP="➜"
ICON_OK="✔"
ICON_WARN="⚠"
ICON_ERR="✘"
ICON_NET="🌐"
ICON_DNS="🧭"
ICON_LOG="📝"
ICON_TG="📨"
ICON_RUN="🚀"
ICON_DONE="🎉"

############################
# 工具函数
############################
UI_WIDTH=72
KV_KEY_WIDTH=18

timestamp() {
  TZ="${DISPLAY_TZ}" date '+%F %T %Z'
}

_log_write() {
  local line="$1"
  [[ -n "${LOG_FILE:-}" && -d "$(dirname "$LOG_FILE")" ]] && echo "$line" >> "$LOG_FILE"
}

_print_pretty() {
  local color="$1" icon="$2" tag="$3" msg="$4"
  printf "%s%s %s %-6s%s %s\n" "$color" "$icon" "$(timestamp)" "$tag" "$C_RESET" "$msg"
}

log_info() {
  local msg="$*"
  [[ "$VERBOSE" == "1" ]] && _print_pretty "$C_BLUE" "$ICON_INFO" "[INFO]" "$msg"
  _log_write "[$(timestamp)] [INFO ] $msg"
}

log_step() {
  local msg="$*"
  [[ "$VERBOSE" == "1" ]] && _print_pretty "$C_CYAN" "$ICON_STEP" "[STEP]" "$msg"
  _log_write "[$(timestamp)] [STEP ] $msg"
}

log_ok() {
  local msg="$*"
  [[ "$VERBOSE" == "1" ]] && _print_pretty "$C_GREEN" "$ICON_OK" "[ OK ]" "$msg"
  _log_write "[$(timestamp)] [ OK  ] $msg"
}

warn() {
  local msg="$*"
  _print_pretty "$C_YELLOW" "$ICON_WARN" "[WARN]" "$msg" >&2
  _log_write "[$(timestamp)] [WARN ] $msg"
}

err() {
  local msg="$*"
  _print_pretty "$C_RED" "$ICON_ERR" "[ERR ]" "$msg" >&2
  _log_write "[$(timestamp)] [ERROR] $msg"
}

print_line() {
  printf '%*s\n' "$UI_WIDTH" '' | tr ' ' '='
}

print_subline() {
  printf '%*s\n' "$UI_WIDTH" '' | tr ' ' '-'
}

print_kv() {
  local key="$1"
  local val="$2"
  printf "  %-${KV_KEY_WIDTH}s : %b\n" "$key" "$val"
}

print_kv_plain() {
  local key="$1"
  local val="$2"
  printf "  %-${KV_KEY_WIDTH}s : %s\n" "$key" "$val"
}

log_banner() {
  local title="$*"
  if [[ "$VERBOSE" == "1" ]]; then
    echo
    printf "%s" "$C_MAGENTA"; print_line
    printf "%s%s%s\n" "$C_BOLD" "$title" "$C_RESET"
    printf "%s" "$C_MAGENTA"; print_line
    printf "%s" "$C_RESET"
  fi
  _log_write "[$(timestamp)] [=====] $title"
}

log_subtitle() {
  local title="$*"
  if [[ "$VERBOSE" == "1" ]]; then
    printf "%s" "$C_DIM"; print_subline
    printf "%s%s%s\n" "$C_BOLD" "$title" "$C_RESET"
    printf "%s" "$C_DIM"; print_subline
    printf "%s" "$C_RESET"
  fi
  _log_write "[$(timestamp)] [-----] $title"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "缺少依赖命令: $1"; exit 1; }
}

ensure_state_dir() {
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR" >/dev/null 2>&1 || true
}

ensure_log_dir() {
  mkdir -p "$LOG_DIR"
  chmod 700 "$LOG_DIR" >/dev/null 2>&1 || true
}

rotate_logs_if_needed() {
  [[ "$ENABLE_LOG_ROTATE" == "1" ]] || return 0
  [[ -f "$LOG_FILE" ]] || return 0
  local max_bytes current_size ts rotated_file
  max_bytes=$((LOG_MAX_SIZE_MB * 1024 * 1024))
  current_size="$(wc -c < "$LOG_FILE" 2>/dev/null | tr -d ' ' || echo 0)"
  if [[ "$current_size" =~ ^[0-9]+$ ]] && (( current_size >= max_bytes )); then
    ts="$(TZ="${DISPLAY_TZ}" date '+%Y%m%d-%H%M%S')"
    rotated_file="${LOG_DIR}/twip-cf-ddns-${ts}.log"
    mv "$LOG_FILE" "$rotated_file"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE" >/dev/null 2>&1 || true
    log_info "${ICON_LOG} 日志轮转完成: $rotated_file"
  fi
}

cleanup_old_logs_once_per_day() {
  [[ -d "$LOG_DIR" ]] || return 0
  local now last_cleanup=0
  now="$(date +%s)"
  [[ -f "$LOG_CLEANUP_STAMP_FILE" ]] && last_cleanup="$(cat "$LOG_CLEANUP_STAMP_FILE" 2>/dev/null || echo 0)"
  [[ "$last_cleanup" =~ ^[0-9]+$ ]] || last_cleanup=0
  (( now - last_cleanup < LOG_CLEANUP_INTERVAL_SECONDS )) && return 0
  local deleted_count=0
  while IFS= read -r _; do ((deleted_count++)) || true
  done < <(find "$LOG_DIR" -type f -name 'twip-cf-ddns*.log' -mtime +"$LOG_RETENTION_DAYS" -print -delete 2>/dev/null || true)
  echo "$now" > "$LOG_CLEANUP_STAMP_FILE"
  chmod 600 "$LOG_CLEANUP_STAMP_FILE" >/dev/null 2>&1 || true
  log_info "${ICON_LOG} 日志清理完成: 删除 ${deleted_count} 个超过 ${LOG_RETENTION_DAYS} 天的旧日志"
}

############################
# 配置文件加载 / 保存
############################

load_config() {
  if [[ ! -f "$CONFIG_FILE" ]]; then
    mkdir -p "$(dirname "$CONFIG_FILE")" 2>/dev/null || true
    return 0
  fi
  source "$CONFIG_FILE" || true
}

save_config() {
  mkdir -p "$(dirname "$CONFIG_FILE")"
  chmod 700 "$(dirname "$CONFIG_FILE")" >/dev/null 2>&1 || true
  cat > "$CONFIG_FILE" <<CFEOF
# TW IPv6 DDNS 配置文件
# 由 setup 向导自动生成，也可手动编辑
# 生成时间: $(TZ="${DISPLAY_TZ}" date '+%F %T %Z')

CF_API_TOKEN="${CF_API_TOKEN}"
CF_ZONE_ID="${CF_ZONE_ID}"
CF_RECORD_NAME="${CF_RECORD_NAME}"
CF_TTL="${CF_TTL}"
CF_PROXIED="${CF_PROXIED}"

TG_BOT_TOKEN="${TG_BOT_TOKEN}"
TG_CHAT_ID="${TG_CHAT_ID}"

DISPLAY_TZ="${DISPLAY_TZ}"
TIMER_INTERVAL_MINUTES="${TIMER_INTERVAL_MINUTES}"
VM_UUID="${VM_UUID}"
CFEOF
  chmod 600 "$CONFIG_FILE"
  log_ok "配置已保存到: $CONFIG_FILE"
}

############################
# 核心工具
############################

_is_placeholder() {
  [[ "$1" == 填你的* || -z "$1" ]]
}

mask_text() {
  local s="$1" len=${#1}
  (( len <= 8 )) && { echo "****"; return; }
  echo "${s:0:4}****${s: -4}"
}

detect_vm_uuid() {
  if [[ -n "$VM_UUID" ]]; then
    echo "$VM_UUID"; return 0
  fi
  if [[ -r /sys/class/dmi/id/product_uuid ]]; then
    tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid | tr -d '[:space:]'
    return 0
  fi
  if command -v dmidecode >/dev/null 2>&1; then
    local u
    u="$(dmidecode -s system-uuid 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ -n "$u" && "$u" != "notsettable" ]]; then
      echo "$u"; return 0
    fi
  fi
  err "无法自动检测 VM UUID，请在配置向导中手动填写 VM_UUID"
  return 1
}

validate_ipv6() {
  local ip="$1"
  [[ -n "$ip" && "$ip" == *:* ]]
}

short_ipv6() {
  local ip="$1"
  if [[ ${#ip} -le 28 ]]; then echo "$ip"
  else echo "${ip:0:16}...${ip: -8}"; fi
}

api_post_json() {
  local url="$1" payload="$2"
  curl -fsS \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" \
    --max-time "$CURL_MAX_TIME" \
    --retry "$CURL_RETRY" \
    --retry-delay 1 \
    --retry-connrefused \
    -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "$payload"
}

cf_api() {
  local method="$1" url="$2" data="${3:-}"
  if [[ -n "$data" ]]; then
    curl -fsS -X "$method" "$url" \
      -H "Authorization: Bearer $CF_API_TOKEN" \
      -H "Content-Type: application/json" \
      --data "$data"
  else
    curl -fsS -X "$method" "$url" \
      -H "Authorization: Bearer $CF_API_TOKEN" \
      -H "Content-Type: application/json"
  fi
}

send_tg_message() {
  local text="$1"
  if _is_placeholder "$TG_BOT_TOKEN" || _is_placeholder "$TG_CHAT_ID"; then
    log_info "${ICON_TG} Telegram 未配置，跳过通知"
    return 0
  fi
  curl -fsS -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    -H "Content-Type: application/json" \
    -d "$(jq -cn \
      --arg chat_id "$TG_CHAT_ID" \
      --arg text "$text" \
      '{chat_id:$chat_id,text:$text,parse_mode:"Markdown"}')" \
    >/dev/null || true
}

send_tg_success() {
  local old_ip="$1" new_ip="$2"
  local now_sh; now_sh="$(TZ="${DISPLAY_TZ}" date '+%Y-%m-%d %H:%M:%S %Z')"
  send_tg_message "✨ *TW IPv6 DDNS 更新成功*

🖥️ *域名:* \`${CF_RECORD_NAME}\`
🕒 *时间:* ${now_sh}

🔍 *检测结果:*
├ 原 IPv6: \`${old_ip:-不存在}\`
└ 新 IPv6: \`${new_ip}\`

✅ *状态:* 已同步至 Cloudflare"
}

send_tg_failure() {
  local reason="$1"
  local now_sh; now_sh="$(TZ="${DISPLAY_TZ}" date '+%Y-%m-%d %H:%M:%S %Z')"
  send_tg_message "❌ *TW IPv6 DDNS 故障告警*

🖥️ *域名:* \`${CF_RECORD_NAME}\`
🕒 *时间:* ${now_sh}

⚠️ *说明:* 脚本连续执行 2 次仍失败

📝 *故障原因:*
\`\`\`
${reason}
\`\`\`"
}

send_tg_recovery() {
  local current_ip="$1"
  local now_sh; now_sh="$(TZ="${DISPLAY_TZ}" date '+%Y-%m-%d %H:%M:%S %Z')"
  send_tg_message "✅ *TW IPv6 DDNS 故障恢复*

🧭️ *域名:* \`${CF_RECORD_NAME}\`
🕒 *时间:* ${now_sh}

🔄 *状态:* 之前故障，现已恢复正常
🧭 *当前 TW IPv6:* \`${current_ip}\`"
}

mark_failure_alert_sent() {
  echo "failure" > "$ALERT_STATE_FILE"
  chmod 600 "$ALERT_STATE_FILE" >/dev/null 2>&1 || true
}

mark_success_state() {
  echo "ok" > "$ALERT_STATE_FILE"
  chmod 600 "$ALERT_STATE_FILE" >/dev/null 2>&1 || true
}

last_alert_state() {
  [[ -f "$ALERT_STATE_FILE" ]] && cat "$ALERT_STATE_FILE" 2>/dev/null || true
}

check_local_has_ipv6() {
  ip -6 addr show scope global 2>/dev/null | grep -Fq "$1"
}

test_tw_ipv6_connectivity() {
  local ip="$1"
  if [[ "$ENABLE_CONNECTIVITY_TEST" != "1" ]]; then
    log_info "已禁用连通性测试"; return 0
  fi
  if [[ "${#PING_TARGETS[@]}" -eq 0 ]]; then
    warn "PING_TARGETS 为空，跳过连通性测试"; return 0
  fi

  log_subtitle "${ICON_NET} 连通性检查"

  log_step "检查本机是否存在目标 IPv6"
  if ! check_local_has_ipv6 "$ip"; then
    err "本机接口中未发现该 TW IPv6: $ip"
    return 1
  fi
  log_ok "本机已存在该 IPv6: $(short_ipv6 "$ip")"

  local target
  for target in "${PING_TARGETS[@]}"; do
    log_step "测试出口连通性 -> $target"
    if ping -6 -c "$PING_COUNT" -W "$PING_WAIT" "$target" >/dev/null 2>&1; then
      log_ok "连通性测试通过: $target"
      return 0
    fi
  done

  err "TW IPv6 对全部目标连通性测试失败"
  return 1
}

############################
# systemd 安装
############################

install_systemd_timer() {
  if [[ "$ENABLE_AUTO_TIMER" != "1" ]]; then
    log_info "已禁用自动安装 systemd timer"; return 0
  fi
  if [[ "$EUID" -ne 0 ]]; then
    warn "安装 sytimer root，已跳过"; return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "未找到 systemctl，已跳过 timer 安装"; return 0
  fi

  local interval="${TIMER_INTERVAL_MINUTES}"
  if ! [[ "$interval" =~ ^[0-9]+$ ]] || (( interval <= 0 )); then
    interval=5
  fi

  mkdir -p "$(dirname "$SCRIPT_INSTALL_PATH")"

  if [[ "$(readlink -f "$0" 2>/dev/null || echo "$0")" != "$SCRIPT_INSTALL_PATH" ]]; then
    if ! cmp -s "$0" "$SCRIPT_INSTALL_PATH" 2>/dev/null; then
      cp -f "$0" "$SCRIPT_INSTALL_PATH"
      chmod +x "$SCRIPT_INSTALL_PATH"
      log_ok "脚本已安装到: $SCRIPT_INSTALL_PATH"
    fi
  else
    chmod +x "$SCRIPT_INSTALL_PATH" >/dev/null 2>&1 || true
  fi

  local new_service_content
  new_service_content="[Unit]
Description=TW IPv6 Cloudflare DDNS
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_INSTALL_PATH} --run"

  local new_timer_content
  new_timer_content="[Unit]
Description=Run TW IPv6 DDNS every ${interval} minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval}min
Unit=twip-cf-ddns.service
Persistent=true

[Install]
WantedBy=timers.target"

  local needs_reload=0

  if [[ "$(cat "$SERVICE_FILE" 2>/dev/null)" != "$new_service_content" ]]; then
    echo "$new_service_content" > "$SERVICE_FILE"
    needs_reload=1
  fi

  if [[ "$(cat "$TIMER_FILE" 2>/dev/null)" != "$new_timer_content" ]]; then
    echo "$new_timer_content" > "$TIMER_FILE"
    needs_reload=1
  fi

  if [[ "$needs_reload" -eq 1 ]]; then
    systemctl daemon-reload
    log_info "systemd 配置已更新，已重载"
  fi

  systemctl enable --now twip-cf-ddns.timer >/dev/null 2>&1 || {
    warn "启用 twip-cf-ddns.timer 失败"; return 0
  }
  log_ok "systemd timer 已启用，执行间隔: ${interval} 分钟"

  # 安装 tw 快捷命令
  local tw_cmd_content
  tw_cmd_content="#!/usr/bin/env bash
exec ${SCRIPT_INSTALL_PATH} console"

  if [[ ! -f /usr/local/bin/tw ]] || \
     [[ "$(cat /usr/local/bin/tw 2>/dev/null)" != "$tw_cmd_content" ]]; then
    echo "$tw_cmd_content" > /usr/local/bin/tw
    chmod +x /usr/local/bin/tw
    log_ok "快捷命令已安装: 输入 'tw' 打开控制台"
  fi
}

############################
# 配置向导
############################

_prompt_input() {
  local prompt="$1" current="$2" secret="${3:-0}" input=""

  if [[ "$secret" == "1" ]]; then
    printf "  %s%s%s" "$C_BOLD" "$prompt" "$C_RESET" >/dev/tty
    [[ -n "$current" ]] && printf " %s[当前: %s]%s" "$C_DIM" "$(mask_text "$current")" "$C_RESET" >/dev/tty
    printf ": " >/dev/tty
    read -rs input </dev/tty || {
      echo >/dev/tty
      err "读取输入失败"
      exit 1
    }
    echo >/dev/tty
  else
    printf "  %s%s%s" "$C_BOLD" "$prompt" "$C_RESET" >/dev/tty
    [[ -n "$current" ]] && printf " %s[当前: %s]%s" "$C_DIM" "$current" "$C_RESET" >/dev/tty
    printf ": " >/dev/tty
    read -r input </dev/tty || {
      err "读取输入失败"
      exit 1
    }
  fi

  if [[ -z "$input" && -n "$current" ]]; then
    printf '%s\n' "$current"
  else
    printf '%s\n' "$input"
  fi
}

run_setup() {
  exec </dev/tty 2>/dev/null || true
  clear 2>/dev/null || true
  echo
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s%s  TW IPv6 DDNS 配置向导%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s" "$C_RESET"
  printf "  直接回车可保留当前值，带 * 为必填项\n"
  echo

  # Cloudflare
  printf "%s%s[ Cloudflare 配置 ]%s\n" "$C_BOLD" "$C_YELLOW" "$C_RESET"; echo

  while true; do
    local cur_token=""; _is_placeholder "$CF_API_TOKEN" || cur_token="$CF_API_TOKEN"
    CF_API_TOKEN="$(_prompt_input "* CF API Token" "$cur_token" "1")"
    _is_placeholder "$CF_API_TOKEN" || break
    warn "CF_API_TOKEN 不能为空，请重新输入"
  done

  while true; do
    local cur_zone=""; _is_placeholder "$CF_ZONE_ID" || cur_zone="$CF_ZONE_ID"
    CF_ZONE_ID="$(_prompt_input "* CF Zone ID" "$cur_zone")"
    _is_placeholder "$CF_ZONE_ID" || break
    warn "CF_ZONE_ID 不能为空，请重新输入"
  done

  while true; do
    local cur_record=""; _is_placeholder "$CF_RECORD_NAME" || cur_record="$CF_RECORD_NAME"
    CF_RECORD_NAME="$(_prompt_input "* DDNS 域名 (如 tw.example.com)" "$cur_record")"
    _is_placeholder "$CF_RECORD_NAME" || break
    warn "CF_RECORD_NAME 不能为空，请重新输入"
  done

  local ttl_in
  ttl_in="$(_prompt_input "  TTL（秒，默认 120）" "$CF_TTL")"
  [[ "$ttl_in" =~ ^[0-9]+$ ]] && CF_TTL="$ttl_in"

  local proxied_in
  proxied_in="$(_prompt_input "  CF 代理（true/false，默认 false）" "$CF_PROXIED")"
  [[ "$proxied_in" == "true" || "$proxied_in" == "false" ]] && CF_PROXIED="$proxied_in"

  echo

  # Telegram
  printf "%s%s[ Telegram 通知（选填，直接回车跳过）]%s\n" "$C_BOLD" "$C_YELLOW" "$C_RESET"; echo

  local tg_token_cur="" tg_chat_cur=""
  _is_placeholder "$TG_BOT_TOKEN" || tg_token_cur="$TG_BOT_TOKEN"
  _is_placeholder "$TG_CHAT_ID"   || tg_chat_cur="$TG_CHAT_ID"

  local tg_in
  tg_in="$(_prompt_input "  TG Bot Token" "$tg_token_cur" "1")"
  [[ -n "$tg_in" ]] && TG_BOT_TOKEN="$tg_in"
  tg_in="$(_prompt_input "  TG Chat ID" "$tg_chat_cur")"
  [[ -n "$tg_in" ]] && TG_CHAT_ID="$tg_in"

  echo

  # 高级选项
  printf "%s%s[ 高级选项（直接回车使用默认值）]%s\n" "$C_BOLD" "$C_YELLOW" "$C_RESET"; echo

  local tz_in
  tz_in="$(_prompt_input "  时区（默认 Asia/Shanghai）" "$DISPLAY_TZ")"
  [[ -n "$tz_in" ]] && DISPLAY_TZ="$tz_in"

  local interval_in
  interval_in="$(_prompt_input "  定时间隔（分钟，默认 5）" "$TIMER_INTERVAL_MINUTES")"
  [[ "$interval_in" =~ ^[0-9]+$ ]] && TIMER_INTERVAL_MINUTES="$interval_in"

  local uuid_in
  uuid_in="$(_prompt_input "  VM UUID（留空自动检测）" "$VM_UUID")"
  VM_UUID="$uuid_in"

  echo

  # 确认
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s%s  请确认以下配置%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line; printf "%s" "$C_RESET"
  print_kv_plain "CF API Token" "$(mask_text "$CF_API_TOKEN")"
  print_kv_plain "CF Zone ID"   "$(mask_text "$CF_ZONE_ID")"
  print_kv_plain "DDNS 域名"       "$CF_RECORD_NAME"
  print_kv_plain "TTL"          "$CF_TTL"
  print_kv_plain "CF 代理"         "$CF_PROXIED"
  print_kv_plain "TG Bot Token" "$( ! _is_placeholder "$TG_BOT_TOKEN" && mask_text "$TG_BOT_TOKEN" || echo "未配置" )"
  print_kv_plain "TG Chat ID"   "$( ! _is_placeholder "$TG_CHAT_ID"   && echo "$TG_CHAT_ID" || echo "未配置" )"
  print_kv_plain "时区"            "$DISPLAY_TZ"
  print_kv_plain "定时间隔"           "${TIMER_INTERVAL_MINUTES} 分钟"
  print_kv_plain "VM UUID"      "$( [[ -n "$VM_UUID" ]] && echo "$VM_UUID" || echo "自动检测" )"
  printf "%s" "$C_MAGENTA"; print_line; printf "%s" "$C_RESET"; echo

  printf "%s以上配置是否正确？[Y/n]: %s" "$C_BOLD" "$C_RESET"
  read -r confirm </dev/tty; confirm="${confirm:-Y}"

  if [[ "${confirm^^}" == "Y" ]]; then
    ensure_state_dir; ensure_log_dir
    save_config; log_ok "配置完成！"; echo
    printf "%s是否立即安装定时任务并执行一次同步？[Y/n]: %s" "$C_BOLD" "$C_RESET"
    read -r do_run </dev/tty; do_run="${do_run:-Y}"
    if [[ "${do_run^^}" == "Y" ]]; then
      install_systemd_timer
      main_run
    fi
  else
    warn "已取消，配置未保存"
  fi
}

maybe_prompt_setup() {
  if _is_placeholder "$CF_API_TOKEN" || \
     _is_placeholder "$CF_ZONE_ID"   || \
     _is_placeholder "$CF_RECORD_NAME"; then
    warn "检测到必填配置项未填写，自动进入配置向导..."
    sleep 1
    run_setup
    exit 0
  fi
}

############################
# 卸载
############################

run_uninstall() {
  clear; echo
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s%s  TW IPv6 DDNS 完整卸载%s\n" "$C_BOLD" "$C_RED" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line; printf "%s" "$C_RESET"; echo
  printf "  将要删除以下内容：\n"
  print_kv "systemd timer"   "${C_YELLOW}twip-cf-ddns.timer${C_RESET}"
  print_kv "systemd service" "${C_YELLOW}twip-cf-ddns.service${C_RESET}"
  print_kv "脚本文件"         "${C_YELLOW}${SCRIPT_INSTALL_PATH}${C_RESET}"
  print_kv "快捷命令"         "${C_YELLOW}/usr/local/bin/tw${C_RESET}"
  print_kv "配置文件"         "${C_YELLOW}${CONFIG_FILE}${C_RESET}"
  print_kv "状态目录"         "${C_YELLOW}${STATE_DIR}${C_RESET}"
  print_kv "日志目录"         "${C_YELLOW}${LOG_DIR}（二次确认）${C_RESET}"
  echo
  printf "%s⚠ 此操作不可逆，确认完整卸载？[y/N]: %s" "$C_RED$C_BOLD" "$C_RESET"
  read -r confirm </dev/tty; confirm="${confirm:-N}"

  if [[ "${confirm^^}" != "Y" ]]; then
    warn "已取消卸载"; return
  fi

  echo
  log_step "停止并禁用 systemd timer / service"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now twip-cf-ddns.timer   2>/dev/null \
      && log_ok "timer 已停止"   || warn "timer 停止失败（可能未安装）"
    systemctl disable --now twip-cf-ddns.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  else
    warn "未找到 systemctl，跳过"
  fi

  log_step "删除 systemd 文件"
  rm -f "$SERVICE_FILE" && log_ok "已删除: $SERVICE_FILE" || true
  rm -f "$TIMER_FILE"   && log_ok "已删除: $TIMER_FILE"   || true

  log_step "删除脚本与快捷命令"
  rm -f "$SCRIPT_INSTALL_PATH" && log_ok "已删除: $SCRIPT_INSTALL_PATH" || true
  rm -f /usr/local/bin/tw      && log_ok "已删除: /usr/local/bin/tw"    || true

  log_step "删除配置文件"
  rm -f "$CONFIG_FILE" && log_ok "已删除: $CONFIG_FILE" || true
  rmdir "$(dirname "$CONFIG_FILE")" 2>/dev/null || true

  log_step "删除状态目录"
  rm -rf "$STATE_DIR" && log_ok "已删除: $STATE_DIR" || true

  log_step "处理日志目录"
  printf "%s是否同时删除日志目录 %s？[y/N]: %s" "$C_BOLD" "$LOG_DIR" "$C_RESET"
  read -r del_log </dev/tty; del_log="${del_log:-N}"
  if [[ "${del_log^^}" == "Y" ]]; then
    rm -rf "$LOG_DIR" && log_ok "已删除: $LOG_DIR" || warn "删除日志目录失败"
  else
    log_info "日志目录已保留: $LOG_DIR"
  fi

  echo
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s%s ✔ 卸载完成%s\n" "$C_BOLD" "$C_GREEN" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line; printf "%s" "$C_RESET"; echo
  exit 0
}

############################
# 控制台
############################

console_show_status() {
  local tw_ipv6="" last_ip="" alert_state="" timer_status="" last_run=""

  [[ -f "$LAST_IP_FILE" ]] && last_ip="$(cat "$LAST_IP_FILE" 2>/dev/null || true)"
  [[ -z "$last_ip" ]] && last_ip="无记录"

  tw_ipv6="$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-f:]+' | grep -v '^fe80' | head -1 || true)"
  [[ -z "$tw_ipv6" ]] && tw_ipv6="未检测到"

  alert_state="$(last_alert_state)"
  case "$alert_state" in
    failure) alert_state="${C_RED}故障${C_RESET}" ;;
    ok)      alert_state="${C_GREEN}正常${C_RESET}" ;;
    *)       alert_state="${C_YELLOW}未知${C_RESET}" ;;
  esac

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet twip-cf-ddns.timer 2>/dev/null; then
      timer_status="${C_GREEN}运行中${C_RESET}"
      last_run="$(systemctl show twip-cf-ddns.service \
        --property=ExecMainStartTimestamp \
        --value 2>/dev/null | grep -v '^$' || echo '未知')"
    else
      timer_status="${C_RED}未运行${C_RESET}"
      last_run="N/A"
    fi
  else
    timer_status="${C_YELLOW}无 systemd${C_RESET}"
    last_run="N/A"
  fi

  echo
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s%s  TW IPv6 DDNS 状态总览%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line; printf "%s" "$C_RESET"
  print_kv "域名"          "${C_BOLD}${CF_RECORD_NAME}${C_RESET}"
  print_kv "定时任务"       "$timer_status"
  print_kv_plain "上次执行" "$last_run"
  print_kv "告警状态"       "$alert_state"
  print_kv "本机全局 IPv6"  "${C_CYAN}${tw_ipv6}${C_RESET}"
  print_kv "上次同步 IP"    "${C_CYAN}${last_ip}${C_RESET}"
  print_kv_plain "配置文件" "$CONFIG_FILE"
  print_kv_plain "日志文件" "$LOG_FILE"
  print_kv_plain "时区"     "$DISPLAY_TZ"
  printf "%s" "$C_MAGENTA"; print_line; printf "%s" "$C_RESET"
}

console_view_log() {
  if [[ ! -f "$LOG_FILE" ]]; then
    warn "日志文件不存在: $LOG_FILE"; return
  fi
  echo
  printf "  %s请输入查看行数 [默认 50]: %s" "$C_BOLD" "$C_RESET"
  read -r lines </dev/tty; lines="${lines:-50}"
  [[ "$lines" =~ ^[0-9]+$ ]] || lines=50
  echo
  printf "%s" "$C_DIM"; print_subline
  printf "%s%s 最近 %d 行日志 %s\n" "$C_BOLD" "$ICON_LOG" "$lines" "$C_RESET"
  printf "%s" "$C_DIM"; print_subline
  printf "%s" "$C_RESET"
  tail -n "$lines" "$LOG_FILE"
  echo
}

console_follow_log() {
  if [[ ! -f "$LOG_FILE" ]]; then
    warn "日志文件不存在: $LOG_FILE"; return
  fi
  printf "%s实时日志（Ctrl+C 退出）%s\n" "$C_CYAN" "$C_RESET"
  tail -f "$LOG_FILE"
}

console_run_now() {
  echo
  printf "%s%s立即执行一次 DDNS 同步...%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  echo
  bash "$SCRIPT_INSTALL_PATH" --run
}

console_timer_menu() {
  echo
  printf "%s--- 定时任务管理 ---%s\n" "$C_BOLD" "$C_RESET"
  printf "  1) 查看 timer 状态\n"
  printf "  2) 启动 timer\n"
  printf "  3) 停止 timer\n"
  printf "  4) 重启 timer\n"
  printf "  0) 返回\n"
  echo
  printf "%s请选择: %s" "$C_BOLD" "$C_RESET"
  read -r sub </dev/tty
  case "$sub" in
    1) systemctl status twip-cf-ddns.timer --no-pager ;;
    2) systemctl enable --now twip-cf-ddns.timer  && log_ok "timer 已启动" ;;
    3) systemctl disable --now twip-cf-ddns.timer && log_ok "timer 已停止" ;;
    4) systemctl restart twip-cf-ddns.timer       && log_ok "timer 已重启" ;;
    0) return ;;
    *) warn "无效选项" ;;
  esac
}

console_clear_alert() {
  mark_success_state
  log_ok "告警状态已手动清除，标记为正常"
}

console_main() {
  exec </dev/tty 2>/dev/null || true
  load_config
  ensure_state_dir
  ensure_log_dir
  touch "$LOG_FILE" 2>/dev/null || true

  while true; do
    clear
    console_show_status
    echo
    printf "%s  请选择操作:%s\n" "$C_BOLD" "$C_RESET"
    printf "  ${C_CYAN}1${C_RESET}) 查看日志（指定行数）\n"
    printf "  ${C_CYAN}2${C_RESET}) 实时跟踪日志\n"
    printf "  ${C_CYAN}3${C_RESET}) 立即执行一次同步\n"
    printf "  ${C_CYAN}4${C_RESET}) 定时任务管理\n"
    printf "  ${C_CYAN}5${C_RESET}) 清除故障告警状态\n"
    printf "  ${C_CYAN}6${C_RESET}) 修改配置\n"
    printf "  ${C_RED}7${C_RESET})  完整卸载\n"
    printf "  ${C_CYAN}0${C_RESET}) 退出\n"
    echo
    printf "%s请输入选项: %s" "$C_BOLD" "$C_RESET"
    read -r choice </dev/tty

    case "$choice" in
      1) console_view_log;    printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      2) console_follow_log ;;
      3) console_run_now;     printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      4) console_timer_menu;  printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      5) console_clear_alert; printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      6) run_setup;           printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      7) run_uninstall ;;
      0) echo "再见"; exit 0 ;;
      *) warn "无效选项，请重新输入"; sleep 1 ;;
    esac
  done
}

############################
# precheck
############################

precheck() {
  load_config
  need_cmd curl
  need_cmd jq
  need_cmd ip
  need_cmd ping

  [[ -n "$CF_API_TOKEN" && "$CF_API_TOKEN" != "填你的CF_API_TOKEN" ]] || {
    err "CF_API_TOKEN 未填写"; exit 1
  }
  [[ -n "$CF_ZONE_ID" && "$CF_ZONE_ID" != "填你的CF_ZONE_ID" ]] || {
    err "CF_ZONE_ID 未填写"; exit 1
  }

  ensure_state_dir
  ensure_log_dir
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE" >/dev/null 2>&1 || true
  rotate_logs_if_needed
  cleanup_old_logs_once_per_day
}

############################
# 单次主逻辑
############################

run_once() {
  local previous_alert_state
  previous_alert_state="$(last_alert_state)"

  log_banner "${ICON_RUN} 开始执行台湾V6 DDNS 同步任务"

  log_step "获取 VM UUID"
  local vm_uuid_detected
  vm_uuid_detected="$(detect_vm_uuid || true)"
  [[ -n "$vm_uuid_detected" ]] || {
    err "无法自动检测 VM UUID，请在配置向导中手动填写 VM_UUID"
    return 1
  }
  log_ok "VM UUID: $(mask_text "$vm_uuid_detected")"

  log_subtitle "${ICON_NET} DynamicV6 查询"
  log_step "请求 DynamicV6 API"

  local payload api_json tw_ipv6
  payload="$(jq -cn --arg vm_uuid "$vm_uuid_detected" '{vm_uuid:$vm_uuid}')"
  api_json="$(api_post_json "$API_URL" "$payload")"

  if ! echo "$api_json" | jq -e . >/dev/null 2>&1; then
    err "DynamicV6 API 返回的不是合法 JSON"
    _log_write "$api_json"; return 1
  fi

  tw_ipv6="$(echo "$api_json" | jq -r --arg wg "$TARGET_WG_INTERFACE" '
    (
      ((.leases // []) | if type=="array" then . else [] end)
      | map(select(.wg_interface == $wg))
      | .[0].ipv6
    ) // empty
  ')"

  [[ -n "$tw_ipv6" && "$tw_ipv6" != "null" ]] || {
    err "API 中未找到 wg_interface=${TARGET_WG_INTERFACE} 的 IPv6"
    _log_write "$api_json"; return 1
  }

  validate_ipv6 "$tw_ipv6" || {
    err "获取到的 IPv6 格式无效: $tw_ipv6"; return 1
  }

  log_ok "获取到 TW IPv6: $(short_ipv6 "$tw_ipv6")"
  test_tw_ipv6_connectivity "$tw_ipv6" || return 1

  local last_local_ip=""
  [[ -f "$LAST_IP_FILE" ]] && last_local_ip="$(cat "$LAST_IP_FILE" 2>/dev/null || true)"

  log_subtitle "${ICON_DNS} Cloudflare 同步"
  log_step "查询 Cloudflare AAAA 记录"

  local cf_query_url cf_query_json cf_success record_count
  cf_query_url="https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?type=AAAA&name=${CF_RECORD_NAME}"
  cf_query_json="$(cf_api GET "$cf_query_url")"

  cf_success="$(echo "$cf_query_json" | jq -r '.success')"
  [[ "$cf_success" == "true" ]] || {
    err "查询 Cloudflare DNS 记录失败"
    _log_write "$cf_query_json"; return 1
  }

  record_count="$(echo "$cf_query_json" | jq -r '.result | length')"

  if [[ "$record_count" -eq 0 ]]; then
    log_step "未找到 AAAA 记录，准备创建"

    local create_data create_json create_success
    create_data="$(jq -cn \
      --arg type "AAAA" \
      --arg name "$CF_RECORD_NAME" \
      --arg content "$tw_ipv6" \
      --argjson proxied "$CF_PROXIED" \
      --argjson ttl "$CF_TTL" \
      '{type:$type,name:$name,content:$content,proxied:$proxied,ttl:$ttl}')"

    create_json="$(cf_api POST \
      "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
      "$create_data")"
    create_success="$(echo "$create_json" | jq -r '.success')"

    [[ "$create_success" == "true" ]] || {
      err "创建 Cloudflare AAAA 记录失败"
      _log_write "$create_json"; return 1
    }

    echo "$tw_ipv6" > "$LAST_IP_FILE"
    chmod 600 "$LAST_IP_FILE" >/dev/null 2>&1 || true
    log_ok "已创建 AAAA: $CF_RECORD_NAME -> $(short_ipv6 "$tw_ipv6")"
    send_tg_success "${last_local_ip:-不存在}" "$tw_ipv6"
    [[ "$previous_alert_state" == "failure" ]] && send_tg_recovery "$tw_ipv6"
    mark_success_state
    log_banner "${ICON_DONE} 本次执行完成：已创建记录"
    return 0
  fi

  local record_id cf_current_ip
  record_id="$(echo "$cf_query_json" | jq -r '.result[0].id')"
  cf_current_ip="$(echo "$cf_query_json" | jq -r '.result[0].content')"

  log_ok "Cloudflare 当前 AAAA: $(short_ipv6 "$cf_current_ip")"

  if [[ "$cf_current_ip" == "$tw_ipv6" ]]; then
    echo "$tw_ipv6" > "$LAST_IP_FILE"
    chmod 600 "$LAST_IP_FILE" >/dev/null 2>&1 || true
    log_ok "IPv6 未变化，无需更新"
    [[ "$previous_alert_state" == "failure" ]] && send_tg_recovery "$tw_ipv6"
    mark_success_state
    log_banner "${ICON_DONE} 本次执行完成：无需更新"
    return 0
  fi

  log_step "检测到 IPv6 变化，准备更新"
  log_info "旧值: $(short_ipv6 "$cf_current_ip")"
  log_info "新值: $(short_ipv6 "$tw_ipv6")"

  local update_data update_json update_success
  update_data="$(jq -cn \
    --arg type "AAAA" \
    --arg name "$CF_RECORD_NAME" \
    --arg content "$tw_ipv6" \
    --argjson proxied "$CF_PROXIED" \
    --argjson ttl "$CF_TTL" \
    '{type:$type,name:$name,content:$content,proxied:$proxied,ttl:$ttl}')"

  update_json="$(cf_api PUT \
    "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${record_id}" \
    "$update_data")"
  update_success="$(echo "$update_json" | jq -r '.success')"

  [[ "$update_success" == "true" ]] || {
    err "更新 Cloudflare AAAA 记录失败"
    _log_write "$update_json"; return 1
  }

  echo "$tw_ipv6" > "$LAST_IP_FILE"
  chmod 600 "$LAST_IP_FILE" >/dev/null 2>&1 || true
  log_ok "已更新 AAAA: $CF_RECORD_NAME -> $(short_ipv6 "$tw_ipv6")"
  send_tg_success "$cf_current_ip" "$tw_ipv6"
  [[ "$previous_alert_state" == "failure" ]] && send_tg_recovery "$tw_ipv6"
  mark_success_state
  log_banner "${ICON_DONE} 本次执行完成：已更新记录"
  return 0
}

############################
# 主入口
############################

main_run() {
  log_banner "${ICON_RUN} 任务启动"

  local err1="" err2=""

  if run_once; then
    log_ok "任务执行成功"
    exit 0
  else
    err1="第一次执行失败，时间：$(TZ="${DISPLAY_TZ}" date '+%F %T %Z')"
    warn "$err1，3 秒后重试"
    sleep 3
  fi

  if run_once; then
    log_ok "第二次重试成功"
    exit 0
  else
    err2="第二次执行失败，时间：$(TZ="${DISPLAY_TZ}" date '+%F %T %Z')"
    err "$err2"
  fi

  if [[ "$(last_alert_state)" != "failure" ]]; then
    send_tg_failure "${err1}
${err2}
请登录服务器手动排查 API / IPv6 / Cloudflare / 路由状态。"
  fi

  mark_failure_alert_sent
  err "任务执行失败，已标记故障状态"
  exit 1
}

############################
# usage
############################

usage() {
  cat <<EOT
Usage:
  $0                        首次运行：配置检测 -> 安装 timer -> 执行同步
  $0 --run                  仅执行一次同步
  $0 --install              仅安装/启用 systemd 定时任务
  $0 setup                  运行配置向导
  $0 console                打开交互控制台（同 tw 命令）
  $0 uninstall              完整卸载
EOT
}

############################
# 入口分发
############################

case "${1:-}" in
  --run)
    precheck
    maybe_prompt_setup
    main_run
    ;;
  --install)
    precheck
    maybe_prompt_setup
    install_systemd_timer
    ;;
  "")
    load_config
    maybe_prompt_setup
    precheck
    install_systemd_timer
    main_run
    ;;
  setup|--setup)
    ensure_log_dir
    ensure_state_dir
    load_config
    run_setup
    ;;
  console|--console)
    console_main
    ;;
  uninstall|--uninstall)
    load_config
    run_uninstall
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
