#!/usr/bin/env bash
set -euo pipefail

############################################################
# Aether DynamicV6 -> sing-box IPv6 同步脚本
# 功能：
# 1. 根据实例请求 Aether API 获取 IPv6
# 2. 按 tag 精准替换 sing-box 配置中的 inet6_bind_address
# 3. 仅当 IP 变化时写入配置并重启 sing-box
# 4. 重启失败自动回滚旧配置并告警
# 5. Telegram 通知
# 6. setup / console / uninstall / timer
############################################################

############################
# 基础路径
############################

SERVICE_NAME="aether-singbox-sync"
SCRIPT_INSTALL_PATH="/usr/local/bin/${SERVICE_NAME}.sh"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"

CONFIG_DIR="/etc/${SERVICE_NAME}"
CONFIG_FILE="${CONFIG_DIR}/config"

STATE_DIR="/var/lib/${SERVICE_NAME}"
LOG_DIR="/var/log/${SERVICE_NAME}"
LOG_FILE="${LOG_DIR}/${SERVICE_NAME}.log"
LAST_IP_FILE="${STATE_DIR}/last_ipv6"
LOG_CLEANUP_STAMP_FILE="${STATE_DIR}/last_log_cleanup"

SINGBOX_CONFIG="/etc/sing-box/config.json"
SINGBOX_SERVICE="sing-box"
BACKUP_DIR="/etc/sing-box/backup"

############################
# 默认配置
############################

API_URL="https://billing.aethercloud.io/api/dynamicv6/vm/status"

VM_UUID=""
INSTANCE_PROFILE="Hong-Kong"

TG_BOT_TOKEN=""
TG_CHAT_ID=""

DISPLAY_TZ="Asia/Shanghai"
TIMER_INTERVAL_MINUTES=5

CURL_CONNECT_TIMEOUT=6
CURL_MAX_TIME=20
CURL_RETRY=2

VERBOSE=1
ENABLE_COLOR=1

LOG_RETENTION_DAYS=1
LOG_CLEANUP_INTERVAL_SECONDS=86400

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
ICON_SYNC="🔄"
ICON_BOX="📦"
ICON_TG="📨"
ICON_DONE="🎉"

UI_WIDTH=72

############################
# 基础函数
############################

timestamp() {
  TZ="${DISPLAY_TZ}" date '+%F %T %Z'
}

_print() {
  local color="$1" icon="$2" tag="$3" msg="$4"
  printf "%s%s %s %-6s%s %s\n" "$color" "$icon" "$(timestamp)" "$tag" "$C_RESET" "$msg"
}

_log_write() {
  mkdir -p "$LOG_DIR"
  echo "[$(timestamp)] $1" >> "$LOG_FILE"
}

log_info() {
  local msg="$*"
  [[ "$VERBOSE" == "1" ]] && _print "$C_BLUE" "$ICON_INFO" "[INFO]" "$msg"
  _log_write "[INFO ] $msg"
}

log_step() {
  local msg="$*"
  [[ "$VERBOSE" == "1" ]] && _print "$C_CYAN" "$ICON_STEP" "[STEP]" "$msg"
  _log_write "[STEP ] $msg"
}

log_ok() {
  local msg="$*"
  [[ "$VERBOSE" == "1" ]] && _print "$C_GREEN" "$ICON_OK" "[ OK ]" "$msg"
  _log_write "[ OK  ] $msg"
}

warn() {
  local msg="$*"
  _print "$C_YELLOW" "$ICON_WARN" "[WARN]" "$msg" >&2
  _log_write "[WARN ] $msg"
}

err() {
  local msg="$*"
  _print "$C_RED" "$ICON_ERR" "[ERR ]" "$msg" >&2
  _log_write "[ERROR] $msg"
}

print_line() {
  printf '%*s\n' "$UI_WIDTH" '' | tr ' ' '='
}

print_subline() {
  printf '%*s\n' "$UI_WIDTH" '' | tr ' ' '-'
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "缺少依赖命令: $1"
    exit 1
  }
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" "$BACKUP_DIR"
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE" >/dev/null 2>&1 || true
}

cleanup_logs_daily() {
  local now last_cleanup=0
  now="$(date +%s)"

  [[ -f "$LOG_CLEANUP_STAMP_FILE" ]] && last_cleanup="$(cat "$LOG_CLEANUP_STAMP_FILE" 2>/dev/null || echo 0)"
  [[ "$last_cleanup" =~ ^[0-9]+$ ]] || last_cleanup=0

  (( now - last_cleanup < LOG_CLEANUP_INTERVAL_SECONDS )) && return 0

  if [[ -f "$LOG_FILE" ]]; then
    : > "$LOG_FILE"
    chmod 600 "$LOG_FILE" >/dev/null 2>&1 || true
  fi

  find "$LOG_DIR" -type f -name '*.log' -mtime +"$LOG_RETENTION_DAYS" -delete 2>/dev/null || true

  echo "$now" > "$LOG_CLEANUP_STAMP_FILE"
  chmod 600 "$LOG_CLEANUP_STAMP_FILE" >/dev/null 2>&1 || true
}

mask_text() {
  local s="${1:-}"
  local len=${#s}
  (( len <= 8 )) && { echo "****"; return; }
  echo "${s:0:4}****${s: -4}"
}

_is_placeholder() {
  [[ -z "${1:-}" || "$1" == 填你的* ]]
}

############################
# 配置
############################

load_config() {
  [[ -f "$CONFIG_FILE" ]] || return 0
  # shellcheck disable=SC1090
  source "$CONFIG_FILE" || true
}

save_config() {
  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_FILE" <<EOF
# ${SERVICE_NAME} 配置
# 生成时间: $(timestamp)

API_URL="${API_URL}"
VM_UUID="${VM_UUID}"
INSTANCE_PROFILE="${INSTANCE_PROFILE}"

TG_BOT_TOKEN="${TG_BOT_TOKEN}"
TG_CHAT_ID="${TG_CHAT_ID}"

DISPLAY_TZ="${DISPLAY_TZ}"
TIMER_INTERVAL_MINUTES="${TIMER_INTERVAL_MINUTES}"

SINGBOX_CONFIG="${SINGBOX_CONFIG}"
SINGBOX_SERVICE="${SINGBOX_SERVICE}"
EOF
  chmod 600 "$CONFIG_FILE"
  log_ok "配置已保存: $CONFIG_FILE"
}

_prompt_input() {
  local prompt="$1"
  local current="${2:-}"
  local secret="${3:-0}"
  local input=""

  if [[ "$secret" == "1" ]]; then
    printf "  %s%s%s" "$C_BOLD" "$prompt" "$C_RESET" >/dev/tty
    [[ -n "$current" ]] && printf " %s[当前: %s]%s" "$C_DIM" "$(mask_text "$current")" "$C_RESET" >/dev/tty
    printf ": " >/dev/tty
    read -rs input </dev/tty || true
    echo >/dev/tty
  else
    printf "  %s%s%s" "$C_BOLD" "$prompt" "$C_RESET" >/dev/tty
    [[ -n "$current" ]] && printf " %s[当前: %s]%s" "$C_DIM" "$current" "$C_RESET" >/dev/tty
    printf ": " >/dev/tty
    read -r input </dev/tty || true
  fi

  if [[ -z "$input" && -n "$current" ]]; then
    printf '%s\n' "$current"
  else
    printf '%s\n' "$input"
  fi
}

instance_label() {
  case "$INSTANCE_PROFILE" in
    "Hong-Kong") echo "Hong-Kong" ;;
    "Dallas") echo "Dallas" ;;
    "Manassas") echo "Manassas" ;;
    "Los-Angeles") echo "Los-Angeles" ;;
    "New-Jersey") echo "New-Jersey" ;;
    "Los-Angeles(CO)") echo "Los-Angeles(CO)" ;;
    *) echo "$INSTANCE_PROFILE" ;;
  esac
}

get_target_wg_interface() {
  case "$INSTANCE_PROFILE" in
    "Hong-Kong") echo "tw" ;;
    "Dallas"|"Manassas"|"Los-Angeles"|"New-Jersey"|"Los-Angeles(CO)") echo "wg0" ;;
    *) echo "tw" ;;
  esac
}

get_target_tag() {
  case "$INSTANCE_PROFILE" in
    "Hong-Kong") echo "twv6" ;;
    "Dallas"|"Manassas"|"Los-Angeles"|"New-Jersey"|"Los-Angeles(CO)") echo "attv6" ;;
    *) echo "twv6" ;;
  esac
}

detect_vm_uuid() {
  if [[ -n "${VM_UUID:-}" ]]; then
    echo "$VM_UUID"
    return 0
  fi

  if [[ -r /sys/class/dmi/id/product_uuid ]]; then
    tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid | tr -d '[:space:]'
    return 0
  fi

  if command -v dmidecode >/dev/null 2>&1; then
    local u
    u="$(dmidecode -s system-uuid 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ -n "$u" && "$u" != "notsettable" ]]; then
      echo "$u"
      return 0
    fi
  fi

  return 1
}

run_setup() {
  exec </dev/tty 2>/dev/null || true
  clear 2>/dev/null || true

  echo
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s%s  Aether sing-box IPv6 同步配置向导%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s" "$C_RESET"
  echo "  直接回车可保留当前值"
  echo

  printf "%s%s[ 实例选择 ]%s\n" "$C_BOLD" "$C_YELLOW" "$C_RESET"
  echo "  1. Hong-Kong"
  echo "  2. Dallas"
  echo "  3. Manassas"
  echo "  4. Los-Angeles"
  echo "  5. New-Jersey"
  echo "  6. Los-Angeles(CO)"
  echo

  local instance_default instance_in
  case "$INSTANCE_PROFILE" in
    "Hong-Kong") instance_default="1" ;;
    "Dallas") instance_default="2" ;;
    "Manassas") instance_default="3" ;;
    "Los-Angeles") instance_default="4" ;;
    "New-Jersey") instance_default="5" ;;
    "Los-Angeles(CO)") instance_default="6" ;;
    *) instance_default="1" ;;
  esac

  instance_in="$(_prompt_input "请输入选项" "$instance_default")"
  case "$instance_in" in
    ""|1) INSTANCE_PROFILE="Hong-Kong" ;;
    2) INSTANCE_PROFILE="Dallas" ;;
    3) INSTANCE_PROFILE="Manassas" ;;
    4) INSTANCE_PROFILE="Los-Angeles" ;;
    5) INSTANCE_PROFILE="New-Jersey" ;;
    6) INSTANCE_PROFILE="Los-Angeles(CO)" ;;
    "Hong-Kong"|"Dallas"|"Manassas"|"Los-Angeles"|"New-Jersey"|"Los-Angeles(CO)") INSTANCE_PROFILE="$instance_in" ;;
    *) warn "输入无效，保留当前实例: $INSTANCE_PROFILE" ;;
  esac

  echo
  printf "%s%s[ Telegram 通知 ]%s\n" "$C_BOLD" "$C_YELLOW" "$C_RESET"
  echo

  TG_BOT_TOKEN="$(_prompt_input "TG Bot Token（留空可跳过）" "${TG_BOT_TOKEN:-}" "1")"
  TG_CHAT_ID="$(_prompt_input "TG Chat ID（留空可跳过）" "${TG_CHAT_ID:-}")"

  echo
  printf "%s%s[ 高级选项 ]%s\n" "$C_BOLD" "$C_YELLOW" "$C_RESET"
  echo

  local tz_in interval_in uuid_in config_in service_in
  tz_in="$(_prompt_input "时区" "$DISPLAY_TZ")"
  [[ -n "$tz_in" ]] && DISPLAY_TZ="$tz_in"

  interval_in="$(_prompt_input "定时间隔（分钟）" "$TIMER_INTERVAL_MINUTES")"
  [[ "$interval_in" =~ ^[0-9]+$ ]] && TIMER_INTERVAL_MINUTES="$interval_in"

  uuid_in="$(_prompt_input "VM UUID（留空自动检测）" "$VM_UUID")"
  VM_UUID="$uuid_in"

  config_in="$(_prompt_input "sing-box 配置路径" "$SINGBOX_CONFIG")"
  [[ -n "$config_in" ]] && SINGBOX_CONFIG="$config_in"

  service_in="$(_prompt_input "sing-box systemd 服务名" "$SINGBOX_SERVICE")"
  [[ -n "$service_in" ]] && SINGBOX_SERVICE="$service_in"

  echo
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s%s  配置确认%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s" "$C_RESET"
  printf "  实例名称         : %s\n" "$(instance_label)"
  printf "  wg_interface     : %s\n" "$(get_target_wg_interface)"
  printf "  sing-box tag     : %s\n" "$(get_target_tag)"
  printf "  TG Bot Token     : %s\n" "$( ! _is_placeholder "$TG_BOT_TOKEN" && mask_text "$TG_BOT_TOKEN" || echo "未配置" )"
  printf "  TG Chat ID       : %s\n" "$( ! _is_placeholder "$TG_CHAT_ID" && echo "$TG_CHAT_ID" || echo "未配置" )"
  printf "  时区             : %s\n" "$DISPLAY_TZ"
  printf "  定时间隔         : %s 分钟\n" "$TIMER_INTERVAL_MINUTES"
  printf "  VM UUID          : %s\n" "$( [[ -n "$VM_UUID" ]] && echo "$VM_UUID" || echo "自动检测" )"
  printf "  sing-box 配置    : %s\n" "$SINGBOX_CONFIG"
  printf "  sing-box 服务    : %s\n" "$SINGBOX_SERVICE"

  echo
  printf "%s以上配置是否保存？[Y/n]: %s" "$C_BOLD" "$C_RESET"
  local confirm
  read -r confirm </dev/tty
  confirm="${confirm:-Y}"

  if [[ "${confirm^^}" == "Y" ]]; then
    ensure_dirs
    save_config
    echo
    printf "%s是否立即安装定时任务并执行一次同步？[Y/n]: %s" "$C_BOLD" "$C_RESET"
    local do_run
    read -r do_run </dev/tty
    do_run="${do_run:-Y}"
    if [[ "${do_run^^}" == "Y" ]]; then
      install_systemd_timer
      main_run
    fi
  else
    warn "已取消保存"
  fi
}

############################
# TG
############################

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
  local instance="$1"
  local tag="$2"
  local old_ip="$3"
  local new_ip="$4"
  local now_sh

  now_sh="$(TZ="${DISPLAY_TZ}" date '+%Y-%m-%d %H:%M:%S %Z')"

  send_tg_message "✅ *sing-box IPv6 更新成功*

━━━━━━━━━━━━━━
*实例*：\`${instance}\`
*Tag*：\`${tag}\`
*时间*：\`${now_sh}\`

*变更详情*
• 旧 IPv6：\`${old_ip:-未设置}\`
• 新 IPv6：\`${new_ip}\`

*执行结果*
• 配置已写入
• sing-box 已重启成功
━━━━━━━━━━━━━━"
}

send_tg_failure() {
  local title="$1"
  local detail="$2"
  local instance tag now_sh

  instance="$(instance_label)"
  tag="$(get_target_tag)"
  now_sh="$(TZ="${DISPLAY_TZ}" date '+%Y-%m-%d %H:%M:%S %Z')"

  send_tg_message "❌ *${title}*

━━━━━━━━━━━━━━
*实例*：\`${instance}\`
*Tag*：\`${tag}\`
*时间*：\`${now_sh}\`

*故障详情*
\`\`\`
${detail}
\`\`\`
━━━━━━━━━━━━━━"
}

############################
# 核心逻辑
############################

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

validate_ipv6() {
  local ip="$1"
  [[ -n "$ip" && "$ip" != "null" && "$ip" == *:* ]]
}

get_api_ipv6() {
  local vm_uuid="$1"
  local wg_interface="$2"
  local payload api_json target_ipv6

  payload="$(jq -cn --arg vm_uuid "$vm_uuid" '{vm_uuid:$vm_uuid}')"
  api_json="$(api_post_json "$API_URL" "$payload")"

  target_ipv6="$(echo "$api_json" | jq -r --arg wg "$wg_interface" '
    (
      [
        (.lease // empty),
        ((.leases // [])[]?)
      ]
      | map(select(.wg_interface == $wg))
      | .[0].ipv6
    ) // empty
  ')"

  echo "$target_ipv6"
}

tag_exists() {
  local tag="$1"
  jq -e --arg tag "$tag" '.outbounds[]? | select(.tag == $tag)' "$SINGBOX_CONFIG" >/dev/null 2>&1
}

get_current_bind_ip() {
  local tag="$1"
  jq -r --arg tag "$tag" '
    .outbounds[]? | select(.tag == $tag) | .inet6_bind_address // empty
  ' "$SINGBOX_CONFIG" | head -n1
}

set_bind_ip_with_backup() {
  local tag="$1"
  local ip="$2"
  local backup_file="$3"
  local tmp_file

  tmp_file="$(mktemp)"
  cp -a "$SINGBOX_CONFIG" "$backup_file"

  jq --arg tag "$tag" --arg ip "$ip" '
    .outbounds |= map(
      if .tag == $tag then
        .inet6_bind_address = $ip
      else
        .
      end
    )
  ' "$SINGBOX_CONFIG" > "$tmp_file"

  mv "$tmp_file" "$SINGBOX_CONFIG"
  chmod 600 "$SINGBOX_CONFIG" >/dev/null 2>&1 || true
}

restore_backup_config() {
  local backup_file="$1"
  [[ -f "$backup_file" ]] || return 1
  cp -a "$backup_file" "$SINGBOX_CONFIG"
  chmod 600 "$SINGBOX_CONFIG" >/dev/null 2>&1 || true
}

restart_singbox() {
  systemctl restart "$SINGBOX_SERVICE"
  systemctl is-active --quiet "$SINGBOX_SERVICE"
}

precheck() {
  load_config
  ensure_dirs
  cleanup_logs_daily
  need_cmd curl
  need_cmd jq
  need_cmd systemctl

  [[ -f "$SINGBOX_CONFIG" ]] || {
    err "sing-box 配置文件不存在: $SINGBOX_CONFIG"
    exit 1
  }
}

run_once() {
  local vm_uuid wg_interface target_tag target_ipv6 current_ip backup_file
  local restart_error_detail rollback_ok=0

  log_step "获取 VM UUID"
  vm_uuid="$(detect_vm_uuid || true)"
  [[ -n "$vm_uuid" ]] || {
    err "无法检测 VM UUID，请在配置中填写 VM_UUID"
    return 1
  }
  log_ok "VM UUID: $(mask_text "$vm_uuid")"

  wg_interface="$(get_target_wg_interface)"
  target_tag="$(get_target_tag)"

  log_info "实例: $(instance_label)"
  log_info "目标 wg_interface: $wg_interface"
  log_info "目标 tag: $target_tag"

  log_step "请求 Aether DynamicV6 API"
  target_ipv6="$(get_api_ipv6 "$vm_uuid" "$wg_interface")"

  validate_ipv6 "$target_ipv6" || {
    err "未获取到有效 IPv6: $target_ipv6"
    return 1
  }
  log_ok "目标 IPv6: $target_ipv6"

  tag_exists "$target_tag" || {
    err "sing-box 配置中未找到 tag=${target_tag}"
    return 1
  }

  current_ip="$(get_current_bind_ip "$target_tag")"
  [[ -n "$current_ip" ]] && log_info "当前配置 IPv6: $current_ip" || warn "当前 inet6_bind_address 为空，将直接写入"

  if [[ "$current_ip" == "$target_ipv6" ]]; then
    echo "$target_ipv6" > "$LAST_IP_FILE"
    chmod 600 "$LAST_IP_FILE" >/dev/null 2>&1 || true
    log_ok "IPv6 未变化，无需更新"
    return 0
  fi

  backup_file="${BACKUP_DIR}/config.json.$(date +%Y%m%d-%H%M%S).bak"

  log_step "检测到 IP 变化，准备写入 sing-box 配置"
  log_info "旧值: ${current_ip:-未设置}"
  log_info "新值: $target_ipv6"

  set_bind_ip_with_backup "$target_tag" "$target_ipv6" "$backup_file"
  log_ok "已更新配置: tag=${target_tag} -> $target_ipv6"

  log_step "重启 sing-box"
  if restart_singbox; then
    echo "$target_ipv6" > "$LAST_IP_FILE"
    chmod 600 "$LAST_IP_FILE" >/dev/null 2>&1 || true
    log_ok "sing-box 重启成功"
    send_tg_success "$(instance_label)" "$target_tag" "$current_ip" "$target_ipv6"
    return 0
  fi

  restart_error_detail="$(systemctl status "$SINGBOX_SERVICE" --no-pager -l 2>/dev/null | tail -n 20 || true)"
  err "sing-box 重启失败，开始自动回滚旧配置"

  if restore_backup_config "$backup_file"; then
    if systemctl restart "$SINGBOX_SERVICE" >/dev/null 2>&1; then
      rollback_ok=1
      log_ok "旧配置已恢复，sing-box 已重新启动"
    else
      err "旧配置恢复后，sing-box 仍然启动失败"
    fi
  else
    err "回滚失败，备份文件不存在: $backup_file"
  fi

  if [[ "$rollback_ok" -eq 1 ]]; then
    send_tg_failure \
      "sing-box 重启失败，已自动回滚" \
      "检测到 IPv6 变化并写入新配置后，sing-box 重启失败。
旧 IP：${current_ip:-未设置}
新 IP：${target_ipv6}
回滚结果：已恢复旧配置并重新启动成功

最近服务状态：
${restart_error_detail}"
  else
    send_tg_failure \
      "sing-box 重启失败，回滚也失败" \
      "检测到 IPv6 变化并写入新配置后，sing-box 重启失败。
旧 IP：${current_ip:-未设置}
新 IP：${target_ipv6}
回滚结果：失败，请立即人工处理

最近服务状态：
${restart_error_detail}"
  fi

  return 1
}

main_run() {
  log_step "${ICON_SYNC} 开始执行同步任务"

  local err1="" err2=""

  if run_once; then
    log_ok "${ICON_DONE} 任务执行成功"
    exit 0
  else
    err1="第一次执行失败：$(timestamp)"
    warn "$err1，3 秒后重试"
    sleep 3
  fi

  if run_once; then
    log_ok "${ICON_DONE} 第二次重试成功"
    exit 0
  else
    err2="第二次执行失败：$(timestamp)"
    err "$err2"
  fi

  send_tg_failure \
    "sing-box IPv6 同步连续失败" \
    "${err1}
${err2}
请检查 API / sing-box 配置 / 服务状态。"
  exit 1
}

############################
# systemd
############################

install_systemd_timer() {
  if [[ "$EUID" -ne 0 ]]; then
    warn "安装 systemd timer 需要 root"
    return 1
  fi

  local interval="${TIMER_INTERVAL_MINUTES}"
  [[ "$interval" =~ ^[0-9]+$ ]] || interval=5
  (( interval > 0 )) || interval=5

  mkdir -p "$(dirname "$SCRIPT_INSTALL_PATH")"

  if [[ "$(readlink -f "$0" 2>/dev/null || echo "$0")" != "$SCRIPT_INSTALL_PATH" ]]; then
    cp -f "$0" "$SCRIPT_INSTALL_PATH"
    chmod +x "$SCRIPT_INSTALL_PATH"
    log_ok "脚本已安装到: $SCRIPT_INSTALL_PATH"
  fi

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Aether sing-box IPv6 Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_INSTALL_PATH} --run
EOF

  cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run Aether sing-box IPv6 Sync every ${interval} minutes

[Timer]
OnBootSec=1min
OnCalendar=*:0/${interval}
Unit=${SERVICE_NAME}.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.timer" >/dev/null 2>&1
  log_ok "systemd timer 已启用，间隔: ${interval} 分钟"

  cat > /usr/local/bin/sbip <<EOF
#!/usr/bin/env bash
exec ${SCRIPT_INSTALL_PATH} console
EOF
  chmod +x /usr/local/bin/sbip
  log_ok "快捷命令已安装: sbip"
}

############################
# 控制台
############################

console_show_status() {
  local current_config_ip timer_status last_run instance_show target_tag last_ip

  instance_show="$(instance_label)"
  target_tag="$(get_target_tag)"
  current_config_ip="$(get_current_bind_ip "$target_tag" 2>/dev/null || true)"
  [[ -z "$current_config_ip" ]] && current_config_ip="未读取到"

  [[ -f "$LAST_IP_FILE" ]] && last_ip="$(cat "$LAST_IP_FILE" 2>/dev/null || true)"
  [[ -z "${last_ip:-}" ]] && last_ip="无记录"

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "${SERVICE_NAME}.timer" 2>/dev/null; then
      timer_status="${C_GREEN}运行中${C_RESET}"
      last_run="$(systemctl show "${SERVICE_NAME}.service" --property=ExecMainStartTimestamp --value 2>/dev/null | grep -v '^$' || echo '未知')"
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
  printf "%s%s  Aether sing-box IPv6 同步状态%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s" "$C_RESET"
  printf "  实例名称         : %s\n" "$instance_show"
  printf "  wg_interface     : %s\n" "$(get_target_wg_interface)"
  printf "  目标 tag         : %s\n" "$target_tag"
  printf "  定时任务         : %b\n" "$timer_status"
  printf "  上次执行         : %s\n" "$last_run"
  printf "  配置当前 IP      : %s\n" "$current_config_ip"
  printf "  上次同步 IP      : %s\n" "$last_ip"
  printf "  配置文件         : %s\n" "$CONFIG_FILE"
  printf "  sing-box 配置    : %s\n" "$SINGBOX_CONFIG"
  printf "  日志文件         : %s\n" "$LOG_FILE"
  printf "  备份目录         : %s\n" "$BACKUP_DIR"
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s" "$C_RESET"
}

console_view_log() {
  [[ -f "$LOG_FILE" ]] || {
    warn "日志文件不存在"
    return
  }

  echo
  printf "  %s请输入查看行数 [默认 50]: %s" "$C_BOLD" "$C_RESET"
  local lines
  read -r lines </dev/tty
  lines="${lines:-50}"
  [[ "$lines" =~ ^[0-9]+$ ]] || lines=50

  echo
  printf "%s" "$C_DIM"; print_subline
  printf "%s最近 %s 行日志%s\n" "$C_BOLD" "$lines" "$C_RESET"
  printf "%s" "$C_DIM"; print_subline
  printf "%s" "$C_RESET"
  tail -n "$lines" "$LOG_FILE"
  echo
}

console_follow_log() {
  [[ -f "$LOG_FILE" ]] || {
    warn "日志文件不存在"
    return
  }
  printf "%s实时日志（Ctrl+C 退出）%s\n" "$C_CYAN" "$C_RESET"
  tail -f "$LOG_FILE"
}

console_run_now() {
  echo
  printf "%s立即执行一次同步...%s\n" "$C_CYAN" "$C_RESET"
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

  local sub
  read -r sub </dev/tty
  case "$sub" in
    1) systemctl status "${SERVICE_NAME}.timer" --no-pager ;;
    2) systemctl enable --now "${SERVICE_NAME}.timer" && log_ok "timer 已启动" ;;
    3) systemctl disable --now "${SERVICE_NAME}.timer" && log_ok "timer 已停止" ;;
    4) systemctl restart "${SERVICE_NAME}.timer" && log_ok "timer 已重启" ;;
    0) return ;;
    *) warn "无效选项" ;;
  esac
}

run_uninstall() {
  exec </dev/tty 2>/dev/null || true
  clear 2>/dev/null || true

  echo
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s%s  Aether sing-box IPv6 同步卸载%s\n" "$C_BOLD" "$C_RED" "$C_RESET"
  printf "%s" "$C_MAGENTA"; print_line
  printf "%s" "$C_RESET"
  echo
  echo "  将删除以下内容："
  echo "  - ${SERVICE_FILE}"
  echo "  - ${TIMER_FILE}"
  echo "  - ${SCRIPT_INSTALL_PATH}"
  echo "  - /usr/local/bin/sbip"
  echo "  - ${CONFIG_FILE}"
  echo "  - ${STATE_DIR}"
  echo "  - ${LOG_DIR}"
  echo
  printf "%s确认卸载？[y/N]: %s" "$C_BOLD" "$C_RESET"

  local confirm
  read -r confirm </dev/tty
  confirm="${confirm:-N}"

  if [[ "${confirm^^}" != "Y" ]]; then
    warn "已取消卸载"
    return
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "${SERVICE_NAME}.timer" 2>/dev/null || true
    systemctl disable --now "${SERVICE_NAME}.service" 2>/dev/null || true
  fi

  rm -f "$SERVICE_FILE" "$TIMER_FILE" "$SCRIPT_INSTALL_PATH" /usr/local/bin/sbip
  rm -f "$CONFIG_FILE"
  rm -rf "$STATE_DIR" "$LOG_DIR"

  systemctl daemon-reload 2>/dev/null || true
  log_ok "卸载完成"
  exit 0
}

console_main() {
  exec </dev/tty 2>/dev/null || true
  load_config
  ensure_dirs
  cleanup_logs_daily

  while true; do
    clear 2>/dev/null || true
    console_show_status
    echo
    printf "%s  请选择操作:%s\n" "$C_BOLD" "$C_RESET"
    printf "  ${C_CYAN}1${C_RESET}) 查看日志\n"
    printf "  ${C_CYAN}2${C_RESET}) 实时日志\n"
    printf "  ${C_CYAN}3${C_RESET}) 立即执行同步\n"
    printf "  ${C_CYAN}4${C_RESET}) 定时任务管理\n"
    printf "  ${C_CYAN}5${C_RESET}) 修改配置\n"
    printf "  ${C_RED}6${C_RESET}) 卸载脚本\n"
    printf "  ${C_CYAN}0${C_RESET}) 退出\n"
    echo
    printf "%s请输入选项: %s" "$C_BOLD" "$C_RESET"

    local choice
    read -r choice </dev/tty
    case "$choice" in
      1) console_view_log; printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      2) console_follow_log ;;
      3) console_run_now; printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      4) console_timer_menu; printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      5) run_setup; printf "\n%s按 Enter 继续...%s" "$C_DIM" "$C_RESET"; read -r _ </dev/tty ;;
      6) run_uninstall ;;
      0) echo "再见"; exit 0 ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

############################
# usage
############################

usage() {
  cat <<EOF
Usage:
  $0                首次运行：配置 -> 安装 timer -> 执行同步
  $0 --run          仅执行一次同步
  $0 --install      安装/启用 systemd 定时任务
  $0 setup          打开配置向导
  $0 console        打开控制台
  $0 uninstall      卸载脚本
EOF
}

############################
# 入口
############################

case "${1:-}" in
  "")
    load_config
    if [[ ! -f "$CONFIG_FILE" ]]; then
      run_setup
    else
      precheck
      install_systemd_timer
      main_run
    fi
    ;;
  --run)
    precheck
    main_run
    ;;
  --install)
    precheck
    install_systemd_timer
    ;;
  setup|--setup)
    load_config
    ensure_dirs
    cleanup_logs_daily
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