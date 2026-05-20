#!/usr/bin/env bash
set -euo pipefail

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
FAILURE_COUNT_FILE="${STATE_DIR}/failure_count"
LAST_FAILURE_FILE="${STATE_DIR}/last_failure"

SINGBOX_CONFIG="/etc/sing-box/config.json"
SINGBOX_SERVICE="sing-box"
BACKUP_DIR="/etc/sing-box/backup"

API_URL="https://billing.aethercloud.io/api/dynamicv6/vm"
VM_UUID=""
INSTANCE_PROFILE="Hong-Kong"

TARGET_WG_INTERFACE=""
TARGET_TAG=""

TG_BOT_TOKEN=""
TG_CHAT_ID=""

DISPLAY_TZ="Asia/Shanghai"
TIMER_INTERVAL_MINUTES=5

CURL_CONNECT_TIMEOUT=6
CURL_MAX_TIME=20
CURL_RETRY=2

VERBOSE=1
ENABLE_COLOR=1

if [[ -t 1 && "${ENABLE_COLOR}" == "1" ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_CYAN=""
fi

ICON_INFO="ℹ"
ICON_STEP="➜"
ICON_OK="✔"
ICON_WARN="⚠"
ICON_ERR="✘"
ICON_DONE="🎉"

timestamp() {
  TZ="${DISPLAY_TZ}" date '+%F %T %Z'
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" "$BACKUP_DIR"
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE" >/dev/null 2>&1 || true
}

_log_write() {
  mkdir -p "$LOG_DIR"
  echo "[$(timestamp)] $1" >> "$LOG_FILE"
}

_print() {
  local color="$1"
  local icon="$2"
  local tag="$3"
  local msg="$4"
  printf "%s%s %s %-6s%s %s\n" "$color" "$icon" "$(timestamp)" "$tag" "$C_RESET" "$msg" >&2
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
  _print "$C_YELLOW" "$ICON_WARN" "[WARN]" "$msg"
  _log_write "[WARN ] $msg"
}

err() {
  local msg="$*"
  _print "$C_RED" "$ICON_ERR" "[ERR ]" "$msg"
  _log_write "[ERROR] $msg"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "缺少依赖命令: $1"
    exit 1
  }
}

pause_return() {
  echo
  printf "按 Enter 返回..."
  read -r _ </dev/tty || true
}

mask_text() {
  local s="${1:-}"
  local len=${#s}

  if (( len <= 8 )); then
    echo "****"
  else
    echo "${s:0:4}****${s: -4}"
  fi
}

mask_ipv4() {
  local ip="${1:-}"

  if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.*.${BASH_REMATCH[4]}"
  else
    echo "${ip:-获取失败}"
  fi
}

get_public_ipv4() {
  local ip=""

  ip="$(curl -4 -fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"

  if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$(curl -4 -fsS --connect-timeout 3 --max-time 5 https://ifconfig.me/ip 2>/dev/null || true)"
  fi

  if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$(curl -4 -fsS --connect-timeout 3 --max-time 5 https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]' || true)"
  fi

  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$ip"
  else
    echo "获取失败"
  fi
}

_is_placeholder() {
  [[ -z "${1:-}" || "$1" == 填你的* ]]
}

load_config() {
  [[ -f "$CONFIG_FILE" ]] || return 0
  # shellcheck disable=SC1090
  source "$CONFIG_FILE" || true
}

save_config() {
  mkdir -p "$CONFIG_DIR"

  cat > "$CONFIG_FILE" <<EOF2
# ${SERVICE_NAME} 配置
# 生成时间: $(timestamp)

API_URL="${API_URL}"
VM_UUID="${VM_UUID}"
INSTANCE_PROFILE="${INSTANCE_PROFILE}"

TARGET_WG_INTERFACE="${TARGET_WG_INTERFACE}"
TARGET_TAG="${TARGET_TAG}"

TG_BOT_TOKEN="${TG_BOT_TOKEN}"
TG_CHAT_ID="${TG_CHAT_ID}"

DISPLAY_TZ="${DISPLAY_TZ}"
TIMER_INTERVAL_MINUTES="${TIMER_INTERVAL_MINUTES}"

SINGBOX_CONFIG="${SINGBOX_CONFIG}"
SINGBOX_SERVICE="${SINGBOX_SERVICE}"
EOF2

  chmod 600 "$CONFIG_FILE"
  log_ok "配置已保存: $CONFIG_FILE"
}

prompt_input() {
  local prompt="$1"
  local current="${2:-}"
  local secret="${3:-0}"
  local input=""

  printf "  %s%s%s" "$C_BOLD" "$prompt" "$C_RESET" >/dev/tty

  if [[ -n "$current" ]]; then
    if [[ "$secret" == "1" ]]; then
      printf " %s[当前: %s]%s" "$C_DIM" "$(mask_text "$current")" "$C_RESET" >/dev/tty
    else
      printf " %s[当前: %s]%s" "$C_DIM" "$current" "$C_RESET" >/dev/tty
    fi
  fi

  printf ": " >/dev/tty

  if [[ "$secret" == "1" ]]; then
    read -rs input </dev/tty || true
    echo >/dev/tty
  else
    read -r input </dev/tty || true
  fi

  if [[ -z "$input" && -n "$current" ]]; then
    printf '%s\n' "$current"
  else
    printf '%s\n' "$input"
  fi
}

instance_label() {
  echo "$INSTANCE_PROFILE"
}

get_target_wg_interface() {
  if [[ -n "${TARGET_WG_INTERFACE:-}" ]]; then
    echo "$TARGET_WG_INTERFACE"
    return 0
  fi

  case "$INSTANCE_PROFILE" in
    "Hong-Kong") echo "tw" ;;
    "Dallas"|"Manassas"|"Los-Angeles"|"New-Jersey") echo "wg0" ;;
    *) echo "tw" ;;
  esac
}

get_target_tag() {
  if [[ -n "${TARGET_TAG:-}" ]]; then
    echo "$TARGET_TAG"
    return 0
  fi

  case "$INSTANCE_PROFILE" in
    "Hong-Kong") echo "twv6" ;;
    "Dallas"|"Manassas"|"Los-Angeles"|"New-Jersey") echo "attv6" ;;
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

show_config_summary() {
  echo
  echo "================ 当前配置 ================"
  echo "实例名称      : $(instance_label)"
  echo "API           : $API_URL"
  echo "wg_interface  : $(get_target_wg_interface)"
  echo "sing-box tag  : $(get_target_tag)"
  echo "TG Bot Token  : $( ! _is_placeholder "$TG_BOT_TOKEN" && mask_text "$TG_BOT_TOKEN" || echo "未配置" )"
  echo "TG Chat ID    : $( ! _is_placeholder "$TG_CHAT_ID" && echo "$TG_CHAT_ID" || echo "未配置" )"
  echo "时区          : $DISPLAY_TZ"
  echo "定时间隔      : ${TIMER_INTERVAL_MINUTES} 分钟"
  echo "VM UUID       : $( [[ -n "$VM_UUID" ]] && echo "$VM_UUID" || echo "自动检测" )"
  echo "sing-box 配置 : $SINGBOX_CONFIG"
  echo "sing-box 服务 : $SINGBOX_SERVICE"
  echo "=========================================="
  echo
}

send_tg_message() {
  local text="$1"

  if _is_placeholder "$TG_BOT_TOKEN" || _is_placeholder "$TG_CHAT_ID"; then
    log_info "Telegram 未配置，跳过通知"
    return 0
  fi

  curl -fsS -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    -H "Content-Type: application/json" \
    -d "$(jq -cn --arg chat_id "$TG_CHAT_ID" --arg text "$text" '{chat_id:$chat_id,text:$text,parse_mode:"Markdown"}')" \
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

*实例*：\`${instance}\`
*Tag*：\`${tag}\`
*时间*：\`${now_sh}\`

*旧 IPv6*：\`${old_ip:-未设置}\`
*新 IPv6*：\`${new_ip}\`

配置已写入，sing-box 已重启成功。"
}

send_tg_failure() {
  local title="$1"
  local _detail="${2:-}"
  local now_sh public_ipv4 masked_ipv4

  now_sh="$(TZ="${DISPLAY_TZ}" date '+%Y-%m-%d %H:%M:%S %Z')"
  public_ipv4="$(get_public_ipv4)"
  masked_ipv4="$(mask_ipv4 "$public_ipv4")"

  send_tg_message "🚨 *故障报警*
❌ *${title}*

*实例名称*：\`$(instance_label)\`
*IPv4 地址*：\`${masked_ipv4}\`
*时间*：\`${now_sh}\`"
}

get_failure_count() {
  local n=0

  [[ -f "$FAILURE_COUNT_FILE" ]] && n="$(cat "$FAILURE_COUNT_FILE" 2>/dev/null || echo 0)"
  [[ "$n" =~ ^[0-9]+$ ]] || n=0

  echo "$n"
}

reset_failure_count() {
  echo 0 > "$FAILURE_COUNT_FILE"
  : > "$LAST_FAILURE_FILE"
  chmod 600 "$FAILURE_COUNT_FILE" "$LAST_FAILURE_FILE" >/dev/null 2>&1 || true
}

record_failure_count() {
  local reason="$1"
  local n

  n="$(get_failure_count)"
  n=$((n + 1))

  echo "$n" > "$FAILURE_COUNT_FILE"

  {
    echo "time=$(timestamp)"
    echo "count=$n"
    echo "reason=$reason"
  } > "$LAST_FAILURE_FILE"

  chmod 600 "$FAILURE_COUNT_FILE" "$LAST_FAILURE_FILE" >/dev/null 2>&1 || true

  echo "$n"
}

api_post_json() {
  local url="$1"
  local payload="$2"

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

normalize_ipv6() {
  local ip="${1:-}"

  ip="${ip%%/*}"
  ip="${ip#[}"
  ip="${ip%]}"

  echo "$ip"
}

validate_ipv6() {
  local ip="$1"

  [[ -n "$ip" ]] || return 1
  [[ "$ip" != "null" ]] || return 1
  [[ "$ip" == *:* ]] || return 1
  [[ "$ip" != */* ]] || return 1

  return 0
}

get_api_ipv6() {
  local vm_uuid="$1"
  local wg_interface="$2"
  local payload api_json target_ipv6 status_url allocate_url api_base active lease_count

  payload="$(jq -cn --arg vm_uuid "$vm_uuid" '{vm_uuid:$vm_uuid}')"

  if [[ "$API_URL" == */status ]]; then
    status_url="$API_URL"
    api_base="${API_URL%/status}"
    allocate_url="${api_base}/allocate"
  else
    api_base="${API_URL%/}"
    status_url="${api_base}/status"
    allocate_url="${api_base}/allocate"
  fi

  log_info "请求 API: $status_url"
  api_json="$(api_post_json "$status_url" "$payload")"

  active="$(echo "$api_json" | jq -r '.active // false')"

  lease_count="$(echo "$api_json" | jq '
    def to_arr:
      if . == null then []
      elif type == "array" then .
      elif type == "object" then [.]
      else []
      end;

    ((.leases | to_arr) + (.lease | to_arr))
    | map(select(type == "object"))
    | length
  ')"

  if [[ "$active" != "true" || "$lease_count" -eq 0 ]]; then
    log_info "status 未返回有效租约，尝试 allocate: $allocate_url"
    api_json="$(api_post_json "$allocate_url" "$payload")"
  fi

  target_ipv6="$(echo "$api_json" | jq -r --arg wg "$wg_interface" '
    def to_arr:
      if . == null then []
      elif type == "array" then .
      elif type == "object" then [.]
      else []
      end;

    (
      ((.leases | to_arr) + (.lease | to_arr))
      | map(select(type == "object"))
      | map(select((.wg_interface // "") == $wg))
      | .[0]
      | (.ipv6_cidr // .ipv6 // .address // .ip // empty)
    ) // empty
  ')"

  if [[ -z "$target_ipv6" || "$target_ipv6" == "null" ]]; then
    lease_count="$(echo "$api_json" | jq '
      def to_arr:
        if . == null then []
        elif type == "array" then .
        elif type == "object" then [.]
        else []
        end;

      ((.leases | to_arr) + (.lease | to_arr))
      | map(select(type == "object"))
      | length
    ')"

    if [[ "$lease_count" -eq 1 ]]; then
      warn "未匹配到 wg_interface=${wg_interface}，但只有一个 lease，自动使用"

      target_ipv6="$(echo "$api_json" | jq -r '
        def to_arr:
          if . == null then []
          elif type == "array" then .
          elif type == "object" then [.]
          else []
          end;

        (
          ((.leases | to_arr) + (.lease | to_arr))
          | map(select(type == "object"))
          | .[0]
          | (.ipv6_cidr // .ipv6 // .address // .ip // empty)
        ) // empty
      ')"
    else
      warn "未找到 wg_interface=${wg_interface} 对应 IPv6，当前 lease："

      echo "$api_json" | jq -r '
        def to_arr:
          if . == null then []
          elif type == "array" then .
          elif type == "object" then [.]
          else []
          end;

        ((.leases | to_arr) + (.lease | to_arr))
        | map(select(type == "object"))
        | .[]
        | "wg_interface=\(.wg_interface // "unknown") ipv6=\(.ipv6_cidr // .ipv6 // .address // .ip // "empty")"
      ' | while read -r line; do
        warn "  $line"
      done

      return 1
    fi
  fi

  target_ipv6="$(normalize_ipv6 "$target_ipv6")"

  echo "$target_ipv6"
}

tag_exists() {
  local tag="$1"

  jq -e --arg tag "$tag" '
    .outbounds[]?
    | select(.tag == $tag)
  ' "$SINGBOX_CONFIG" >/dev/null 2>&1
}

get_current_bind_ip() {
  local tag="$1"

  jq -r --arg tag "$tag" '
    .outbounds[]?
    | select(.tag == $tag)
    | .inet6_bind_address // empty
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

  jq empty "$tmp_file"

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

  need_cmd curl
  need_cmd jq
  need_cmd systemctl

  [[ -f "$SINGBOX_CONFIG" ]] || {
    err "sing-box 配置文件不存在: $SINGBOX_CONFIG"
    exit 1
  }

  jq empty "$SINGBOX_CONFIG" >/dev/null || {
    err "sing-box 配置文件不是有效 JSON: $SINGBOX_CONFIG"
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
    err "未获取到有效 IPv6: ${target_ipv6:-empty}"
    return 1
  }

  log_ok "目标 IPv6: $target_ipv6"

  tag_exists "$target_tag" || {
    err "sing-box 配置中未找到 tag=${target_tag}"
    return 1
  }

  current_ip="$(get_current_bind_ip "$target_tag")"

  if [[ -z "$current_ip" ]]; then
    log_info "当前 inet6_bind_address 为空，将直接写入"
  fi

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
    send_tg_failure "sing-box 重启失败，已自动回滚"
  else
    send_tg_failure "sing-box 重启失败，回滚也失败"
  fi

  _log_write "[ERROR] sing-box 重启失败详情: ${restart_error_detail}"

  return 1
}

main_run() {
  local failure_count failure_detail

  log_step "开始执行同步任务"

  if run_once; then
    reset_failure_count
    log_ok "${ICON_DONE} 任务执行成功，连续失败计数已清零"
    exit 0
  fi

  failure_detail="同步任务失败：$(timestamp)"
  failure_count="$(record_failure_count "$failure_detail")"

  warn "本次同步失败，当前连续失败次数: ${failure_count}/3"

  if (( failure_count < 3 )); then
    warn "未达到报警阈值，不发送 Telegram。下一次将由 systemd timer 在约 ${TIMER_INTERVAL_MINUTES} 分钟后再次执行"
    exit 1
  fi

  if (( failure_count == 3 )); then
    err "连续失败已达到 3 次，发送 Telegram 报警"
    send_tg_failure "sing-box IPv6 同步连续 3 次失败"
    exit 1
  fi

  warn "连续失败次数已超过 3 次，本次不重复报警，避免通知刷屏"
  exit 1
}

install_systemd_timer() {
  if [[ "$EUID" -ne 0 ]]; then
    warn "安装 systemd timer 需要 root"
    return 1
  fi

  local interval="${TIMER_INTERVAL_MINUTES}"

  [[ "$interval" =~ ^[0-9]+$ ]] || interval=5
  (( interval > 0 )) || interval=5
  TIMER_INTERVAL_MINUTES="$interval"

  mkdir -p "$(dirname "$SCRIPT_INSTALL_PATH")"

  if [[ "$(readlink -f "$0" 2>/dev/null || echo "$0")" != "$SCRIPT_INSTALL_PATH" ]]; then
    cp -f "$0" "$SCRIPT_INSTALL_PATH"
    chmod +x "$SCRIPT_INSTALL_PATH"
    log_ok "脚本已安装到: $SCRIPT_INSTALL_PATH"
  else
    chmod +x "$SCRIPT_INSTALL_PATH"
  fi

  cat > "$SERVICE_FILE" <<EOF2
[Unit]
Description=Aether sing-box IPv6 Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_INSTALL_PATH} --run
EOF2

  cat > "$TIMER_FILE" <<EOF2
[Unit]
Description=Run Aether sing-box IPv6 Sync every ${interval} minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval}min
Unit=${SERVICE_NAME}.service
Persistent=true

[Install]
WantedBy=timers.target
EOF2

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.timer" >/dev/null 2>&1

  log_ok "systemd timer 已启用，间隔: ${interval} 分钟"

  cat > /usr/local/bin/sbip <<EOF2
#!/usr/bin/env bash
exec ${SCRIPT_INSTALL_PATH} console
EOF2

  chmod +x /usr/local/bin/sbip
  log_ok "快捷命令已安装: sbip"
}

run_setup() {
  [[ -r /dev/tty ]] && exec </dev/tty || true
  ensure_dirs

  if [[ -f "$CONFIG_FILE" ]]; then
    load_config
    clear 2>/dev/null || true

    echo
    echo "检测到已有配置："
    show_config_summary
    echo "  1) 保留旧配置并继续安装/执行"
    echo "  2) 重新填写配置"
    echo

    printf "请选择 [1/2，默认 1]: "

    local old_choice
    read -r old_choice </dev/tty || true
    old_choice="${old_choice:-1}"

    if [[ "$old_choice" == "1" ]]; then
      log_ok "已选择保留旧配置"

      printf "是否立即安装/更新定时任务并执行一次同步？[Y/n]: "

      local do_run
      read -r do_run </dev/tty || true
      do_run="${do_run:-Y}"

      if [[ "${do_run^^}" == "Y" ]]; then
        install_systemd_timer
        precheck
        main_run
      fi

      return 0
    fi
  fi

  clear 2>/dev/null || true

  echo
  echo "=========== Aether sing-box IPv6 同步配置向导 ==========="
  echo "直接回车可保留当前值"
  echo
  echo "[实例选择]"
  echo "  1. Hong-Kong"
  echo "  2. Dallas"
  echo "  3. Manassas"
  echo "  4. Los-Angeles"
  echo "  5. New-Jersey"
  echo

  local default_choice

  case "$INSTANCE_PROFILE" in
    "Hong-Kong") default_choice="1" ;;
    "Dallas") default_choice="2" ;;
    "Manassas") default_choice="3" ;;
    "Los-Angeles") default_choice="4" ;;
    "New-Jersey") default_choice="5" ;;
    *) default_choice="1" ;;
  esac

  local instance_in
  instance_in="$(prompt_input "请输入选项" "$default_choice")"

  case "$instance_in" in
    ""|1) INSTANCE_PROFILE="Hong-Kong" ;;
    2) INSTANCE_PROFILE="Dallas" ;;
    3) INSTANCE_PROFILE="Manassas" ;;
    4) INSTANCE_PROFILE="Los-Angeles" ;;
    5) INSTANCE_PROFILE="New-Jersey" ;;
    "Hong-Kong"|"Dallas"|"Manassas"|"Los-Angeles"|"New-Jersey") INSTANCE_PROFILE="$instance_in" ;;
    *) warn "输入无效，保留当前实例: $INSTANCE_PROFILE" ;;
  esac

  echo
  echo "[API 设置]"
  API_URL="$(prompt_input "API 地址" "$API_URL")"

  echo
  echo "[匹配设置]"
  echo "留空使用内置映射："
  echo "  Hong-Kong -> wg_interface=tw, tag=twv6"
  echo "  美国地区  -> wg_interface=wg0, tag=attv6"

  TARGET_WG_INTERFACE="$(prompt_input "自定义 wg_interface，留空自动" "$TARGET_WG="$(留空 _TOKEN，留空可跳过" "$TG_BOT_TOKEN" "1")"
  TG_CHAT_ID="$(prompt_input "TG Chat ID，留空可跳过" "$TG_CHAT_ID")"

  echo
  echo "[高级选项]"
  DISPLAY_TZ="$(prompt_input "时区" "$DISPLAY_TZ")"

_in="$(，_MIN"9]+$ && "$interval_in" -gt 0 ]]; then
    TIMER_INTERVAL_MINUTES="$interval_in"
  else
    TIMER_INTERVAL_MINUTES=5
  fi

  VM_UUID="$(prompt_input "VM UUID，留空自动检测" "$VM_UUID")"
  SINGBOX_CONFIG="$(prompt_input "sing-box 配置路径"BOXINGBOX_SERVICE="$(prompt_input "sing-box systemd 服务名" "$SINGBOX_SERVICE")"

  show_config_summary

  printf "以上配置是否保存？[Y/n]: "

  local confirm
  read -r confirm </dev/tty || true
  confirm="${confirm:-Y}"

  if [[ "${confirm^^}" == "Y" ]]; then
    save_config

    printf "是否立即安装定时任务并执行一次同步？[Y/n]: "

    local do_install
    read -r do_install </dev/tty || true
    do_install="${do_install:-Y}"

    if [[ "${do_install^^}" == "Y" ]]; then
      install_systemd_timer
      precheck
      main_run
    fi
  else
    warn "已取消保存"
  fi
}

console_show_status() {
  load_config
  ensure_dirs

  local target_tag current_config_ip last_ip timer_status last_run fail_count

  target_tag="$(get_target_tag)"
  current_config_ip="$(get_current_bind_ip "$target_tag" 2>/dev/null || true)"
  [[ -z "$current_config_ip" ]] && current_config_ip="未读取到"

  last_ip="无记录"

  if [[ -f "$LAST_IP_FILE" ]]; then
    last_ip="$(cat "$LAST_IP_FILE" 2>/dev/null || echo "无记录")"
  fi

  [[ -z "$last_ip" ]] && last_ip="无记录"

  fail_count="$(get_failure_count)"

  if systemctl is-active --quiet "${SERVICE_NAME}.timer" 2>/dev/null; then
    timer_status="运行中"
    last_run="$(systemctl show "${SERVICE_NAME}.service" --property=ExecMainStartTimestamp --value 2>/dev/null | grep -v '^$' || echo '未知')"
  else
    timer_status="未运行"
    last_run="N/A"
  fi

  echo
  echo "================ Aether sing-box IPv6 同步状态 ================"
  echo "实例名称        : $(instance_label)"
  echo "API             : $API_URL"
  echo "wg_interface    : $(get_target_wg_interface)"
  echo "目标 tag        : $target_tag"
  echo "定时任务        : $timer_status"
  echo "定时间隔        : ${TIMER_INTERVAL_MINUTES} 分钟"
  echo "上次执行        : $last_run"
  echo "连续失败次数    : $fail_count"
  echo "配置当前 IP     : $current_config_ip"
  echo "上次同步 IP     : $last_ip"
  echo "配置文件        : $CONFIG_FILE"
  echo "sing-box 配置   : $SINGBOX_CONFIG"
  echo "日志文件        : $LOG_FILE"
  echo "备份目录        : $BACKUP_DIR"
  echo "==============================================================="
  echo
}

console_main() {
  [[ -r /dev/tty ]] && exec </dev/tty || true
  load_config
  ensure_dirs

  while true; do
    clear 2>/dev/null || true
    console_show_status

    echo "请选择操作："
    echo "  1) 查看日志"
    echo "  2) 实时日志"
    echo "  3) 立即执行同步"
    echo "  4) 启动 timer"
    echo "  5) 停止 timer"
    echo "  6) 重启 timer"
    echo "  7) 修改配置"
    echo "  8) 卸载脚本"
    echo "  0) 退出"
    echo

    printf "请输入选项: "

    local choice
    read -r choice </dev/tty || true

    case "$choice" in
      1)
        echo
        tail -n 100 "$LOG_FILE" 2>/dev/null || true
        pause_return
        ;;
      2)
        echo
        echo "实时日志，按 Ctrl+C 返回终端后重新输入 sbip 进入菜单。"
        echo
        tail -f "$LOG_FILE"
        ;;
      3)
        echo
        echo "开始执行同步，请稍候..."
        echo
        bash "$SCRIPT_INSTALL_PATH" --run 2>&1 || true
        pause_return
        ;;
      4)
        systemctl enable --now "${SERVICE_NAME}.timer"
        echo "timer 已启动"
        pause_return
        ;;
      5)
        systemctl disable --now "${SERVICE_NAME}.timer"
        echo "timer 已停止"
        pause_return
        ;;
      6)
        systemctl restart "${SERVICE_NAME}.timer"
        echo "timer 已重启"
        pause_return
        ;;
      7)
        run_setup
        pause_return
        ;;
      8)
        run_uninstall
        ;;
      0)
        exit 0
        ;;
      *)
        warn "无效选项"
        sleep 1
        ;;
    esac
  done
}

run_uninstall() {
  [[ -r /dev/tty ]] && exec </dev/tty || true

  echo
  echo "将删除："
  echo "  - $SERVICE_FILE"
  echo "  - $TIMER_FILE"
  echo "  - $SCRIPT_INSTALL_PATH"
  echo "  - /usr/local/bin/sbip"
  echo "  - $CONFIG_FILE"
  echo "  - $STATE_DIR"
  echo "  - $LOG_DIR"
  echo

  printf "确认卸载？[y/N]: "

  local confirm
  read -r confirm </dev/tty || true
  confirm="${confirm:-N}"

  if [[ "${confirm^^}" != "Y" ]]; then
    warn "已取消卸载"
    return 0
  fi

  systemctl disable --now "${SERVICE_NAME}.timer" 2>/dev/null || true
  systemctl disable --now "${SERVICE_NAME}.service" 2>/dev/null || true

  rm -f "$SERVICE_FILE" "$TIMER_FILE" "$SCRIPT_INSTALL_PATH" /usr/local/bin/sbip
  rm -f "$CONFIG_FILE"
  rm -rf "$STATE_DIR" "$LOG_DIR"

  systemctl daemon-reload 2>/dev/null || true

  echo "卸载完成"
  exit 0
}

usage() {
  cat <<EOF2
Usage:
  $0                配置/安装/执行
  $0 setup          配置向导
  $0 --run          执行一次同步
  $0 --install      安装/更新 systemd timer
  $0 console        控制台
  $0 uninstall      卸载
EOF2
}

case "${1:-}" in
  "")
    load_config
    run_setup
    ;;
  setup|--setup)
    load_config
    run_setup
    ;;
  --run)
    precheck
    main_run
    ;;
  --install)
    load_config
    ensure_dirs
    need_cmd systemctl
    install_systemd_timer
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
