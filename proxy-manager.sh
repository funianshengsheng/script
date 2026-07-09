#!/usr/bin/env bash
# =============================================================================
#  Proxy Node Manager  (Sing-box + Xray 双内核)
#  多协议一键部署 / 节点生成 / 分享链接 + 二维码
#
#  支持协议:
#    VLESS: Reality-Vision / XHTTP-Reality / gRPC-Reality / Encryption / Encryption-XHTTP
#           WS-TLS / gRPC-TLS / H2-TLS / XHTTP-TLS
#    FinalMask(官方 Xray v26.3.27+): Enc-XHTTP-FinalMask / Enc-FinalMask-sudoku / FullStack
#    VMess: TCP / mKCP / QUIC / WS / WS-TLS / gRPC-TLS / H2-TLS
#    Trojan: Reality / WS-TLS / gRPC-TLS / H2-TLS
#    其他: Shadowsocks / Shadowsocks-2022 / SOCKS5 / HTTP /
#          Hysteria2 / TUIC v5 / AnyTLS / ShadowTLS v3 / NaïveProxy /
#          Snell v4/v5 / Mieru / WireGuard
#  内核: VLESS/VMess/Trojan/SS/SOCKS/FinalMask 走 Xray; QUIC 系走 sing-box; Snell/Mieru/WireGuard 独立
# =============================================================================

set -o pipefail

# ---------------------------------------------------------------------------
# 一、颜色与输出辅助
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[38;5;203m';    GREEN='\033[38;5;151m';  YELLOW='\033[38;5;223m'
    BLUE='\033[38;5;110m';   CYAN='\033[38;5;109m';   MAGENTA='\033[38;5;183m'
    BOLD='\033[1m';          DIM='\033[38;5;245m';     NC='\033[0m'
else
    RED='';GREEN='';YELLOW='';BLUE='';CYAN='';MAGENTA='';BOLD='';DIM='';NC=''
fi

info()  { echo -e "${CYAN}$*${NC}"; }
ok()    { echo -e "${GREEN}$*${NC}"; }
warn()  { echo -e "${YELLOW}$*${NC}"; }
err()   { echo -e "${RED}$*${NC}"; }
die()   { err "$*"; exit 1; }
hr()    { echo -e "${DIM}------------------------------------------------------------${NC}"; }

# 兼容从 net-tcp-tune 移植的 PTM 模块颜色变量名。
gl_hong="$RED"; gl_lv="$GREEN"; gl_huang="$YELLOW"; gl_bai="$NC"
gl_kjlan="$CYAN"; gl_zi="$MAGENTA"; gl_hui="$DIM"

# ---------------------------------------------------------------------------
# 二、全局常量
# ---------------------------------------------------------------------------
SCRIPT_VERSION="1.6.9"
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"

# sing-box
SB_DIR="/etc/sing-box"
SB_CONFIG="${SB_DIR}/config.json"
SB_CERT_DIR="${SB_DIR}/cert"
SB_CERT="${SB_CERT_DIR}/cert.pem"
SB_KEY="${SB_CERT_DIR}/key.pem"
SB_BIN="/usr/local/bin/sing-box"
SB_SERVICE="sing-box"
SB_SERVICE_FILE="/etc/systemd/system/${SB_SERVICE}.service"

# Xray
XRAY_DIR="/usr/local/etc/xray"
XRAY_CONFIG="${XRAY_DIR}/config.json"
XRAY_BIN="/usr/local/bin/xray"
XRAY_SHARE="/usr/local/share/xray"
XRAY_SERVICE="xray"
XRAY_SERVICE_FILE="/etc/systemd/system/${XRAY_SERVICE}.service"

# 统一状态文件 (节点信息 / 元数据)
STATE_DIR="/etc/proxy-manager"
STATE="${STATE_DIR}/state.json"

# Snell
SNELL_BIN="/usr/local/bin/snell-server"
SNELL_CONF="/etc/snell/snell-server.conf"
SNELL_SERVICE="snell"
SNELL_SERVICE_FILE="/etc/systemd/system/${SNELL_SERVICE}.service"
SNELL_STATE="${STATE_DIR}/snell.env"

# ShadowTLS (ihciah/shadow-tls, Snell 插件模式使用)
SHADOWTLS_BIN="/usr/local/bin/shadow-tls"
SHADOWTLS_REPO="ihciah/shadow-tls"

# simple-obfs (Shadowsocks HTTP 伪装插件)
SIMPLE_OBFS_BIN="/usr/local/bin/obfs-server"
SIMPLE_OBFS_REPO="https://github.com/shadowsocks/simple-obfs.git"

# Mieru / mita (enfein/mieru, 独立服务端)
MITA_SERVICE="mita"
MITA_SERVICE_FILE="/etc/systemd/system/${MITA_SERVICE}.service"
MIERU_STATE="${STATE_DIR}/mieru.env"
MITA_REPO="enfein/mieru"

# WireGuard (独立内核, wg-quick)
WG_DIR="/etc/wireguard"
WG_IFACE="wg0"
WG_CONF="${WG_DIR}/${WG_IFACE}.conf"
WG_STATE="${STATE_DIR}/wireguard.env"

SHORTCUT="/usr/local/bin/pm"
SCRIPT_UPDATE_URL="https://raw.githubusercontent.com/funianshengsheng/script/main/proxy-manager.sh"
AUTO_UPDATE_ENV="PROXY_MANAGER_AUTO_UPDATED"

# Reality 伪装域名候选 (需真实可达、支持 TLS1.3)
REALITY_SNIS=(
    "www.microsoft.com" "www.apple.com" "www.amazon.com"
    "www.cloudflare.com" "dl.google.com" "www.icloud.com"
    "addons.mozilla.org" "www.tesla.com" "www.samsung.com"
)

PUBLIC_IPV4=""; PUBLIC_IPV6=""

# ---------------------------------------------------------------------------
# 二之二、兼容层 (systemd / OpenRC / BusyBox)
# ---------------------------------------------------------------------------
pm_systemd_bin() { type -P systemctl 2>/dev/null || true; }
pm_journalctl_bin() { type -P journalctl 2>/dev/null || true; }
pm_has_systemd() {
    [[ -n "$(pm_systemd_bin)" ]] || return 1
    [[ -d /run/systemd/system ]] && return 0
    [[ "$(ps -p 1 -o comm= 2>/dev/null)" == "systemd" ]] && return 0
    return 1
}
pm_has_openrc() { command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; }
pm_service_supported() { pm_has_systemd || pm_has_openrc; }
pm_openrc_service_path() { printf '/etc/init.d/%s' "$1"; }

pm_openrc_systemctl() {
    pm_has_openrc || return 1
    local action="$1"; shift || true
    local now=false quiet=false svc
    case "$action" in
        daemon-reload) return 0 ;;
        is-active)
            while [[ "${1:-}" == --* ]]; do [[ "$1" == "--quiet" ]] && quiet=true; shift; done
            svc="${1:-}"
            [[ -n "$svc" ]] || return 1
            if rc-service "$svc" status >/dev/null 2>&1; then
                $quiet || echo "active"
                return 0
            fi
            $quiet || echo "inactive"
            return 3
            ;;
        enable|disable)
            while [[ "${1:-}" == --* ]]; do [[ "$1" == "--now" ]] && now=true; shift; done
            local failed=0
            for svc in "$@"; do
                [[ -n "$svc" ]] || continue
                if [[ "$action" == "enable" ]]; then
                    rc-update add "$svc" default >/dev/null 2>&1 || failed=1
                    $now && rc-service "$svc" start >/dev/null 2>&1 || true
                else
                    $now && rc-service "$svc" stop >/dev/null 2>&1 || true
                    rc-update del "$svc" default >/dev/null 2>&1 || true
                fi
            done
            return "$failed"
            ;;
        start|stop|restart|status)
            local failed=0
            for svc in "$@"; do
                [[ -n "$svc" ]] || continue
                rc-service "$svc" "$action" >/dev/null 2>&1 || {
                    [[ "$action" == "restart" ]] && rc-service "$svc" start >/dev/null 2>&1 || failed=1
                }
            done
            return "$failed"
            ;;
        *) return 1 ;;
    esac
}

systemctl() {
    local bin; bin="$(pm_systemd_bin)"
    if [[ -n "$bin" ]]; then "$bin" "$@"; return $?; fi
    pm_openrc_systemctl "$@"
}

journalctl() {
    local bin; bin="$(pm_journalctl_bin)"
    if [[ -n "$bin" ]]; then "$bin" "$@"; return $?; fi
    local svc="" n=40 arg prev=""
    for arg in "$@"; do
        [[ "$prev" == "-u" ]] && svc="$arg"
        [[ "$prev" == "-n" ]] && n="$arg"
        prev="$arg"
    done
    if [[ -n "$svc" && -f "/var/log/${svc}.log" ]]; then
        tail -n "$n" "/var/log/${svc}.log"
    else
        tail -n "$n" /var/log/messages /var/log/syslog 2>/dev/null || true
    fi
}

pm_write_openrc_service() {
    pm_has_openrc || return 0
    local svc="$1" desc="$2" cmd="$3" args="${4:-}" env_lines="${5:-}" path
    path="$(pm_openrc_service_path "$svc")"
    cat > "$path" <<EOF
#!/sbin/openrc-run
description="${desc}"
command="${cmd}"
command_args="${args}"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="/var/log/\${RC_SVCNAME}.log"
error_log="/var/log/\${RC_SVCNAME}.log"
${env_lines}

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$path"
}

pm_remove_openrc_service() {
    local svc
    for svc in "$@"; do
        [[ -n "$svc" ]] || continue
        rm -f "$(pm_openrc_service_path "$svc")"
    done
}

pm_date_epoch() {
    local d="$1"
    date -d "$d" +%s 2>/dev/null && return 0
    date -j -f "%Y-%m-%d" "$d" +%s 2>/dev/null && return 0
    local y m day
    IFS=- read -r y m day <<< "$d"
    [[ "$y$m$day" =~ ^[0-9]+$ ]] || return 1
    TZ=UTC awk -v y="$y" -v m="$m" -v d="$day" 'BEGIN { print mktime(y " " m " " d " 00 00 00") }' 2>/dev/null
}

pm_date_valid() { [[ "$(pm_date_epoch "$1" 2>/dev/null)" =~ ^[0-9]+$ ]]; }

pm_is_leap_year() {
    local y="$1"
    (( (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 ))
}

pm_days_in_month() {
    local y="$1" m="$2"
    m=$((10#$m))
    case "$m" in
        1|3|5|7|8|10|12) echo 31 ;;
        4|6|9|11) echo 30 ;;
        2) pm_is_leap_year "$y" && echo 29 || echo 28 ;;
        *) echo 28 ;;
    esac
}

pm_add_months() {
    local base_date="$1" months="$2" target_day="$3" y m total ny nm last
    IFS=- read -r y m _ <<< "$base_date"
    [[ "$y$m$months$target_day" =~ ^[0-9]+$ ]] || return 1
    m=$((10#$m))
    total=$((m + months))
    ny=$((y + (total - 1) / 12))
    nm=$(((total - 1) % 12 + 1))
    last="$(pm_days_in_month "$ny" "$nm")"
    (( target_day > last )) && target_day="$last"
    printf "%04d-%02d-%02d\n" "$ny" "$nm" "$target_day"
}

# ---------------------------------------------------------------------------
# 三、系统检测与前置检查
# ---------------------------------------------------------------------------
check_root() { [[ "$(id -u)" == "0" ]] || die "请以 root 权限运行本脚本 (sudo -i 后执行)。"; }

OS_ID=""; PKG=""; ARCH=""; SB_ARCH=""; XRAY_ARCH=""; SNELL_ARCH=""
detect_system() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        OS_ID="$(. /etc/os-release && echo "$ID")"
    fi
    if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
    elif command -v dnf     >/dev/null 2>&1; then PKG="dnf"
    elif command -v yum     >/dev/null 2>&1; then PKG="yum"
    elif command -v apk     >/dev/null 2>&1; then PKG="apk"
    elif command -v zypper  >/dev/null 2>&1; then PKG="zypper"
    elif command -v pacman  >/dev/null 2>&1; then PKG="pacman"
    else PKG=""; fi

    case "$(uname -m)" in
        x86_64|amd64)   ARCH="amd64"; SB_ARCH="amd64"; XRAY_ARCH="64";         SNELL_ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64"; SB_ARCH="arm64"; XRAY_ARCH="arm64-v8a";  SNELL_ARCH="aarch64" ;;
        armv7l|armv7)   ARCH="armv7"; SB_ARCH="armv7"; XRAY_ARCH="arm32-v7a";  SNELL_ARCH="armv7l" ;;
        i386|i686)      ARCH="386";   SB_ARCH="386";   XRAY_ARCH="32";         SNELL_ARCH="i386" ;;
        *) ARCH="$(uname -m)"; SB_ARCH="amd64"; XRAY_ARCH="64"; SNELL_ARCH="amd64" ;;
    esac
}

pkg_install() {
    case "$PKG" in
        apt) apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 ;;
        dnf) dnf install -y -q "$@" >/dev/null 2>&1 ;;
        yum) yum install -y -q "$@" >/dev/null 2>&1 ;;
        apk) apk add --no-cache "$@" >/dev/null 2>&1 ;;
        zypper) zypper --non-interactive install -y "$@" >/dev/null 2>&1 ;;
        pacman) pacman -Sy --noconfirm --needed "$@" >/dev/null 2>&1 ;;
        *)   return 1 ;;
    esac
}

check_dependencies() {
    local deps=(curl tar unzip jq openssl qrencode) miss=() d
    for d in "${deps[@]}"; do command -v "$d" >/dev/null 2>&1 || miss+=("$d"); done
    [[ ${#miss[@]} -eq 0 ]] && return 0
    info "正在安装依赖: ${miss[*]}"
    pkg_install "${miss[@]}" || warn "自动安装依赖失败, 请手动安装: ${miss[*]}"
    for d in curl tar jq openssl; do
        command -v "$d" >/dev/null 2>&1 || die "关键依赖 $d 安装失败, 请手动安装后重试。"
    done
}

# PTM 模块沿用 net-tcp-tune 的 install_package 调用习惯，这里适配为本脚本的 pkg_install。
install_package() {
    local cmds=("$@") missing=() packages=() cmd pkg
    for cmd in "${cmds[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    [[ ${#missing[@]} -eq 0 ]] && return 0

    for cmd in "${missing[@]}"; do
        case "$cmd:$PKG" in
            nft:*) pkg="nftables" ;;
            tc:apt|tc:apk) pkg="iproute2" ;;
            tc:dnf|tc:yum) pkg="iproute-tc" ;;
            tc:*) pkg="iproute2" ;;
            crontab:apt) pkg="cron" ;;
            crontab:dnf|crontab:yum) pkg="cronie" ;;
            crontab:apk) pkg="dcron" ;;
            crontab:zypper|crontab:pacman) pkg="cronie" ;;
            *) pkg="$cmd" ;;
        esac
        packages+=("$pkg")
    done

    info "正在安装依赖: ${packages[*]}"
    pkg_install "${packages[@]}" || { warn "自动安装依赖失败, 请手动安装: ${packages[*]}"; return 1; }
    return 0
}

# 将北京时间的计划任务时间转换为服务器本地时区，供 PTM cron 使用。
snell_bj_to_local_time() {
    local bh=$1 bm=$2 base epoch lh lm
    base=$(TZ='Asia/Shanghai' date +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)
    epoch=$(TZ='Asia/Shanghai' date -d "$base $bh:$bm:00" +%s 2>/dev/null \
            || date -d "$base $bh:$bm:00" +%s 2>/dev/null)
    if [[ -n "$epoch" ]]; then
        lh=$(date -d "@$epoch" +%H 2>/dev/null || date -r "$epoch" +%H 2>/dev/null)
        lm=$(date -d "@$epoch" +%M 2>/dev/null || date -r "$epoch" +%M 2>/dev/null)
    fi
    if ! [[ "$lh" =~ ^[0-9]{1,2}$ ]]; then
        lh="$bh"
        lm="$bm"
    fi
    printf "%02d %02d\n" $((10#$lh)) $((10#$lm))
}

# ---------------------------------------------------------------------------
# 四、网络 / 随机值 / 端口辅助
# ---------------------------------------------------------------------------
detect_ip() {
    [[ -n "$PUBLIC_IPV4$PUBLIC_IPV6" ]] && return 0
    PUBLIC_IPV4="$(curl -s4 --max-time 8 https://api.ipify.org 2>/dev/null \
                 || curl -s4 --max-time 8 https://ifconfig.me 2>/dev/null \
                 || curl -s4 --max-time 8 https://ip.sb 2>/dev/null)"
    PUBLIC_IPV6="$(curl -s6 --max-time 8 https://api6.ipify.org 2>/dev/null \
                 || curl -s6 --max-time 8 https://ifconfig.co 2>/dev/null)"
    PUBLIC_IPV4="${PUBLIC_IPV4//[$'\r\n ']/}"
    PUBLIC_IPV6="${PUBLIC_IPV6//[$'\r\n ']/}"
}

server_host() {
    local h=""
    [[ -f "$STATE" ]] && h="$(jq -r '.meta.host // empty' "$STATE" 2>/dev/null)"
    if [[ -n "$h" ]]; then echo "$h"; return; fi
    detect_ip
    if   [[ -n "$PUBLIC_IPV4" ]]; then echo "$PUBLIC_IPV4"
    elif [[ -n "$PUBLIC_IPV6" ]]; then echo "[$PUBLIC_IPV6]"
    else echo "YOUR_SERVER_IP"; fi
}

random_port() {
    if command -v shuf >/dev/null 2>&1; then shuf -i 10000-60000 -n1
    else echo $(( (RANDOM % 50000) + 10000 )); fi
}

# 端口是否被占用: 系统实际监听 + sing-box 配置 + Xray 配置
port_used() {
    local p="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tuln 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${p}$" && return 0
    fi
    [[ -f "$SB_CONFIG" ]]   && jq -e --argjson p "$p" 'any(.inbounds[]?; .listen_port==$p)' "$SB_CONFIG"  >/dev/null 2>&1 && return 0
    [[ -f "$XRAY_CONFIG" ]] && jq -e --argjson p "$p" 'any(.inbounds[]?; .port==$p)'         "$XRAY_CONFIG" >/dev/null 2>&1 && return 0
    [[ -f "$STATE" ]] && jq -e --argjson p "$p" '
      any(.nodes | to_entries[]?; (
        ((.key | test("-" + ($p|tostring) + "$")) and (.value.core | test("snell|mieru|shadowtls"))) or
        ((try (.value.extra_tag | fromjson | .port) catch null) == $p) or
        (((try (.value.extra_tag | fromjson | .proto) catch "") == "BOTH") and ((try (.value.extra_tag | fromjson | .port) catch 0) + 1 == $p))
      ))
    ' "$STATE" >/dev/null 2>&1 && return 0
    [[ -f "$WG_STATE" ]] && source "$WG_STATE" 2>/dev/null && [[ "${WG_PORT:-}" == "$p" ]] && return 0
    return 1
}

gen_uuid() {
    if [[ -x "$SB_BIN" ]]; then "$SB_BIN" generate uuid 2>/dev/null && return; fi
    if [[ -x "$XRAY_BIN" ]]; then "$XRAY_BIN" uuid 2>/dev/null && return; fi
    if [[ -r /proc/sys/kernel/random/uuid ]]; then cat /proc/sys/kernel/random/uuid; return; fi
    command -v uuidgen >/dev/null 2>&1 && { uuidgen; return; }
    openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'
}

gen_b64()  { openssl rand -base64 "${1:-16}" | tr -d '\r\n'; }
gen_pass() { openssl rand -hex "${1:-16}" | tr -d '\r\n'; }
gen_short_id() { openssl rand -hex 8; }

mktemp_json() {
    local dir="${TMPDIR:-/tmp}" tmp
    tmp="$(mktemp "${dir%/}/proxy-manager.XXXXXX.json" 2>/dev/null)" && { printf '%s' "$tmp"; return 0; }
    tmp="$(mktemp 2>/dev/null)" || return 1
    mv "$tmp" "${tmp}.json" || return 1
    printf '%s.json' "$tmp"
}

url_encode() {
    local s="$1" out="" c i
    for ((i=0;i<${#s};i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) out+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    printf '%s' "$out"
}

b64_line() { printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 | tr -d '\r\n'; }
b64_urlsafe() { b64_line "$1" | tr '+/' '-_' | sed 's/=*$//'; }

b64_urlsafe_decode() {
    local s="$1" mod
    s="${s//-/+}"; s="${s//_/\/}"
    mod=$(( ${#s} % 4 ))
    (( mod == 2 )) && s="${s}=="
    (( mod == 3 )) && s="${s}="
    (( mod == 1 )) && return 1
    printf '%s' "$s" | base64 -d 2>/dev/null
}

# ---- 交互输入 ----
REPLY_PORT=""
ask_port_with_default() {
    local prompt="${1:-监听端口}" def="$2" p
    while true; do
        read -rp "$(echo -e "${CYAN}${prompt} (回车使用: ${def}): ${NC}")" p
        [[ -z "$p" ]] && p="$def"
        if ! [[ "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then err "  端口无效, 请输入 1-65535。"; continue; fi
        if port_used "$p"; then err "  端口 $p 已被占用, 请换一个。"; continue; fi
        REPLY_PORT="$p"; return 0
    done
}

ask_port() {
    local prompt="${1:-监听端口}" p
    p="$(random_port)"; while port_used "$p"; do p="$(random_port)"; done
    ask_port_with_default "$prompt" "$p"
    ok "  使用端口: $REPLY_PORT"
}

REPLY_SNI=""
ask_sni() {
    local s def
    def="${REALITY_SNIS[$((RANDOM % ${#REALITY_SNIS[@]}))]}"
    read -rp "$(echo -e "${CYAN}Reality 伪装域名 SNI (回车使用: ${def}): ${NC}")" s
    [[ -z "$s" ]] && s="$def"
    REPLY_SNI="$s"; ok "  使用伪装域名: $REPLY_SNI"
}

ask_tls_sni() {
    local s def="${1:-www.bing.com}"
    read -rp "$(echo -e "${CYAN}TLS SNI (回车使用: ${def}): ${NC}")" s
    REPLY_SNI="${s:-$def}"
    ok "  使用 TLS SNI: $REPLY_SNI"
}

REPLY_NAME=""
ask_name() {
    local def="$1" n
    read -rp "$(echo -e "${CYAN}节点备注名 (回车使用: ${def}): ${NC}")" n
    REPLY_NAME="${n:-$def}"
}

REPLY_VALUE=""
ask_value_default() {
    local prompt="$1" def="$2" v
    read -rp "$(echo -e "${CYAN}${prompt} (回车使用: ${def}): ${NC}")" v
    REPLY_VALUE="${v:-$def}"
}

ask_plain_default() {
    ask_value_default "$1" "$2"
}

ask_int_default() {
    local prompt="$1" def="$2" min="${3:-1}" max="${4:-65535}" v
    while true; do
        ask_value_default "$prompt" "$def"; v="$REPLY_VALUE"
        [[ "$v" =~ ^[0-9]+$ ]] || { err "${prompt}必须是数字。"; continue; }
        (( v >= min && v <= max )) || { err "${prompt}范围应为 ${min}-${max}。"; continue; }
        REPLY_VALUE="$v"; return 0
    done
}

REPLY_UUID=""
ask_uuid_value() {
    local prompt="${1:-UUID}" def v
    def="$(gen_uuid)"
    while true; do
        ask_value_default "$prompt" "$def"; v="$REPLY_VALUE"
        [[ "$v" =~ ^[0-9a-fA-F-]{32,36}$ ]] || { err "UUID 格式不正确。"; continue; }
        REPLY_UUID="$v"; return 0
    done
}

REPLY_PASS=""
ask_secret_value() {
    local prompt="${1:-密码}" def="${2:-$(gen_pass 16)}" v
    while true; do
        ask_value_default "$prompt" "$def"; v="$REPLY_VALUE"
        [[ "$v" == *":"* || "$v" == *"/"* || "$v" == *"?"* || "$v" == *"&"* || "$v" == *"@"* || "$v" == *"#"* || "$v" == *" "* ]] && { err "${prompt}不能包含 :、/、?、&、@、# 或空格。"; continue; }
        REPLY_PASS="$v"; return 0
    done
}

REPLY_USER=""
ask_username_value() {
    local prompt="${1:-用户名}" def="${2:-user$(openssl rand -hex 2)}" v
    while true; do
        ask_value_default "$prompt" "$def"; v="$REPLY_VALUE"
        [[ "$v" == *":"* || "$v" == *"/"* || "$v" == *"?"* || "$v" == *"&"* || "$v" == *"@"* || "$v" == *"#"* || "$v" == *" "* ]] && { err "${prompt}不能包含 :、/、?、&、@、# 或空格。"; continue; }
        REPLY_USER="$v"; return 0
    done
}

REPLY_SHORT_ID=""
ask_short_id_value() {
    local def v
    def="$(gen_short_id)"
    while true; do
        ask_value_default "Reality ShortID" "$def"; v="$REPLY_VALUE"
        [[ "$v" =~ ^[0-9a-fA-F]{0,16}$ ]] || { err "ShortID 必须是 0-16 位十六进制。"; continue; }
        REPLY_SHORT_ID="$v"; return 0
    done
}

REPLY_PATH=""
ask_path_value() {
    local prompt="${1:-Path}" def v
    def="/$(openssl rand -hex 4)"
    read -rp "$(echo -e "${CYAN}${prompt} (回车使用: ${def}): ${NC}")" v
    v="${v:-$def}"
    [[ "$v" == /* ]] || v="/${v}"
    REPLY_PATH="$v"
}

REPLY_SERVICE=""
ask_service_value() {
    local prompt="${1:-gRPC serviceName}" def v
    def="grpc$(openssl rand -hex 3)"
    ask_value_default "$prompt" "$def"
    REPLY_SERVICE="$REPLY_VALUE"
}

confirm() {
    local prompt="${1:-确认继续?}" def="${2:-n}" ans
    if [[ "$def" == "y" ]]; then read -rp "$(echo -e "${YELLOW}${prompt} [Y/n]: ${NC}")" ans; ans="${ans:-y}"
    else read -rp "$(echo -e "${YELLOW}${prompt} [y/N]: ${NC}")" ans; ans="${ans:-n}"; fi
    [[ "$ans" =~ ^[Yy]$ ]]
}

pause() { echo; read -n1 -s -r -p "$(echo -e "${DIM}按任意键返回菜单...${NC}")"; echo; }
break_end() { echo -e "${GREEN}操作完成${NC}"; pause; }

# ---------------------------------------------------------------------------
# 五、内核安装 / 服务管理
# ---------------------------------------------------------------------------
sb_installed() { [[ -x "$SB_BIN" ]]; }
sb_running()   { systemctl is-active --quiet "$SB_SERVICE" 2>/dev/null; }
sb_version()   { sb_installed && "$SB_BIN" version 2>/dev/null | head -n1 | awk '{print $3}'; }

xray_installed() { [[ -x "$XRAY_BIN" ]]; }
xray_running()   { systemctl is-active --quiet "$XRAY_SERVICE" 2>/dev/null; }
xray_version()   { xray_installed && "$XRAY_BIN" version 2>/dev/null | head -n1 | awk '{print $2}'; }

# ---- sing-box ----
install_singbox() {
    info "正在获取 sing-box 最新版本..."
    local tag ver url tmp dir
    tag="$(curl -fsSL --max-time 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r '.tag_name // empty')"
    [[ -z "$tag" ]] && { err "无法获取 sing-box 版本 (GitHub API 失败), 请检查网络。"; return 1; }
    ver="${tag#v}"
    url="https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${ver}-linux-${SB_ARCH}.tar.gz"
    info "下载 sing-box ${tag} (${SB_ARCH})..."
    tmp="$(mktemp -d)"
    curl -fL --max-time 120 "$url" -o "$tmp/sb.tar.gz" || { err "下载失败: $url"; rm -rf "$tmp"; return 1; }
    tar -xzf "$tmp/sb.tar.gz" -C "$tmp" || { err "解压失败。"; rm -rf "$tmp"; return 1; }
    dir="$(find "$tmp" -maxdepth 1 -type d -name 'sing-box-*' | head -n1)"
    [[ -f "$dir/sing-box" ]] || { err "未找到 sing-box 可执行文件。"; rm -rf "$tmp"; return 1; }
    install -m 755 "$dir/sing-box" "$SB_BIN" || { err "安装二进制失败。"; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
    mkdir -p "$SB_DIR" "$SB_CERT_DIR" "$STATE_DIR"
    init_sb_config; init_state; write_sb_service
    ok "sing-box ${tag} 安装完成。"
}

write_sb_service() {
    if pm_has_systemd; then
        mkdir -p "$(dirname "$SB_SERVICE_FILE")"
        cat > "$SB_SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
WorkingDirectory=${SB_DIR}
ExecStart=${SB_BIN} run -c ${SB_CONFIG}
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    fi
    pm_write_openrc_service "$SB_SERVICE" "sing-box service" "$SB_BIN" "run -c ${SB_CONFIG}"
    systemctl daemon-reload
    systemctl enable "$SB_SERVICE" >/dev/null 2>&1
}

require_singbox() { sb_installed && return 0; warn "尚未安装 sing-box, 现在开始安装..."; install_singbox; }

restart_singbox() {
    systemctl restart "$SB_SERVICE" 2>/dev/null; sleep 1
    if sb_running; then ok "sing-box 服务运行中。"; return 0
    else err "sing-box 启动失败! 最近日志:"; journalctl -u "$SB_SERVICE" -n 15 --no-pager 2>/dev/null | sed 's/^/    /'; return 1; fi
}

# ---- Xray ----
install_xray() {
    info "正在获取 Xray 最新版本..."
    command -v unzip >/dev/null 2>&1 || pkg_install unzip
    local tag url tmp
    tag="$(curl -fsSL --max-time 15 https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null | jq -r '.tag_name // empty')"
    [[ -z "$tag" ]] && { err "无法获取 Xray 版本 (GitHub API 失败), 请检查网络。"; return 1; }
    url="https://github.com/XTLS/Xray-core/releases/download/${tag}/Xray-linux-${XRAY_ARCH}.zip"
    info "下载 Xray ${tag} (linux-${XRAY_ARCH})..."
    tmp="$(mktemp -d)"
    curl -fL --max-time 120 "$url" -o "$tmp/xray.zip" || { err "下载失败: $url"; rm -rf "$tmp"; return 1; }
    unzip -oq "$tmp/xray.zip" -d "$tmp" || { err "解压失败。"; rm -rf "$tmp"; return 1; }
    [[ -f "$tmp/xray" ]] || { err "未找到 xray 可执行文件。"; rm -rf "$tmp"; return 1; }
    install -m 755 "$tmp/xray" "$XRAY_BIN" || { err "安装二进制失败。"; rm -rf "$tmp"; return 1; }
    mkdir -p "$XRAY_SHARE"
    [[ -f "$tmp/geoip.dat" ]]   && install -m 644 "$tmp/geoip.dat"   "$XRAY_SHARE/"
    [[ -f "$tmp/geosite.dat" ]] && install -m 644 "$tmp/geosite.dat" "$XRAY_SHARE/"
    rm -rf "$tmp"
    mkdir -p "$XRAY_DIR" "$STATE_DIR"
    init_xray_config; init_state; write_xray_service
    ok "Xray ${tag} 安装完成。"
}

write_xray_service() {
    if pm_has_systemd; then
        mkdir -p "$(dirname "$XRAY_SERVICE_FILE")"
        cat > "$XRAY_SERVICE_FILE" <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=${XRAY_BIN} run -config ${XRAY_CONFIG}
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
Environment=XRAY_LOCATION_ASSET=${XRAY_SHARE}

[Install]
WantedBy=multi-user.target
EOF
    fi
    pm_write_openrc_service "$XRAY_SERVICE" "Xray Service" "$XRAY_BIN" "run -config ${XRAY_CONFIG}" "export XRAY_LOCATION_ASSET=${XRAY_SHARE}"
    systemctl daemon-reload
    systemctl enable "$XRAY_SERVICE" >/dev/null 2>&1
}

require_xray() { xray_installed && return 0; warn "尚未安装 Xray, 现在开始安装..."; install_xray; }

restart_xray() {
    systemctl restart "$XRAY_SERVICE" 2>/dev/null; sleep 1
    if xray_running; then ok "Xray 服务运行中。"; return 0
    else err "Xray 启动失败! 最近日志:"; journalctl -u "$XRAY_SERVICE" -n 15 --no-pager 2>/dev/null | sed 's/^/    /'; return 1; fi
}

# ---------------------------------------------------------------------------
# 六、配置 / 状态基础操作
# ---------------------------------------------------------------------------
init_sb_config() {
    [[ -f "$SB_CONFIG" ]] && return 0
    cat > "$SB_CONFIG" <<'EOF'
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
    chmod 600 "$SB_CONFIG"
}

init_xray_config() {
    [[ -f "$XRAY_CONFIG" ]] && return 0
    cat > "$XRAY_CONFIG" <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}
EOF
    chmod 600 "$XRAY_CONFIG"
}

init_state() {
    mkdir -p "$STATE_DIR"
    [[ -f "$STATE" ]] && return 0
    echo '{ "meta": {}, "nodes": {} }' > "$STATE"
    chmod 600 "$STATE"
}

ensure_cert() {
    [[ -f "$SB_CERT" && -f "$SB_KEY" ]] && return 0
    mkdir -p "$SB_CERT_DIR"
    info "生成自签名 TLS 证书 (CN=www.bing.com)..."
    openssl ecparam -genkey -name prime256v1 -out "$SB_KEY" >/dev/null 2>&1
    openssl req -new -x509 -days 36500 -key "$SB_KEY" -out "$SB_CERT" -subj "/CN=www.bing.com" >/dev/null 2>&1
    chmod 600 "$SB_KEY" "$SB_CERT"
}

# 核心: 向指定内核配置追加 inbound, 校验+应用, 失败回滚
# 用法: core_add_inbounds <singbox|xray> '<inbound_json>' ['<inbound_json2>'...]
core_add_inbounds() {
    local core="$1"; shift
    local cfg tmp jq_args=() prog='.inbounds += [' i=0 arg
    case "$core" in
        singbox) cfg="$SB_CONFIG" ;;
        xray)    cfg="$XRAY_CONFIG" ;;
        *) err "未知内核: $core"; return 1 ;;
    esac
    for arg in "$@"; do
        jq_args+=(--argjson "inb$i" "$arg")
        [[ $i -gt 0 ]] && prog+=', '
        prog+="\$inb$i"; ((i++))
    done
    prog+=']'
    tmp="$(mktemp_json)" || { err "创建临时配置文件失败。"; return 1; }
    if ! jq "${jq_args[@]}" "$prog" "$cfg" > "$tmp"; then err "生成配置失败 (jq)。"; rm -f "$tmp"; return 1; fi

    if [[ "$core" == singbox ]]; then
        if ! "$SB_BIN" check -c "$tmp" 2>/tmp/pm_check.log; then
            err "配置校验未通过, 已放弃修改:"; sed 's/^/    /' /tmp/pm_check.log; rm -f "$tmp"; return 1
        fi
    else
        if ! "$XRAY_BIN" -test -config "$tmp" >/tmp/pm_check.log 2>&1; then
            err "配置校验未通过, 已放弃修改:"; sed 's/^/    /' /tmp/pm_check.log; rm -f "$tmp"; return 1
        fi
    fi

    cp "$cfg" "${cfg}.bak" 2>/dev/null
    mv "$tmp" "$cfg"; chmod 600 "$cfg"
    if ! core_restart "$core"; then
        warn "启动失败, 回滚配置..."; mv "${cfg}.bak" "$cfg" 2>/dev/null; core_restart "$core"; return 1
    fi
    return 0
}

core_restart() { case "$1" in singbox) restart_singbox ;; xray) restart_xray ;; esac; }

choose_same_type_policy() {
    local type="$1" tag="$2" existing choice t
    [[ -f "$STATE" ]] || return 0
    existing="$(jq -r --arg type "$type" --arg tag "$tag" '.nodes | to_entries[] | select(.key != $tag and .value.type == $type) | .key' "$STATE" 2>/dev/null)"
    [[ -z "$existing" ]] && return 0

    echo
    warn "检测到已存在同类型节点 [${type}], 请选择处理方式:"
    echo -e "  ${GREEN}1.${NC} 新增共存 ${DIM}(默认, 不影响已有节点)${NC}"
    echo -e "  ${GREEN}2.${NC} 覆盖旧节点 ${DIM}(删除已有同类型节点后保留新节点)${NC}"
    read -rp "$(echo -e "${CYAN}请选择 (默认: 1): ${NC}")" choice
    [[ "$choice" == "2" ]] || return 0

    while IFS= read -r t; do
        [[ -z "$t" ]] && continue
        delete_node "$t" || warn "旧节点 ${t} 删除失败, 已保留为共存节点。"
    done <<< "$existing"
}

# save_node <core> <tag> <type> <name> <link> <detail> [extra_tag]
save_node() {
    LAST_NODE_TYPE="$3"
    init_state
    choose_same_type_policy "$3" "$2"
    local tmp; tmp="$(mktemp)"
    jq --arg core "$1" --arg tag "$2" --arg type "$3" --arg name "$4" \
       --arg link "$5" --arg detail "$6" --arg extra "${7:-}" \
       '.nodes[$tag] = {core:$core, type:$type, name:$name, link:$link, detail:$detail, extra_tag:$extra}' \
       "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    chmod 600 "$STATE"
}

# ---------------------------------------------------------------------------
# 七、Reality / VLESS 加密 密钥生成
# ---------------------------------------------------------------------------
XRAY_REALITY_PRIV=""; XRAY_REALITY_PUB=""
gen_xray_reality_keys() {
    local out; out="$("$XRAY_BIN" x25519 2>/dev/null)"
    XRAY_REALITY_PRIV="$(echo "$out" | grep -iE 'private' | head -n1 | awk -F: '{gsub(/[[:space:]]/,"",$2);print $2}')"
    XRAY_REALITY_PUB="$(echo "$out"  | grep -iE 'public'  | head -n1 | awk -F: '{gsub(/[[:space:]]/,"",$2);print $2}')"
    # 新版 Xray 可能用 Password 表示公钥
    [[ -z "$XRAY_REALITY_PUB" ]] && XRAY_REALITY_PUB="$(echo "$out" | grep -iE 'password' | head -n1 | awk -F: '{gsub(/[[:space:]]/,"",$2);print $2}')"
    [[ -n "$XRAY_REALITY_PRIV" && -n "$XRAY_REALITY_PUB" ]]
}

ask_xray_reality_keys() {
    local priv pub
    read -rp "$(echo -e "${CYAN}Reality PrivateKey (回车自动生成): ${NC}")" priv
    if [[ -z "$priv" ]]; then
        gen_xray_reality_keys || return 1
        ok "  Reality key 已自动生成。"
        return 0
    fi
    read -rp "$(echo -e "${CYAN}Reality PublicKey (手动 PrivateKey 时必填): ${NC}")" pub
    [[ -z "$pub" ]] && { err "手动 Reality PrivateKey 时必须填写 PublicKey, 用于客户端分享链接。"; return 1; }
    XRAY_REALITY_PRIV="$priv"; XRAY_REALITY_PUB="$pub"
}

# VLESS Encryption: 生成 decryption(服务端)/encryption(客户端), 取 X25519 组
XRAY_VLESS_DEC=""; XRAY_VLESS_ENC=""
gen_xray_vless_enc() {
    local out; out="$("$XRAY_BIN" vlessenc 2>/dev/null)"
    XRAY_VLESS_DEC="$(echo "$out" | grep -m1 '"decryption"' | sed -E 's/.*"decryption": *"([^"]+)".*/\1/')"
    XRAY_VLESS_ENC="$(echo "$out" | grep -m1 '"encryption"' | sed -E 's/.*"encryption": *"([^"]+)".*/\1/')"
    [[ -n "$XRAY_VLESS_DEC" && -n "$XRAY_VLESS_ENC" ]]
}

ask_xray_vless_enc() {
    local dec enc
    read -rp "$(echo -e "${CYAN}VLESS decryption (回车自动生成): ${NC}")" dec
    if [[ -z "$dec" ]]; then
        gen_xray_vless_enc || return 1
        ok "  VLESS 加密参数已自动生成。"
        return 0
    fi
    read -rp "$(echo -e "${CYAN}VLESS encryption (手动 decryption 时必填): ${NC}")" enc
    [[ -z "$enc" ]] && { err "手动 VLESS decryption 时必须填写 encryption。"; return 1; }
    XRAY_VLESS_DEC="$dec"; XRAY_VLESS_ENC="$enc"
}

# ---------------------------------------------------------------------------
# 八、结果展示
# ---------------------------------------------------------------------------
show_result() {
    local name="$1" link="$2" detail="${3:-}"
    echo; hr; ok "  ✅ ${name} 部署成功!"; hr
    echo -e "${BOLD}分享链接:${NC}"; echo -e "${GREEN}${link}${NC}"; echo
    local cy; cy="$(clash_node_yaml "${LAST_NODE_TYPE:-}" "$name" "$link")"
    if [[ -n "$cy" ]]; then
        echo; echo -e "${BOLD}Mihomo 配置:${NC}"
        echo -e "${GREEN}${cy}${NC}"
    fi
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${BOLD}二维码, 客户端扫码导入:${NC}"; qrencode -t ANSIUTF8 "$link"
    else
        warn "未安装 qrencode, 跳过二维码。"
    fi
    hr
}

# ===========================================================================
#  九、Xray 协议 (XHTTP 系列为 Xray 独有卖点)
# ===========================================================================

# --- Xray: VLESS-XHTTP-Reality -------------------------------------------
add_xray_xhttp_reality() {
    require_xray || return 1
    echo -e "\n${BLUE}${BOLD}VLESS-XHTTP-Reality${NC} Xray 独有传输, 抗封锁抗探测"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_sni;             local sni="$REPLY_SNI"
    ask_name "XHTTP-Reality-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_short_id_value; local sid="$REPLY_SHORT_ID"
    ask_path_value "XHTTP Path"; local path="$REPLY_PATH"
    ask_xray_reality_keys || { err "Xray Reality 密钥生成失败。"; return 1; }
    local tag="xray-xhttp-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" \
        --arg sni "$sni" --arg pk "$XRAY_REALITY_PRIV" --arg sid "$sid" --arg path "$path" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid}], decryption:"none" },
        streamSettings:{
            network:"xhttp", security:"reality",
            realitySettings:{ show:false, dest:($sni+":443"), xver:0,
                              serverNames:[$sni], privateKey:$pk, shortIds:[$sid] },
            xhttpSettings:{ path:$path, mode:"auto" }
        },
        sniffing:{ enabled:true, destOverride:["http","tls"] }
    }')"
    core_add_inbounds "xray" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="vless://${uuid}@${host}:${port}?encryption=none&security=reality&sni=$(url_encode "$sni")&fp=chrome&pbk=${XRAY_REALITY_PUB}&sid=${sid}&type=xhttp&path=$(url_encode "$path")&mode=auto#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: XHTTP  Path: ${path}\n  SNI : ${sni}\n  公钥: ${XRAY_REALITY_PUB}\n  ShortID: ${sid}\n  指纹: chrome"
    save_node "xray" "$tag" "VLESS-XHTTP-Reality" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- Xray: VLESS-Vision-Reality (经典 TCP) -------------------------------
add_xray_vision_reality() {
    require_xray || return 1
    echo -e "\n${BLUE}${BOLD}VLESS-Reality-Vision${NC} 抗封锁首选"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_sni;             local sni="$REPLY_SNI"
    ask_name "Xray-Vision-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_short_id_value; local sid="$REPLY_SHORT_ID"
    ask_xray_reality_keys || { err "Xray Reality 密钥生成失败。"; return 1; }
    local tag="xray-vision-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" \
        --arg sni "$sni" --arg pk "$XRAY_REALITY_PRIV" --arg sid "$sid" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid, flow:"xtls-rprx-vision"}], decryption:"none" },
        streamSettings:{
            network:"tcp", security:"reality",
            realitySettings:{ show:false, dest:($sni+":443"), xver:0,
                              serverNames:[$sni], privateKey:$pk, shortIds:[$sid] }
        },
        sniffing:{ enabled:true, destOverride:["http","tls"] }
    }')"
    core_add_inbounds "xray" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$(url_encode "$sni")&fp=chrome&pbk=${XRAY_REALITY_PUB}&sid=${sid}&type=tcp#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  Flow: xtls-rprx-vision\n  SNI : ${sni}\n  公钥: ${XRAY_REALITY_PUB}\n  ShortID: ${sid}\n  指纹: chrome"
    save_node "xray" "$tag" "VLESS-Reality-Vision" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- Xray: VLESS-Encryption (原生加密, 抗量子) ----------------------------
add_xray_vless_encryption() {
    require_xray || return 1
    echo -e "\n${BLUE}${BOLD}VLESS-Encryption${NC} Xray 原生加密, 需 v25.9.5+ 客户端"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "VLESS-Enc-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_xray_vless_enc || { err "生成 VLESS 加密参数失败, 请确认 Xray 版本 >= v25.9.5 (菜单可更新 Xray)。"; return 1; }
    local dec="$XRAY_VLESS_DEC" enc="$XRAY_VLESS_ENC"
    local tag="xray-vlessenc-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg dec "$dec" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid}], decryption:$dec },
        streamSettings:{ network:"raw", security:"none" },
        sniffing:{ enabled:true, destOverride:["http","tls"] }
    }')"
    core_add_inbounds "xray" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="vless://${uuid}@${host}:${port}?encryption=$(url_encode "$enc")&type=tcp#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: raw(tcp)  安全: VLESS 原生加密\n  encryption(客户端): ${enc}\n  注意: 需 Xray/v2rayN v25.9.5+; sing-box 客户端暂不支持"
    save_node "xray" "$tag" "VLESS-Encryption" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# ===========================================================================
#  十、VLESS / VMess / Trojan / Shadowsocks 协议 (Xray 内核)
# ===========================================================================

# --- VLESS-gRPC-Reality ---
add_vless_grpc_reality() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}VLESS-gRPC-Reality${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_sni;             local sni="$REPLY_SNI"
    ask_name "VLESS-gRPC-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_short_id_value; local sid="$REPLY_SHORT_ID"
    ask_service_value "gRPC serviceName"; local svc="$REPLY_SERVICE"
    ask_xray_reality_keys || { err "Reality 密钥生成失败。"; return 1; }
    local tag="vless-grpc-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" \
        --arg sni "$sni" --arg pk "$XRAY_REALITY_PRIV" --arg sid "$sid" --arg svc "$svc" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid}], decryption:"none" },
        streamSettings:{ network:"grpc", grpcSettings:{ serviceName:$svc },
            security:"reality", realitySettings:{ show:false, dest:($sni+":443"), xver:0,
                serverNames:[$sni], privateKey:$pk, shortIds:[$sid] } },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="vless://${uuid}@${host}:${port}?encryption=none&security=reality&sni=$(url_encode "$sni")&fp=chrome&pbk=${XRAY_REALITY_PUB}&sid=${sid}&type=grpc&serviceName=$(url_encode "$svc")&mode=gun#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  SNI : ${sni}\n  公钥: ${XRAY_REALITY_PUB}\n  ShortID: ${sid}\n  gRPC serviceName: ${svc}"
    save_node "xray" "$tag" "VLESS-gRPC-Reality" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- VLESS-Encryption-XHTTP ---
add_vless_encryption_xhttp() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}VLESS-Encryption-XHTTP${NC} 需 Xray/v2rayN v25.9.5+ 客户端"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "VLESS-Enc-XHTTP-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_path_value "XHTTP Path"; local path="$REPLY_PATH"
    ask_xray_vless_enc || { err "VLESS 加密参数生成失败, 请确认 Xray >= v25.9.5。"; return 1; }
    local tag="vless-enc-xhttp-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg dec "$XRAY_VLESS_DEC" --arg path "$path" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid}], decryption:$dec },
        streamSettings:{ network:"xhttp", xhttpSettings:{ path:$path, mode:"auto" }, security:"none" },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="vless://${uuid}@${host}:${port}?encryption=$(url_encode "$XRAY_VLESS_ENC")&type=xhttp&path=$(url_encode "$path")&mode=auto#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: XHTTP  Path: ${path}\n  安全: VLESS 原生加密\n  encryption: ${XRAY_VLESS_ENC}\n  注意: 需 v25.9.5+ 客户端, sing-box 客户端暂不支持"
    save_node "xray" "$tag" "VLESS-Encryption-XHTTP" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- VLESS-(WS/gRPC/H2/XHTTP)-TLS ---------------------------------------
add_vless_tls() {
    local transport="$1"
    require_xray || return 1; ensure_cert
    local label default_name tag_prefix
    case "$transport" in
        ws)    label="VLESS-WS-TLS";    default_name="VLESS-WS";    tag_prefix="vless-ws-tls" ;;
        grpc)  label="VLESS-gRPC-TLS";  default_name="VLESS-gRPC";  tag_prefix="vless-grpc-tls" ;;
        h2)    label="VLESS-H2-TLS";    default_name="VLESS-H2";    tag_prefix="vless-h2-tls" ;;
        xhttp) label="VLESS-XHTTP-TLS"; default_name="VLESS-XHTTP"; tag_prefix="vless-xhttp-tls" ;;
        *) err "未知 VLESS TLS 传输: $transport"; return 1 ;;
    esac

    echo -e "\n${MAGENTA}${BOLD}${label}${NC} 自签证书模式, 客户端需允许不安全证书"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_tls_sni;          local sni="$REPLY_SNI"
    ask_name "${default_name}-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    local host path svc stream link transport_desc tag
    host="$(server_host)"
    tag="${tag_prefix}-${port}"

    case "$transport" in
        ws)
            ask_path_value "WebSocket Path"; path="$REPLY_PATH"
            stream="$(jq -cn --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg path "$path" '{
                network:"ws", security:"tls",
                tlsSettings:{alpn:["http/1.1"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                wsSettings:{path:$path}
            }')"
            link="vless://${uuid}@${host}:${port}?encryption=none&security=tls&sni=$(url_encode "$sni")&allowInsecure=1&type=ws&host=$(url_encode "$sni")&path=$(url_encode "$path")#$(url_encode "$name")"
            transport_desc="WebSocket  Path: ${path}"
            ;;
        grpc)
            ask_service_value "gRPC serviceName"; svc="$REPLY_SERVICE"
            stream="$(jq -cn --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg svc "$svc" '{
                network:"grpc", security:"tls",
                tlsSettings:{alpn:["h2"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                grpcSettings:{serviceName:$svc}
            }')"
            link="vless://${uuid}@${host}:${port}?encryption=none&security=tls&sni=$(url_encode "$sni")&allowInsecure=1&type=grpc&serviceName=$(url_encode "$svc")&mode=gun#$(url_encode "$name")"
            transport_desc="gRPC serviceName: ${svc}"
            ;;
        h2)
            ask_path_value "HTTP/2 Path"; path="$REPLY_PATH"
            stream="$(jq -cn --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg path "$path" '{
                network:"http", security:"tls",
                tlsSettings:{alpn:["h2"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                httpSettings:{host:[$sni], path:$path}
            }')"
            link="vless://${uuid}@${host}:${port}?encryption=none&security=tls&sni=$(url_encode "$sni")&allowInsecure=1&type=http&host=$(url_encode "$sni")&path=$(url_encode "$path")#$(url_encode "$name")"
            transport_desc="HTTP/2  Path: ${path}"
            ;;
        xhttp)
            ask_path_value "XHTTP Path"; path="$REPLY_PATH"
            stream="$(jq -cn --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg path "$path" '{
                network:"xhttp", security:"tls",
                tlsSettings:{alpn:["h2","http/1.1"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                xhttpSettings:{path:$path, mode:"auto"}
            }')"
            link="vless://${uuid}@${host}:${port}?encryption=none&security=tls&sni=$(url_encode "$sni")&allowInsecure=1&type=xhttp&path=$(url_encode "$path")&mode=auto#$(url_encode "$name")"
            transport_desc="XHTTP  Path: ${path}  Mode: auto"
            ;;
    esac

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --argjson stream "$stream" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid}], decryption:"none" },
        streamSettings:$stream,
        sniffing:{ enabled:true, destOverride:["http","tls"] }
    }')"
    core_add_inbounds "xray" "$inbound" || return 1

    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: ${transport_desc}\n  TLS SNI: ${sni}\n  证书: 自签名, 客户端需开启 allowInsecure/跳过证书验证"
    save_node "xray" "$tag" "$label" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- VLESS-Encryption-XHTTP-FinalMask (官方 Xray v26.3.27+ finalmask) ---
add_vless_enc_xhttp_finalmask() {
    require_xray || return 1
    echo -e "\n${BLUE}${BOLD}VLESS-Encryption-XHTTP-FinalMask${NC} 需 Xray v26.3.27+ 客户端"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "ENC-XHTTP-FM-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_path_value "XHTTP Path"; local path="$REPLY_PATH"
    ask_xray_vless_enc || { err "VLESS 加密参数生成失败, 需 Xray >= v25.9.5。"; return 1; }
    local fm='{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20","maxSplit":"3-6"}}]}'
    local fm_uri; fm_uri="$(jq -crn --argjson v "$fm" '$v|tojson|@uri')"
    local tag="vless-enc-xhttp-fm-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg dec "$XRAY_VLESS_DEC" --arg path "$path" --argjson fm "$fm" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid}], decryption:$dec },
        streamSettings:{ network:"xhttp", security:"none", xhttpSettings:{path:$path}, finalmask:$fm },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }')"
    core_add_inbounds "xray" "$inbound" || { err "若校验失败, 可能 Xray 内核过旧不支持 finalmask, 请用菜单更新 Xray。"; return 1; }
    local host; host="$(server_host)"
    local link="vless://${uuid}@${host}:${port}?type=xhttp&security=none&path=$(url_encode "$path")&encryption=$(url_encode "$XRAY_VLESS_ENC")&fm=${fm_uri}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: XHTTP  Path: ${path}\n  FinalMask: fragment/tlshello\n  encryption: ${XRAY_VLESS_ENC}\n  注意: 客户端需 Xray v26.3.27+; fm 为非标准参数, 多数 GUI 需手动补 finalmask 块; sing-box 不支持"
    save_node "xray" "$tag" "VLESS-Enc-XHTTP-FinalMask" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- VLESS-Encryption-FinalMask (sudoku, TCP) ---
add_vless_enc_finalmask() {
    require_xray || return 1
    echo -e "\n${BLUE}${BOLD}VLESS-Encryption-FinalMask sudoku${NC} 需 Xray v26.3.27+ 客户端"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "ENC-FM-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_xray_vless_enc || { err "VLESS 加密参数生成失败, 需 Xray >= v25.9.5。"; return 1; }
    ask_secret_value "FinalMask sudoku 密码" "$(gen_pass 16)"; local spw="$REPLY_PASS"
    local fm; fm="$(jq -cn --arg pw "$spw" '{tcp:[{type:"sudoku",settings:{password:$pw,ascii:"prefer_ascii",paddingMin:0,paddingMax:3}}]}')"
    local fm_uri; fm_uri="$(jq -crn --argjson v "$fm" '$v|tojson|@uri')"
    local tag="vless-enc-fm-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg dec "$XRAY_VLESS_DEC" --argjson fm "$fm" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid}], decryption:$dec },
        streamSettings:{ network:"tcp", security:"none", finalmask:$fm },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }')"
    core_add_inbounds "xray" "$inbound" || { err "若校验失败, 可能 Xray 内核过旧, 请更新 Xray。"; return 1; }
    local host; host="$(server_host)"
    local link="vless://${uuid}@${host}:${port}?type=tcp&security=none&encryption=$(url_encode "$XRAY_VLESS_ENC")&fm=${fm_uri}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: TCP\n  FinalMask: sudoku\n  sudoku 密码: ${spw}\n  encryption: ${XRAY_VLESS_ENC}\n  注意: 客户端需 Xray v26.3.27+; fm 非标准需手动补; sing-box 不支持"
    save_node "xray" "$tag" "VLESS-Enc-FinalMask" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- FullStack: VLESS Encryption + XHTTP + REALITY + FinalMask ---
add_vless_fullstack() {
    require_xray || return 1
    echo -e "\n${BLUE}${BOLD}FullStack REALITY+XHTTP+加密+FinalMask${NC} 需 Xray v26.3.27+ 客户端"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_sni;             local sni="$REPLY_SNI"
    ask_name "FullStack-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_path_value "XHTTP Path"; local path="$REPLY_PATH"
    ask_short_id_value; local sid="$REPLY_SHORT_ID"
    ask_xray_vless_enc || { err "VLESS 加密参数生成失败, 需 Xray >= v25.9.5。"; return 1; }
    ask_xray_reality_keys || { err "Reality 密钥生成失败。"; return 1; }
    local fm='{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20","maxSplit":"3-6"}}]}'
    local fm_uri; fm_uri="$(jq -crn --argjson v "$fm" '$v|tojson|@uri')"
    local tag="vless-fullstack-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg dec "$XRAY_VLESS_DEC" \
        --arg path "$path" --arg sni "$sni" --arg pk "$XRAY_REALITY_PRIV" --arg sid "$sid" --argjson fm "$fm" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vless",
        settings:{ clients:[{id:$uuid}], decryption:$dec },
        streamSettings:{ network:"xhttp", security:"reality",
            realitySettings:{ dest:($sni+":443"), show:false, xver:0, spiderX:"/", shortIds:[$sid], privateKey:$pk, serverNames:[$sni] },
            xhttpSettings:{ path:$path }, finalmask:$fm },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }')"
    core_add_inbounds "xray" "$inbound" || { err "若校验失败, 可能 Xray 内核过旧, 请更新 Xray。"; return 1; }
    local host; host="$(server_host)"
    local link="vless://${uuid}@${host}:${port}?type=xhttp&security=reality&path=$(url_encode "$path")&pbk=${XRAY_REALITY_PUB}&fp=chrome&sni=$(url_encode "$sni")&sid=${sid}&spx=%2F&encryption=$(url_encode "$XRAY_VLESS_ENC")&fm=${fm_uri}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: XHTTP  Path: ${path}\n  安全: REALITY + VLESS加密 + FinalMask\n  SNI: ${sni}  公钥: ${XRAY_REALITY_PUB}  ShortID: ${sid}\n  encryption: ${XRAY_VLESS_ENC}\n  注意: 客户端需 Xray v26.3.27+; fm 非标准需手动补; sing-box 不支持"
    save_node "xray" "$tag" "VLESS-FullStack" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- VMess-WebSocket ---
add_vmess_ws() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}VMess-WebSocket${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "VMess-WS-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "UUID"; local uuid="$REPLY_UUID"
    ask_path_value "WebSocket Path"; local path="$REPLY_PATH"
    local tag="vmess-ws-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg path "$path" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vmess",
        settings:{ clients:[{id:$uuid}] },
        streamSettings:{ network:"ws", wsSettings:{ path:$path } } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local vmjson
    vmjson="$(jq -cn --arg ps "$name" --arg add "$host" --arg port "$port" --arg id "$uuid" --arg path "$path" '{
        v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:"auto",
        net:"ws", type:"none", host:"", path:$path, tls:"" }')"
    local link="vmess://$(b64_line "$vmjson")"
    local detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: WebSocket  Path: ${path}\n  TLS : 无, 可自行套 CDN/Nginx"
    save_node "xray" "$tag" "VMess-WS" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

REPLY_HEADER=""
choose_vmess_header() {
    local transport="$1" c
    case "$transport" in
        tcp)
            echo -e "${CYAN}请选择 TCP 伪装类型:${NC}"
            echo -e "  ${GREEN}1.${NC} none ${DIM}(默认)${NC}"
            echo -e "  ${GREEN}2.${NC} http"
            read -rp "$(echo -e "${CYAN}请选择 (默认: 1): ${NC}")" c
            [[ "$c" == "2" ]] && REPLY_HEADER="http" || REPLY_HEADER="none"
            ;;
        kcp|quic)
            echo -e "${CYAN}请选择 ${transport^^} header 类型:${NC}"
            echo -e "  ${GREEN}1.${NC} none ${DIM}(默认)${NC}"
            echo -e "  ${GREEN}2.${NC} srtp"
            echo -e "  ${GREEN}3.${NC} utp"
            echo -e "  ${GREEN}4.${NC} wechat-video"
            echo -e "  ${GREEN}5.${NC} dtls"
            echo -e "  ${GREEN}6.${NC} wireguard"
            read -rp "$(echo -e "${CYAN}请选择 (默认: 1): ${NC}")" c
            case "$c" in
                2) REPLY_HEADER="srtp" ;;
                3) REPLY_HEADER="utp" ;;
                4) REPLY_HEADER="wechat-video" ;;
                5) REPLY_HEADER="dtls" ;;
                6) REPLY_HEADER="wireguard" ;;
                *) REPLY_HEADER="none" ;;
            esac
            ;;
        *) REPLY_HEADER="none" ;;
    esac
}

# --- VMess-(TCP/mKCP/QUIC) ----------------------------------------------
add_vmess_plain() {
    local transport="$1"
    require_xray || return 1
    local label default_name tag_prefix stream net vm_type transport_desc header
    case "$transport" in
        tcp)
            label="VMess-TCP"; default_name="VMess-TCP"; tag_prefix="vmess-tcp"; net="tcp"
            ;;
        kcp)
            label="VMess-mKCP"; default_name="VMess-mKCP"; tag_prefix="vmess-kcp"; net="kcp"
            ;;
        quic)
            label="VMess-QUIC"; default_name="VMess-QUIC"; tag_prefix="vmess-quic"; net="quic"
            ;;
        *) err "未知 VMess 传输: $transport"; return 1 ;;
    esac

    echo -e "\n${MAGENTA}${BOLD}${label}${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    choose_vmess_header "$transport"; header="$REPLY_HEADER"; vm_type="$header"
    ask_name "${default_name}-${port}"; local name="$REPLY_NAME"
    local uuid host tag inbound vmjson link detail
    ask_uuid_value "UUID"; uuid="$REPLY_UUID"; host="$(server_host)"; tag="${tag_prefix}-${port}"
    case "$transport" in
        tcp)
            stream="$(jq -cn --arg header "$header" '{network:"tcp",security:"none",tcpSettings:{header:{type:$header}}}')"
            transport_desc="TCP, header: ${header}"
            ;;
        kcp)
            stream="$(jq -cn --arg header "$header" '{network:"kcp",security:"none",kcpSettings:{header:{type:$header}}}')"
            transport_desc="mKCP UDP, header: ${header}"
            ;;
        quic)
            stream="$(jq -cn --arg header "$header" '{network:"quic",security:"none",quicSettings:{security:"none",key:"",header:{type:$header}}}')"
            transport_desc="QUIC UDP, security: none, header: ${header}"
            ;;
    esac
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --argjson stream "$stream" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vmess",
        settings:{ clients:[{id:$uuid, alterId:0}] },
        streamSettings:$stream,
        sniffing:{ enabled:true, destOverride:["http","tls"] }
    }')"
    core_add_inbounds "xray" "$inbound" || return 1

    vmjson="$(jq -cn --arg ps "$name" --arg add "$host" --arg port "$port" --arg id "$uuid" --arg net "$net" --arg type "$vm_type" '{
        v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:"auto",
        net:$net, type:$type, host:"", path:"", tls:""
    }')"
    link="vmess://$(b64_line "$vmjson")"
    detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: ${transport_desc}"
    save_node "xray" "$tag" "$label" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- VMess-(WS/gRPC/H2)-TLS ---------------------------------------------
add_vmess_tls() {
    local transport="$1"
    require_xray || return 1; ensure_cert
    local label default_name tag_prefix path svc stream net vm_type vm_path vm_host transport_desc
    case "$transport" in
        ws)   label="VMess-WS-TLS";   default_name="VMess-WS-TLS";   tag_prefix="vmess-ws-tls";   net="ws";   vm_type="none" ;;
        grpc) label="VMess-gRPC-TLS"; default_name="VMess-gRPC-TLS"; tag_prefix="vmess-grpc-tls"; net="grpc"; vm_type="gun" ;;
        h2)   label="VMess-H2-TLS";   default_name="VMess-H2-TLS";   tag_prefix="vmess-h2-tls";   net="h2";   vm_type="http" ;;
        *) err "未知 VMess TLS 传输: $transport"; return 1 ;;
    esac

    echo -e "\n${MAGENTA}${BOLD}${label}${NC} 自签证书模式, 客户端需允许不安全证书"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_tls_sni;          local sni="$REPLY_SNI"
    ask_name "${default_name}-${port}"; local name="$REPLY_NAME"
    local uuid host tag inbound vmjson link detail
    ask_uuid_value "UUID"; uuid="$REPLY_UUID"; host="$(server_host)"; tag="${tag_prefix}-${port}"; vm_host=""
    case "$transport" in
        ws)
            ask_path_value "WebSocket Path"; path="$REPLY_PATH"; vm_path="$path"; vm_host="$sni"
            stream="$(jq -cn --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg path "$path" '{
                network:"ws", security:"tls",
                tlsSettings:{alpn:["http/1.1"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                wsSettings:{path:$path}
            }')"
            transport_desc="WebSocket  Path: ${path}"
            ;;
        grpc)
            ask_service_value "gRPC serviceName"; svc="$REPLY_SERVICE"; vm_path="$svc"
            stream="$(jq -cn --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg svc "$svc" '{
                network:"grpc", security:"tls",
                tlsSettings:{alpn:["h2"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                grpcSettings:{serviceName:$svc}
            }')"
            transport_desc="gRPC serviceName: ${svc}"
            ;;
        h2)
            ask_path_value "HTTP/2 Path"; path="$REPLY_PATH"; vm_path="$path"; vm_host="$sni"
            stream="$(jq -cn --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg path "$path" '{
                network:"http", security:"tls",
                tlsSettings:{alpn:["h2"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                httpSettings:{host:[$sni], path:$path}
            }')"
            transport_desc="HTTP/2  Path: ${path}"
            ;;
    esac

    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --argjson stream "$stream" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"vmess",
        settings:{ clients:[{id:$uuid, alterId:0}] },
        streamSettings:$stream,
        sniffing:{ enabled:true, destOverride:["http","tls"] }
    }')"
    core_add_inbounds "xray" "$inbound" || return 1

    vmjson="$(jq -cn --arg ps "$name" --arg add "$host" --arg port "$port" --arg id "$uuid" \
        --arg net "$net" --arg type "$vm_type" --arg host "$vm_host" --arg path "$vm_path" --arg sni "$sni" '{
        v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:"auto",
        net:$net, type:$type, host:$host, path:$path, tls:"tls", sni:$sni, allowInsecure:"1"
    }')"
    link="vmess://$(b64_line "$vmjson")"
    detail="  地址: ${host}\n  端口: ${port}\n  UUID: ${uuid}\n  传输: ${transport_desc}\n  TLS SNI: ${sni}\n  证书: 自签名, 客户端需开启 allowInsecure/跳过证书验证"
    save_node "xray" "$tag" "$label" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- Trojan-Reality ---
add_trojan_reality() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}Trojan-Reality${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_sni;             local sni="$REPLY_SNI"
    ask_name "Trojan-Reality-${port}"; local name="$REPLY_NAME"
    ask_secret_value "Trojan 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS"
    ask_short_id_value; local sid="$REPLY_SHORT_ID"
    ask_xray_reality_keys || { err "Reality 密钥生成失败。"; return 1; }
    local tag="trojan-reality-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$pw" \
        --arg sni "$sni" --arg pk "$XRAY_REALITY_PRIV" --arg sid "$sid" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"trojan",
        settings:{ clients:[{password:$pw}] },
        streamSettings:{ network:"tcp", security:"reality", realitySettings:{ show:false, dest:($sni+":443"), xver:0,
            serverNames:[$sni], privateKey:$pk, shortIds:[$sid] } },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="trojan://${pw}@${host}:${port}?security=reality&sni=$(url_encode "$sni")&fp=chrome&pbk=${XRAY_REALITY_PUB}&sid=${sid}&type=tcp#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  密码: ${pw}\n  SNI : ${sni}\n  公钥: ${XRAY_REALITY_PUB}\n  ShortID: ${sid}"
    save_node "xray" "$tag" "Trojan-Reality" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- Trojan-(TCP/WS/gRPC/H2)-TLS ----------------------------------------
add_trojan_tls() {
    local transport="$1"
    require_xray || return 1; ensure_cert
    local label default_name tag_prefix path svc stream link transport_desc
    case "$transport" in
        tcp)  label="Trojan-TCP-TLS";  default_name="Trojan-TCP";  tag_prefix="trojan-tcp-tls" ;;
        ws)   label="Trojan-WS-TLS";   default_name="Trojan-WS";   tag_prefix="trojan-ws-tls" ;;
        grpc) label="Trojan-gRPC-TLS"; default_name="Trojan-gRPC"; tag_prefix="trojan-grpc-tls" ;;
        h2)   label="Trojan-H2-TLS";   default_name="Trojan-H2";   tag_prefix="trojan-h2-tls" ;;
        *) err "未知 Trojan TLS 传输: $transport"; return 1 ;;
    esac

    echo -e "\n${MAGENTA}${BOLD}${label}${NC} 自签证书模式, 客户端需允许不安全证书"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_tls_sni;          local sni="$REPLY_SNI"
    ask_name "${default_name}-${port}"; local name="$REPLY_NAME"
    local pw host tag inbound detail
    ask_secret_value "Trojan 密码" "$(gen_pass 16)"; pw="$REPLY_PASS"; host="$(server_host)"; tag="${tag_prefix}-${port}"

    case "$transport" in
        tcp)
            stream="$(jq -cn --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
                network:"tcp", security:"tls",
                tlsSettings:{alpn:["http/1.1"], certificates:[{certificateFile:$cert, keyFile:$key}]}
            }')"
            link="trojan://${pw}@${host}:${port}?security=tls&sni=$(url_encode "$sni")&allowInsecure=1&type=tcp#$(url_encode "$name")"
            transport_desc="TCP"
            ;;
        ws)
            ask_path_value "WebSocket Path"; path="$REPLY_PATH"
            stream="$(jq -cn --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg path "$path" '{
                network:"ws", security:"tls",
                tlsSettings:{alpn:["http/1.1"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                wsSettings:{path:$path}
            }')"
            link="trojan://${pw}@${host}:${port}?security=tls&sni=$(url_encode "$sni")&allowInsecure=1&type=ws&host=$(url_encode "$sni")&path=$(url_encode "$path")#$(url_encode "$name")"
            transport_desc="WebSocket  Path: ${path}"
            ;;
        grpc)
            ask_service_value "gRPC serviceName"; svc="$REPLY_SERVICE"
            stream="$(jq -cn --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg svc "$svc" '{
                network:"grpc", security:"tls",
                tlsSettings:{alpn:["h2"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                grpcSettings:{serviceName:$svc}
            }')"
            link="trojan://${pw}@${host}:${port}?security=tls&sni=$(url_encode "$sni")&allowInsecure=1&type=grpc&serviceName=$(url_encode "$svc")&mode=gun#$(url_encode "$name")"
            transport_desc="gRPC serviceName: ${svc}"
            ;;
        h2)
            ask_path_value "HTTP/2 Path"; path="$REPLY_PATH"
            stream="$(jq -cn --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" --arg path "$path" '{
                network:"http", security:"tls",
                tlsSettings:{alpn:["h2"], certificates:[{certificateFile:$cert, keyFile:$key}]},
                httpSettings:{host:[$sni], path:$path}
            }')"
            link="trojan://${pw}@${host}:${port}?security=tls&sni=$(url_encode "$sni")&allowInsecure=1&type=http&host=$(url_encode "$sni")&path=$(url_encode "$path")#$(url_encode "$name")"
            transport_desc="HTTP/2  Path: ${path}"
            ;;
    esac

    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$pw" --argjson stream "$stream" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"trojan",
        settings:{ clients:[{password:$pw}] },
        streamSettings:$stream,
        sniffing:{ enabled:true, destOverride:["http","tls"] }
    }')"
    core_add_inbounds "xray" "$inbound" || return 1

    detail="  地址: ${host}\n  端口: ${port}\n  密码: ${pw}\n  传输: ${transport_desc}\n  TLS SNI: ${sni}\n  证书: 自签名, 客户端需开启 allowInsecure/跳过证书验证"
    save_node "xray" "$tag" "$label" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- Shadowsocks / Shadowsocks 2022 ---
time_synced() {
    if command -v timedatectl >/dev/null 2>&1; then
        [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == "yes" ]] && return 0
    fi
    if command -v chronyc >/dev/null 2>&1; then
        chronyc tracking 2>/dev/null | grep -qi 'Leap status.*Normal' && return 0
    fi
    return 1
}

chrony_conf_path() {
    if [[ -f /etc/chrony/chrony.conf ]]; then echo "/etc/chrony/chrony.conf"
    elif [[ -f /etc/chrony.conf ]]; then echo "/etc/chrony.conf"
    fi
}

configure_chrony_sources() {
    local conf; conf="$(chrony_conf_path)"
    [[ -n "$conf" ]] || return 0
    if grep -q '# Proxy-Manager NTP' "$conf" 2>/dev/null; then return 0; fi
    cp "$conf" "${conf}.bak.$(date +%s)" 2>/dev/null || true
    sed -i 's/^\(server \|pool \)/#&/' "$conf" 2>/dev/null || true
    cat >> "$conf" <<'NTP'

# Proxy-Manager NTP - SS2022 对时间漂移敏感
server ntp.aliyun.com iburst
server ntp1.aliyun.com iburst
server time.cloudflare.com iburst
pool pool.ntp.org iburst maxsources 4
makestep 1 -1
NTP
}

start_time_service() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now chronyd >/dev/null 2>&1 || systemctl enable --now chrony >/dev/null 2>&1 || true
        systemctl enable --now ntpd >/dev/null 2>&1 || systemctl enable --now ntp >/dev/null 2>&1 || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-update add chronyd default >/dev/null 2>&1 || rc-update add ntpd default >/dev/null 2>&1 || true
        rc-service chronyd restart >/dev/null 2>&1 || rc-service ntpd restart >/dev/null 2>&1 || true
    fi
}

ensure_time_sync() {
    info "检查系统时间同步, SS2022 对时间漂移较敏感..."
    time_synced && { ok "系统时间已同步。"; return 0; }

    if ! command -v chronyc >/dev/null 2>&1 && ! command -v ntpd >/dev/null 2>&1; then
        info "未检测到 chrony/ntp, 尝试安装 chrony..."
        pkg_install chrony || pkg_install ntp || warn "自动安装时间同步服务失败, 请手动安装 chrony 或 ntp。"
    fi

    configure_chrony_sources
    start_time_service
    command -v chronyc >/dev/null 2>&1 && { chronyc -a 'burst 4/4' >/dev/null 2>&1 || true; chronyc -a makestep >/dev/null 2>&1 || true; }
    command -v ntpdate >/dev/null 2>&1 && ntpdate -u pool.ntp.org >/dev/null 2>&1 || true
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-ntp true >/dev/null 2>&1 || true
    fi
    sleep 2

    local offset=""
    if command -v chronyc >/dev/null 2>&1; then
        offset="$(chronyc tracking 2>/dev/null | awk '/System time/{print $4, $5}')"
    fi
    info "当前时间: $(date '+%Y-%m-%d %H:%M:%S %Z')${offset:+ | 偏移: $offset}"
    time_synced && { ok "系统时间同步已启用。"; return 0; }

    warn "未能确认系统时间已同步。SS2022 可能因时间漂移连接失败。"
    confirm "仍继续生成 SS2022 节点?" "n"
}

choose_ss_method() {
    echo -e "${CYAN}请选择 Shadowsocks 加密方式:${NC}"
    echo -e "  ${GREEN}1.${NC} aes-128-gcm"
    echo -e "  ${GREEN}2.${NC} aes-256-gcm"
    echo -e "  ${GREEN}3.${NC} chacha20-poly1305"
    local c; read -rp "$(echo -e "${CYAN}请选择 (默认: 2): ${NC}")" c
    case "$c" in
        1) REPLY_METHOD="aes-128-gcm" ;;
        3) REPLY_METHOD="chacha20-poly1305" ;;
        *) REPLY_METHOD="aes-256-gcm" ;;
    esac
}

ss2022_key_bytes() {
    case "$1" in
        2022-blake3-aes-128-gcm) echo 16 ;;
        2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305) echo 32 ;;
        *) echo 32 ;;
    esac
}

ss2022_psk_valid() {
    local method="$1" psk="$2" want got
    want="$(ss2022_key_bytes "$method")"
    got="$(printf '%s' "$psk" | base64 -d 2>/dev/null | wc -c | tr -d '[:space:]')"
    [[ "$got" == "$want" ]]
}

ask_ss2022_psk() {
    local method="$1" def v
    def="$(gen_b64 "$(ss2022_key_bytes "$method")")"
    while true; do
        ask_value_default "SS2022 PSK" "$def"; v="$REPLY_VALUE"
        ss2022_psk_valid "$method" "$v" || { err "SS2022 PSK 必须是 $(ss2022_key_bytes "$method") 字节随机值的 base64。"; continue; }
        REPLY_PASS="$v"; return 0
    done
}

choose_ss2022_method() {
    echo -e "${CYAN}请选择 Shadowsocks 2022 加密方式:${NC}"
    echo -e "  ${GREEN}1.${NC} 2022-blake3-aes-128-gcm"
    echo -e "  ${GREEN}2.${NC} 2022-blake3-aes-256-gcm"
    echo -e "  ${GREEN}3.${NC} 2022-blake3-chacha20-poly1305"
    local c; read -rp "$(echo -e "${CYAN}请选择 (默认: 2): ${NC}")" c
    case "$c" in
        1) REPLY_METHOD="2022-blake3-aes-128-gcm" ;;
        3) REPLY_METHOD="2022-blake3-chacha20-poly1305" ;;
        *) REPLY_METHOD="2022-blake3-aes-256-gcm" ;;
    esac
}

REPLY_SS_PLUGIN=""
REPLY_OBFS_HOST=""
choose_ss_plugin() {
    local allow_shadowtls="${1:-false}" c host
    echo -e "${CYAN}请选择 Shadowsocks 插件/增强模式:${NC}"
    echo -e "  ${GREEN}1.${NC} 不启用 ${DIM}(默认)${NC}"
    echo -e "  ${GREEN}2.${NC} HTTP obfs ${DIM}(simple-obfs 伪装)${NC}"
    [[ "$allow_shadowtls" == "true" ]] && echo -e "  ${GREEN}3.${NC} ShadowTLS v3 ${DIM}(适合需要套一层 TLS 伪装的客户端)${NC}"
    read -rp "$(echo -e "${CYAN}请选择 (默认: 1): ${NC}")" c
    case "$c" in
        2)
            ask_plain_default "HTTP obfs Host" "www.microsoft.com"
            host="$REPLY_VALUE"
            REPLY_SS_PLUGIN="http-obfs"
            REPLY_OBFS_HOST="$host"
            ;;
        3)
            if [[ "$allow_shadowtls" == "true" ]]; then
                REPLY_SS_PLUGIN="shadowtls"
                REPLY_OBFS_HOST=""
            else
                REPLY_SS_PLUGIN="none"
                REPLY_OBFS_HOST=""
            fi
            ;;
        *)
            REPLY_SS_PLUGIN="none"
            REPLY_OBFS_HOST=""
            ;;
    esac
}

simple_obfs_installed() { [[ -x "$SIMPLE_OBFS_BIN" ]] || command -v obfs-server >/dev/null 2>&1; }
simple_obfs_bin() { [[ -x "$SIMPLE_OBFS_BIN" ]] && echo "$SIMPLE_OBFS_BIN" || command -v obfs-server 2>/dev/null; }
ss_obfs_service() { printf 'ss-obfs-%s' "$1"; }

install_simple_obfs() {
    simple_obfs_installed && return 0
    info "安装 simple-obfs (HTTP 伪装插件)..."
    local deps=()
    case "$PKG" in
        apt) deps=(git build-essential autoconf automake libtool pkg-config libssl-dev libev-dev libc-ares-dev libpcre2-dev asciidoc xmlto) ;;
        dnf|yum) deps=(git gcc gcc-c++ make autoconf automake libtool pkgconfig openssl-devel libev-devel c-ares-devel pcre-devel asciidoc xmlto) ;;
        apk) deps=(git build-base autoconf automake libtool pkgconf openssl-dev libev-dev c-ares-dev pcre2-dev asciidoc xmlto) ;;
        zypper) deps=(git gcc gcc-c++ make autoconf automake libtool pkg-config libopenssl-devel libev-devel c-ares-devel pcre-devel asciidoc xmlto) ;;
        pacman) deps=(git base-devel autoconf automake libtool pkgconf openssl libev c-ares pcre2 asciidoc xmlto) ;;
        *) deps=(git autoconf automake libtool pkg-config) ;;
    esac
    pkg_install "${deps[@]}" || { err "simple-obfs 编译依赖安装失败。"; return 1; }

    local src="/tmp/simple-obfs-src"
    rm -rf "$src"
    git clone --depth=1 "$SIMPLE_OBFS_REPO" "$src" >/dev/null 2>&1 || { err "下载 simple-obfs 失败。"; return 1; }
    ( cd "$src" && git submodule update --init --recursive >/dev/null 2>&1 || true )
    ( cd "$src" && ./autogen.sh >/tmp/simple-obfs-autogen.log 2>&1 ) || { err "simple-obfs autogen 失败: /tmp/simple-obfs-autogen.log"; return 1; }
    ( cd "$src" && ./configure --disable-documentation >/tmp/simple-obfs-configure.log 2>&1 ) || { err "simple-obfs configure 失败: /tmp/simple-obfs-configure.log"; return 1; }
    ( cd "$src" && make -j"$(nproc 2>/dev/null || echo 1)" >/tmp/simple-obfs-make.log 2>&1 ) || { err "simple-obfs 编译失败: /tmp/simple-obfs-make.log"; return 1; }
    ( cd "$src" && make install >/tmp/simple-obfs-install.log 2>&1 ) || { err "simple-obfs 安装失败: /tmp/simple-obfs-install.log"; return 1; }
    ldconfig 2>/dev/null || true
    simple_obfs_installed || { err "simple-obfs 安装验证失败。"; return 1; }
    ok "simple-obfs 安装完成。"
}

write_ss_obfs_service() {
    local svc="$1" listen_port="$2" backend_port="$3" bin svc_file
    bin="$(simple_obfs_bin)"
    [[ -n "$bin" ]] || { err "未找到 obfs-server。"; return 1; }
    svc_file="/etc/systemd/system/${svc}.service"
    if pm_has_systemd; then
        mkdir -p "$(dirname "$svc_file")"
        cat > "$svc_file" <<EOF
[Unit]
Description=Shadowsocks simple-obfs HTTP Frontend (${listen_port})
After=network.target xray.service

[Service]
Type=simple
User=root
ExecStart=${bin} -s 0.0.0.0 -p ${listen_port} -r 127.0.0.1:${backend_port} --obfs http --http-method GET
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    fi
    pm_write_openrc_service "$svc" "Shadowsocks simple-obfs HTTP Frontend (${listen_port})" "$bin" "-s 0.0.0.0 -p ${listen_port} -r 127.0.0.1:${backend_port} --obfs http --http-method GET"
    systemctl daemon-reload
    systemctl enable --now "$svc" >/dev/null 2>&1
    sleep 1
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "simple-obfs 服务运行中: ${listen_port} -> 127.0.0.1:${backend_port}"
        return 0
    fi
    err "simple-obfs 服务启动失败:"
    journalctl -u "$svc" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'
    return 1
}

remove_ss_obfs_service() {
    local svc="$1"
    [[ -n "$svc" ]] || return 0
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}.service"
    pm_remove_openrc_service "$svc"
    systemctl daemon-reload 2>/dev/null || true
}

add_shadowsocks() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}Shadowsocks${NC} 经典 AEAD"
    ask_port "监听端口"; local port="$REPLY_PORT"
    choose_ss_method; local method="$REPLY_METHOD"
    ask_name "SS-${port}"; local name="$REPLY_NAME"
    ask_secret_value "Shadowsocks 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS" tag; tag="ss-${port}"
    choose_ss_plugin; local plugin="$REPLY_SS_PLUGIN" obfs_host="$REPLY_OBFS_HOST" listen_addr="0.0.0.0" backend_port="$port" extra="" tmp=""
    if [[ "$plugin" == "http-obfs" ]]; then
        install_simple_obfs || return 1
        backend_port="$(random_port)"
        while port_used "$backend_port" || [[ "$backend_port" == "$port" ]]; do backend_port="$(random_port)"; done
        ask_port_with_default "SS 后端端口 (仅本机监听)" "$backend_port"; backend_port="$REPLY_PORT"
        [[ "$backend_port" != "$port" ]] || { err "后端端口不能与对外端口相同。"; return 1; }
        listen_addr="127.0.0.1"
    fi
    local inbound
    inbound="$(jq -n --arg tag "$tag" --arg listen "$listen_addr" --argjson port "$backend_port" --arg m "$method" --arg pw "$pw" '{
        tag:$tag, listen:$listen, port:$port, protocol:"shadowsocks",
        settings:{ method:$m, password:$pw, network:"tcp,udp" } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="ss://$(b64_urlsafe "${method}:${pw}")@${host}:${port}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  加密: ${method}\n  密码: ${pw}\n  类型: Shadowsocks"
    if [[ "$plugin" == "http-obfs" ]]; then
        local obfs_svc plugin_raw
        obfs_svc="$(ss_obfs_service "$port")"
        write_ss_obfs_service "$obfs_svc" "$port" "$backend_port" || {
            tmp="$(mktemp_json)" && jq --arg t "$tag" '.inbounds |= map(select(.tag != $t))' "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
            core_restart xray >/dev/null 2>&1 || true
            return 1
        }
        plugin_raw="obfs-local;obfs=http;obfs-host=${obfs_host}"
        link="ss://$(b64_urlsafe "${method}:${pw}")@${host}:${port}/?plugin=$(url_encode "$plugin_raw")#$(url_encode "$name")"
        detail="${detail}\n  插件: simple-obfs http\n  Obfs Host: ${obfs_host}\n  后端端口: ${backend_port}\n  服务: ${obfs_svc}"
        extra="$(jq -cn --arg obfs_service "$obfs_svc" --argjson backend_port "$backend_port" --arg plugin "http-obfs" --arg obfs_host "$obfs_host" \
            '{obfs_service:$obfs_service, backend_port:$backend_port, plugin:$plugin, obfs_host:$obfs_host}')"
    fi
    save_node "xray" "$tag" "Shadowsocks" "$name" "$link" "$detail" "$extra"
    show_result "$name" "$link" "$detail"
}

add_ss2022() {
    echo -e "\n${MAGENTA}${BOLD}Shadowsocks 2022${NC}"
    echo -e "${DIM}SS2022 对客户端要求较新, 可按需选择 HTTP obfs 或 ShadowTLS v3。${NC}"
    choose_ss_plugin true; local plugin="$REPLY_SS_PLUGIN" obfs_host="$REPLY_OBFS_HOST"
    if [[ "$plugin" == "shadowtls" ]]; then
        add_shadowtls
        return $?
    fi
    require_xray || return 1
    ensure_time_sync || return 1
    ask_port "监听端口"; local port="$REPLY_PORT"
    choose_ss2022_method; local method="$REPLY_METHOD"
    ask_name "SS2022-${port}"; local name="$REPLY_NAME"
    ask_ss2022_psk "$method"; local pw="$REPLY_PASS" tag; tag="ss2022-${port}"
    local listen_addr="0.0.0.0" backend_port="$port" extra="" tmp=""
    if [[ "$plugin" == "http-obfs" ]]; then
        install_simple_obfs || return 1
        backend_port="$(random_port)"
        while port_used "$backend_port" || [[ "$backend_port" == "$port" ]]; do backend_port="$(random_port)"; done
        ask_port_with_default "SS2022 后端端口 (仅本机监听)" "$backend_port"; backend_port="$REPLY_PORT"
        [[ "$backend_port" != "$port" ]] || { err "后端端口不能与对外端口相同。"; return 1; }
        listen_addr="127.0.0.1"
    fi
    local inbound
    inbound="$(jq -n --arg tag "$tag" --arg listen "$listen_addr" --argjson port "$backend_port" --arg m "$method" --arg pw "$pw" '{
        tag:$tag, listen:$listen, port:$port, protocol:"shadowsocks",
        settings:{ method:$m, password:$pw, network:"tcp,udp" } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="ss://$(b64_urlsafe "${method}:${pw}")@${host}:${port}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  加密: ${method}\n  密码: ${pw}"
    if [[ "$plugin" == "http-obfs" ]]; then
        local obfs_svc plugin_raw
        obfs_svc="$(ss_obfs_service "$port")"
        write_ss_obfs_service "$obfs_svc" "$port" "$backend_port" || {
            tmp="$(mktemp_json)" && jq --arg t "$tag" '.inbounds |= map(select(.tag != $t))' "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
            core_restart xray >/dev/null 2>&1 || true
            return 1
        }
        plugin_raw="obfs-local;obfs=http;obfs-host=${obfs_host}"
        link="ss://$(b64_urlsafe "${method}:${pw}")@${host}:${port}/?plugin=$(url_encode "$plugin_raw")#$(url_encode "$name")"
        detail="${detail}\n  插件: simple-obfs http\n  Obfs Host: ${obfs_host}\n  后端端口: ${backend_port}\n  服务: ${obfs_svc}"
        extra="$(jq -cn --arg obfs_service "$obfs_svc" --argjson backend_port "$backend_port" --arg plugin "http-obfs" --arg obfs_host "$obfs_host" \
            '{obfs_service:$obfs_service, backend_port:$backend_port, plugin:$plugin, obfs_host:$obfs_host}')"
    fi
    save_node "xray" "$tag" "SS2022" "$name" "$link" "$detail" "$extra"
    show_result "$name" "$link" "$detail"
}

shadowsocks_menu() {
    echo -e "\n${YELLOW}${BOLD}=== Shadowsocks ===${NC}"
    echo -e "  ${GREEN}1.${NC} Shadowsocks AEAD"
    echo -e "  ${GREEN}2.${NC} Shadowsocks 2022"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) add_shadowsocks ;;
        2) add_ss2022 ;;
        *) return 0 ;;
    esac
}

# --- Hysteria2 ------------------------------------------------------------
add_hysteria2() {
    require_singbox || return 1; ensure_cert
    echo -e "\n${MAGENTA}${BOLD}Hysteria2${NC} 基于 QUIC, 弱网强"
    ask_port "监听端口 UDP"; local port="$REPLY_PORT"
    ask_tls_sni; local sni="$REPLY_SNI"
    ask_name "Hysteria2-${port}"; local name="$REPLY_NAME"
    ask_secret_value "Hysteria2 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS"; local tag="hysteria2-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$pw" --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
        type:"hysteria2", tag:$tag, listen:"::", listen_port:$port,
        users:[{password:$pw}],
        tls:{ enabled:true, server_name:$sni, alpn:["h3"], certificate_path:$cert, key_path:$key } }')"
    core_add_inbounds "singbox" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="hysteria2://${pw}@${host}:${port}?insecure=1&sni=$(url_encode "$sni")#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port} UDP\n  密码: ${pw}\n  SNI : ${sni}\n  证书: 自签名, 客户端需开启允许不安全"
    save_node "singbox" "$tag" "Hysteria2" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- TUIC v5 --------------------------------------------------------------
add_tuic() {
    require_singbox || return 1; ensure_cert
    echo -e "\n${MAGENTA}${BOLD}TUIC v5${NC} 基于 QUIC"
    ask_port "监听端口 UDP"; local port="$REPLY_PORT"
    ask_tls_sni; local sni="$REPLY_SNI"
    ask_name "TUIC-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "TUIC UUID"; local uuid="$REPLY_UUID"
    ask_secret_value "TUIC 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS"; local tag="tuic-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg pw "$pw" --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
        type:"tuic", tag:$tag, listen:"::", listen_port:$port,
        users:[{uuid:$uuid, password:$pw}], congestion_control:"bbr",
        tls:{ enabled:true, server_name:$sni, alpn:["h3"], certificate_path:$cert, key_path:$key } }')"
    core_add_inbounds "singbox" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="tuic://${uuid}:${pw}@${host}:${port}?congestion_control=bbr&alpn=h3&sni=$(url_encode "$sni")&allow_insecure=1#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port} UDP\n  UUID: ${uuid}\n  密码: ${pw}\n  SNI : ${sni}\n  拥塞控制: bbr  ALPN: h3\n  证书: 自签名, 客户端需允许不安全"
    save_node "singbox" "$tag" "TUIC" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- AnyTLS ---------------------------------------------------------------
add_anytls() {
    require_singbox || return 1; ensure_cert
    echo -e "\n${MAGENTA}${BOLD}AnyTLS${NC} 新型抗指纹协议, 需 sing-box 1.12+ 客户端"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_tls_sni; local sni="$REPLY_SNI"
    ask_name "AnyTLS-${port}"; local name="$REPLY_NAME"
    ask_secret_value "AnyTLS 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS"; local tag="anytls-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$pw" --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
        type:"anytls", tag:$tag, listen:"::", listen_port:$port,
        users:[{password:$pw}],
        tls:{ enabled:true, server_name:$sni, certificate_path:$cert, key_path:$key } }')"
    core_add_inbounds "singbox" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="anytls://${pw}@${host}:${port}?insecure=1&sni=$(url_encode "$sni")#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  密码: ${pw}\n  SNI : ${sni}\n  证书: 自签名, 客户端需允许不安全"
    save_node "singbox" "$tag" "AnyTLS" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- ShadowTLS v3 (+ Shadowsocks) ----------------------------------------
add_shadowtls() {
    require_singbox || return 1
    echo -e "\n${MAGENTA}${BOLD}ShadowTLS v3${NC}"
    ask_port "对外监听端口"; local port="$REPLY_PORT"
    ask_sni;               local sni="$REPLY_SNI"
    ask_name "ShadowTLS-${port}"; local name="$REPLY_NAME"
    local stls_pw ss_pw inner_port method
    ask_secret_value "ShadowTLS 密码" "$(gen_pass 16)"; stls_pw="$REPLY_PASS"
    ensure_time_sync || return 1
    choose_ss2022_method; method="$REPLY_METHOD"
    ask_ss2022_psk "$method"; ss_pw="$REPLY_PASS"
    inner_port="$(random_port)"; while port_used "$inner_port" || [[ "$inner_port" == "$port" ]]; do inner_port="$(random_port)"; done
    while true; do
        ask_port_with_default "内层 Shadowsocks 端口 (仅本机监听)" "$inner_port"
        inner_port="$REPLY_PORT"
        [[ "$inner_port" != "$port" ]] && break
        err "  内层端口不能与对外监听端口相同。"
    done
    local stag="shadowtls-${port}" sstag="stls-ss-${port}"

    local stls_in ss_in
    stls_in="$(jq -n --arg tag "$stag" --argjson port "$port" --arg pw "$stls_pw" --arg sni "$sni" --arg detour "$sstag" '{
        type:"shadowtls", tag:$tag, listen:"::", listen_port:$port, version:3,
        users:[{password:$pw}], handshake:{ server:$sni, server_port:443 }, detour:$detour }')"
    ss_in="$(jq -n --arg tag "$sstag" --argjson port "$inner_port" --arg m "$method" --arg pw "$ss_pw" '{
        type:"shadowsocks", tag:$tag, listen:"127.0.0.1", listen_port:$port, method:$m, password:$pw }')"
    core_add_inbounds "singbox" "$stls_in" "$ss_in" || return 1

    local host; host="$(server_host)"
    local ss_userinfo; ss_userinfo="$(b64_urlsafe "${method}:${ss_pw}")"
    local link="ss://${ss_userinfo}@${host}:${port}?shadow-tls=$(url_encode "{\"version\":\"3\",\"password\":\"${stls_pw}\",\"host\":\"${sni}\"}")#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  ── ShadowTLS ──\n  版本: 3\n  ShadowTLS 密码: ${stls_pw}\n  握手域名 SNI: ${sni}\n  ── 内层 Shadowsocks ──\n  本机端口: ${inner_port}\n  加密: ${method}\n  SS 密码: ${ss_pw}\n  提示: 该协议多数客户端需手动填写以上参数。"
    save_node "singbox" "$stag" "ShadowTLS" "$name" "$link" "$detail" "$sstag"
    show_result "$name" "$link" "$detail"
}

# --- SOCKS5 ---
add_socks() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}SOCKS5${NC} 明文, 建议仅内网或中转使用"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "SOCKS5-${port}"; local name="$REPLY_NAME"
    ask_username_value "SOCKS5 用户名" "user$(openssl rand -hex 2)"; local user="$REPLY_USER"
    ask_secret_value "SOCKS5 密码" "$(gen_pass 8)"; local pass="$REPLY_PASS"
    local tag="socks-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg u "$user" --arg p "$pass" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"socks",
        settings:{ auth:"password", accounts:[{user:$u, pass:$p}], udp:true } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="socks://$(b64_urlsafe "${user}:${pass}")@${host}:${port}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  用户名: ${user}\n  密码: ${pass}\n  协议: SOCKS5"
    save_node "xray" "$tag" "SOCKS5" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- HTTP Proxy ---
add_http_proxy() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}HTTP Proxy${NC} 明文, 建议仅内网或中转使用"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "HTTP-${port}"; local name="$REPLY_NAME"
    ask_username_value "HTTP 用户名" "http$(openssl rand -hex 2)"; local user="$REPLY_USER"
    ask_secret_value "HTTP 密码" "$(gen_pass 8)"; local pass="$REPLY_PASS"
    local tag="http-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg u "$user" --arg p "$pass" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"http",
        settings:{ accounts:[{user:$u, pass:$p}], allowTransparent:false } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="http://${user}:${pass}@${host}:${port}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  用户名: ${user}\n  密码: ${pass}\n  协议: HTTP Proxy"
    save_node "xray" "$tag" "HTTP" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- NaïveProxy (sing-box naive 入站) ------------------------------------
add_naive() {
    require_singbox || return 1; ensure_cert
    echo -e "\n${MAGENTA}${BOLD}NaïveProxy${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_tls_sni; local sni="$REPLY_SNI"
    ask_name "Naive-${port}"; local name="$REPLY_NAME"
    ask_username_value "NaïveProxy 用户名" "naive$(openssl rand -hex 3)"; local user="$REPLY_USER"
    ask_secret_value "NaïveProxy 密码" "$(gen_pass 12)"; local pass="$REPLY_PASS"
    local tag="naive-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg u "$user" --arg p "$pass" \
        --arg sni "$sni" --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
        type:"naive", tag:$tag, listen:"::", listen_port:$port,
        users:[{username:$u, password:$p}],
        tls:{ enabled:true, server_name:$sni, certificate_path:$cert, key_path:$key } }')"
    core_add_inbounds "singbox" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="naive+https://${user}:${pass}@${host}:${port}?insecure=1#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  用户名: ${user}\n  密码: ${pass}\n  SNI : ${sni}\n  证书: 自签名, 建议配真实域名证书, 自签需客户端允许不安全"
    save_node "singbox" "$tag" "NaïveProxy" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# ===========================================================================
#  十一、Snell (独立内核, v4/v5)
# ===========================================================================
snell_installed() { [[ -x "$SNELL_BIN" ]]; }
snell_running()   { systemctl is-active --quiet "$SNELL_SERVICE" 2>/dev/null; }
snell_managed_exists() {
    [[ -f "$STATE" ]] && jq -e '.nodes | to_entries[] | select(.value.core == "snell-managed")' "$STATE" >/dev/null 2>&1
}

snell_load_state() {
    SNELL_VERSION=""; SNELL_PORT=""; SNELL_PSK=""
    if [[ -f "$SNELL_STATE" ]]; then
        # shellcheck disable=SC1090
        source "$SNELL_STATE"
    fi
    if [[ -z "$SNELL_PORT$SNELL_PSK" && -f "$SNELL_CONF" ]]; then
        SNELL_PORT="$(grep -oP 'listen = .*:\K[0-9]+' "$SNELL_CONF" 2>/dev/null)"
        SNELL_PSK="$(grep -oP '^psk *= *\K.+' "$SNELL_CONF" 2>/dev/null)"
        SNELL_VERSION="${SNELL_VERSION:-4}"
    fi
    [[ -n "$SNELL_PORT$SNELL_PSK" ]]
}

snell_version() {
    snell_load_state >/dev/null 2>&1 && printf 'v%s' "${SNELL_VERSION:-未知}" || printf '未知'
}

shadowtls_installed() { [[ -x "$SHADOWTLS_BIN" ]]; }
shadowtls_version() {
    shadowtls_installed || return 0
    "$SHADOWTLS_BIN" --version 2>/dev/null | head -n1 | awk '{print $NF}'
}

shadowtls_arch() {
    case "$ARCH" in
        amd64) echo "x86_64-unknown-linux-musl" ;;
        arm64) echo "aarch64-unknown-linux-musl" ;;
        *) return 1 ;;
    esac
}

install_shadowtls_binary() {
    local asset_arch tag url tmp
    asset_arch="$(shadowtls_arch)" || { err "ShadowTLS 仅支持 amd64 / arm64 架构, 当前: ${ARCH}。"; return 1; }
    info "获取 ShadowTLS 最新版本..."
    tag="$(curl -fsSL --max-time 15 "https://api.github.com/repos/${SHADOWTLS_REPO}/releases/latest" 2>/dev/null | jq -r '.tag_name // empty')"
    [[ -z "$tag" ]] && { err "无法获取 ShadowTLS 版本 (GitHub API 失败)。"; return 1; }
    url="https://github.com/${SHADOWTLS_REPO}/releases/download/${tag}/shadow-tls-${asset_arch}"
    info "下载 ShadowTLS ${tag} (${asset_arch})..."
    tmp="$(mktemp)" || { err "创建临时文件失败。"; return 1; }
    curl -fL --max-time 120 "$url" -o "$tmp" || { err "下载失败: $url"; rm -f "$tmp"; return 1; }
    install -m 755 "$tmp" "$SHADOWTLS_BIN" || { err "安装 ShadowTLS 失败。"; rm -f "$tmp"; return 1; }
    rm -f "$tmp"
    ok "ShadowTLS ${tag} 安装完成。"
}

require_shadowtls() { shadowtls_installed && return 0; warn "尚未安装 ShadowTLS, 现在开始安装..."; install_shadowtls_binary; }

snell_shadowtls_service() { printf 'shadowtls-snell-%s' "$1"; }
snell_shadowtls_backend_service() { printf 'snell-stls-backend-%s' "$1"; }
snell_shadowtls_conf() { printf '/etc/snell/snell-shadowtls-%s.conf' "$1"; }
snell_shadowtls_bin() { printf '/usr/local/bin/snell-server-v%s' "$1"; }
snell_instance_service() { printf 'snell-%s' "$1"; }
snell_instance_conf() { printf '/etc/snell/snell-%s.conf' "$1"; }

ensure_snell_binary_for_shadowtls() {
    local major="$1" ver="$2" bin url tmp
    bin="$(snell_shadowtls_bin "$major")"
    [[ -x "$bin" ]] && return 0
    url="https://dl.nssurge.com/snell/snell-server-${ver}-linux-${SNELL_ARCH}.zip"
    command -v unzip >/dev/null 2>&1 || pkg_install unzip
    info "下载 Snell v${major} 后端 (${SNELL_ARCH})..."
    tmp="$(mktemp -d)" || { err "创建临时目录失败。"; return 1; }
    curl -fL --max-time 60 "$url" -o "$tmp/snell.zip" || { err "下载失败: $url"; rm -rf "$tmp"; return 1; }
    unzip -oq "$tmp/snell.zip" -d "$tmp" || { err "解压失败。"; rm -rf "$tmp"; return 1; }
    [[ -f "$tmp/snell-server" ]] || { err "未找到 snell-server 可执行文件。"; rm -rf "$tmp"; return 1; }
    install -m 755 "$tmp/snell-server" "$bin" || { err "安装 Snell 后端失败。"; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

snell_mihomo_yaml() {
    local name="$1" host="$2" port="$3" psk="$4" ver="$5"
    [[ "$ver" =~ ^[0-9]+$ ]] || ver=4
    printf '  - name: "%s"\n    type: snell\n    server: "%s"\n    port: %s\n    psk: "%s"\n    version: %s\n    tfo: true\n' \
        "$name" "$host" "$port" "$psk" "$ver"
    (( ver >= 3 )) && printf '    udp: true\n'
    (( ver >= 4 )) && printf '    reuse: true\n'
}

snell_uri() {
    local name="$1" host="$2" port="$3" psk="$4" ver="$5"
    printf 'snell://%s@%s:%s?version=%s#%s' "$psk" "$host" "$port" "$ver" "$(url_encode "$name")"
}

install_snell_version() {
    local major="$1" ver="$2"
    echo -e "\n${MAGENTA}${BOLD}Snell v${major}${NC} Surge 官方协议"
    [[ -f "$SNELL_STATE" || -f "$SNELL_CONF" ]] && warn "检测到旧版单实例 Snell 配置, 本次将新增独立实例, 不覆盖旧服务。"
    ensure_snell_binary_for_shadowtls "$major" "$ver" || return 1

    ask_port "Snell 监听端口"; local port="$REPLY_PORT"
    ask_name "Snell-v${major}-${port}"; local name="$REPLY_NAME"
    ask_secret_value "Snell PSK" "$(gen_pass 16)"; local psk="$REPLY_PASS"

    local tag conf bin svc svc_file
    tag="snell-${port}"
    conf="$(snell_instance_conf "$port")"
    bin="$(snell_shadowtls_bin "$major")"
    svc="$(snell_instance_service "$port")"
    svc_file="/etc/systemd/system/${svc}.service"

    mkdir -p "$(dirname "$conf")" "$STATE_DIR"
    cat > "$conf" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
EOF
    chmod 600 "$conf"

    if pm_has_systemd; then
        mkdir -p "$(dirname "$svc_file")"
        cat > "$svc_file" <<EOF
[Unit]
Description=Snell v${major} Proxy Server (${port})
After=network.target

[Service]
Type=simple
User=root
ExecStart=${bin} -c ${conf}
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    fi
    pm_write_openrc_service "$svc" "Snell v${major} Proxy Server (${port})" "$bin" "-c ${conf}"
    systemctl daemon-reload
    systemctl enable --now "$svc" >/dev/null 2>&1
    sleep 1
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        err "Snell 启动失败:"; journalctl -u "$svc" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'; return 1
    fi

    local host link; host="$(server_host)"
    link="$(snell_uri "$name" "$host" "$port" "$psk" "$major")"
    local surge="${name} = snell, ${host}, ${port}, psk=${psk}, version=${major}, reuse=true, tfo=true"
    local detail="  地址: ${host}\n  端口: ${port}\n  PSK : ${psk}\n  版本: ${major}\n  服务: ${svc}\n  配置: ${conf}"
    save_node "snell-managed" "$tag" "Snell v${major}" "$name" "$link" "$detail"

    echo; hr; ok "  ✅ Snell v${major} 部署成功!"; hr
    echo -e "${BOLD}分享链接:${NC}"; echo -e "${GREEN}${link}${NC}"; echo
    echo -e "${BOLD}Surge 节点配置行:${NC}"; echo -e "${GREEN}${surge}${NC}"; echo
    echo -e "${BOLD}Mihomo 配置:${NC}"
    echo -e "${GREEN}"
    snell_mihomo_yaml "$name" "$host" "$port" "$psk" "$major"
    echo -e "${NC}"
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${BOLD}二维码, 客户端扫码导入:${NC}"; qrencode -t ANSIUTF8 "$link"
    fi
    hr
}

add_snell_shadowtls_version() {
    local major="$1" ver="$2"
    require_shadowtls || return 1
    ensure_snell_binary_for_shadowtls "$major" "$ver" || return 1

    echo -e "\n${MAGENTA}${BOLD}Snell v${major} + ShadowTLS v3${NC}"
    ask_port "ShadowTLS 对外监听端口"; local port="$REPLY_PORT"
    ask_tls_sni "www.apple.com"; local sni="$REPLY_SNI"
    ask_name "Snell-STLS-${port}"; local name="$REPLY_NAME"
    ask_secret_value "Snell PSK" "$(gen_pass 16)"; local psk="$REPLY_PASS"
    ask_secret_value "ShadowTLS 密码" "$(gen_pass 16)"; local stls_pw="$REPLY_PASS"

    local inner_port
    inner_port="$(random_port)"
    while port_used "$inner_port" || [[ "$inner_port" == "$port" ]]; do inner_port="$(random_port)"; done
    while true; do
        ask_port_with_default "Snell 后端端口 (仅本机监听)" "$inner_port"
        inner_port="$REPLY_PORT"
        [[ "$inner_port" != "$port" ]] && break
        err "  后端端口不能与对外监听端口相同。"
    done

    local tag conf bin stls_svc backend_svc stls_service_file backend_service_file
    tag="snell-shadowtls-${port}"
    conf="$(snell_shadowtls_conf "$port")"
    bin="$(snell_shadowtls_bin "$major")"
    stls_svc="$(snell_shadowtls_service "$port")"
    backend_svc="$(snell_shadowtls_backend_service "$port")"
    stls_service_file="/etc/systemd/system/${stls_svc}.service"
    backend_service_file="/etc/systemd/system/${backend_svc}.service"

    mkdir -p "$(dirname "$conf")" "$STATE_DIR"
    cat > "$conf" <<EOF
[snell-server]
listen = 127.0.0.1:${inner_port}
psk = ${psk}
ipv6 = true
EOF
    chmod 600 "$conf"

    if pm_has_systemd; then
        mkdir -p "$(dirname "$backend_service_file")"
        cat > "$backend_service_file" <<EOF
[Unit]
Description=Snell v${major} backend for ShadowTLS (${port})
After=network.target

[Service]
Type=simple
User=root
ExecStart=${bin} -c ${conf}
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

        cat > "$stls_service_file" <<EOF
[Unit]
Description=ShadowTLS v3 frontend for Snell (${port})
After=network.target ${backend_svc}.service
Requires=${backend_svc}.service

[Service]
Type=simple
User=root
Environment=MONOIO_FORCE_LEGACY_DRIVER=1
Environment=RUST_LOG=error
ExecStart=${SHADOWTLS_BIN} --v3 server --listen 0.0.0.0:${port} --server 127.0.0.1:${inner_port} --tls ${sni}:443 --password ${stls_pw}
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    fi
    pm_write_openrc_service "$backend_svc" "Snell v${major} backend for ShadowTLS (${port})" "$bin" "-c ${conf}"
    pm_write_openrc_service "$stls_svc" "ShadowTLS v3 frontend for Snell (${port})" "$SHADOWTLS_BIN" "--v3 server --listen 0.0.0.0:${port} --server 127.0.0.1:${inner_port} --tls ${sni}:443 --password ${stls_pw}" $'export MONOIO_FORCE_LEGACY_DRIVER=1\nexport RUST_LOG=error'

    systemctl daemon-reload
    systemctl enable --now "$backend_svc" >/dev/null 2>&1
    sleep 1
    if ! systemctl is-active --quiet "$backend_svc" 2>/dev/null; then
        err "Snell 后端启动失败:"; journalctl -u "$backend_svc" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'; return 1
    fi
    systemctl enable --now "$stls_svc" >/dev/null 2>&1
    sleep 1
    if ! systemctl is-active --quiet "$stls_svc" 2>/dev/null; then
        err "ShadowTLS 前端启动失败:"; journalctl -u "$stls_svc" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'; return 1
    fi

    local host; host="$(server_host)"
    local link="Snell-STLS-${port} = snell, ${host}, ${port}, psk=${psk}, version=${major}, reuse=true, tfo=true, shadow-tls-password=${stls_pw}, shadow-tls-sni=${sni}, shadow-tls-version=3"
    local detail="  地址: ${host}\n  对外端口: ${port}\n  Snell 后端端口: ${inner_port}\n  Snell 版本: ${major}\n  Snell PSK: ${psk}\n  ShadowTLS 密码: ${stls_pw}\n  ShadowTLS SNI: ${sni}\n  服务: ${stls_svc} / ${backend_svc}\n  提示: Snell+ShadowTLS 多数客户端需手动填写以上参数或使用 Surge/Loon 配置行。"
    save_node "snell-shadowtls" "$tag" "Snell+ShadowTLS" "$name" "$link" "$detail"

    echo; hr; ok "  ✅ Snell v${major} + ShadowTLS v3 部署成功!"; hr
    echo -e "${BOLD}Surge/Loon 配置行:${NC}"; echo -e "${GREEN}${link}${NC}"
    echo -e "${BOLD}连接信息:${NC}"
    echo -e "${DIM}${detail}${NC}"
    hr
}

install_snell_v4() { install_snell_version "4" "v4.1.1"; }
install_snell_v5() { install_snell_version "5" "v5.0.1"; }
install_snell_shadowtls_v4() { add_snell_shadowtls_version "4" "v4.1.1"; }
install_snell_shadowtls_v5() { add_snell_shadowtls_version "5" "v5.0.1"; }

install_snell() {
    echo -e "\n${YELLOW}${BOLD}=== Snell ===${NC}"
    echo -e "  ${GREEN}1.${NC} Snell v4"
    echo -e "  ${GREEN}2.${NC} Snell v5 ${DIM}(默认)${NC}"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c major ver; read -rp "$(echo -e "${CYAN}请选择版本 (默认: 2): ${NC}")" c
    case "$c" in
        0) return 0 ;;
        1) major="4"; ver="v4.1.1" ;;
        2|"") major="5"; ver="v5.0.1" ;;
        *) err "无效选项。"; return 1 ;;
    esac
    if confirm "是否启用 ShadowTLS v3 插件模式?" "n"; then
        add_snell_shadowtls_version "$major" "$ver"
    else
        install_snell_version "$major" "$ver"
    fi
}

snell_show_link() {
    snell_load_state || { warn "未找到 Snell 配置。"; return 0; }
    local host; host="$(server_host)"
    local link; link="$(snell_uri "Snell-v${SNELL_VERSION}-${SNELL_PORT}" "$host" "$SNELL_PORT" "$SNELL_PSK" "$SNELL_VERSION")"
    local surge="Snell-${SNELL_PORT} = snell, ${host}, ${SNELL_PORT}, psk=${SNELL_PSK}, version=${SNELL_VERSION}, reuse=true, tfo=true"
    echo -e "${BOLD}[Snell v${SNELL_VERSION}]${NC} ${SNELL_PORT}"
    echo -e "${BOLD}分享链接:${NC}"
    echo -e "${GREEN}${link}${NC}"
    echo
    echo -e "${BOLD}Surge 节点配置行:${NC}"
    echo -e "${GREEN}${surge}${NC}"
    echo
    echo -e "${BOLD}Mihomo 配置:${NC}"
    echo -e "${GREEN}"
    snell_mihomo_yaml "Snell-v${SNELL_VERSION}-${SNELL_PORT}" "$host" "$SNELL_PORT" "$SNELL_PSK" "$SNELL_VERSION"
    echo -e "${NC}"
}

uninstall_snell() {
    snell_installed || snell_managed_exists || { warn "Snell 未安装。"; return 0; }
    [[ "$1" == "quiet" ]] || confirm "确认卸载 Snell?" "n" || return 0
    if [[ -f "$STATE" ]]; then
        local t
        while IFS= read -r t; do
            [[ -n "$t" ]] && delete_snell_managed_node "$t" >/dev/null 2>&1 || true
        done <<< "$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-managed") | .key' "$STATE" 2>/dev/null)"
    fi
    systemctl stop "$SNELL_SERVICE" 2>/dev/null; systemctl disable "$SNELL_SERVICE" 2>/dev/null
    rm -f "$SNELL_SERVICE_FILE" "$SNELL_BIN" "$SNELL_STATE" "$SNELL_CONF"
    pm_remove_openrc_service "$SNELL_SERVICE"
    rmdir "$(dirname "$SNELL_CONF")" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    ok "Snell 已卸载。"
}

# ===========================================================================
#  十一之二、Mieru / mita (独立内核, enfein/mieru)
# ===========================================================================
mita_bin() { command -v mita 2>/dev/null || { [[ -x /usr/bin/mita ]] && echo /usr/bin/mita; }; }
mieru_installed() { [[ -n "$(mita_bin)" ]]; }
mieru_running()   { systemctl is-active --quiet "$MITA_SERVICE" 2>/dev/null; }
mieru_version() {
    local bin v
    bin="$(mita_bin)"
    [[ -n "$bin" ]] || return 0
    v="$("$bin" version 2>/dev/null | head -n1)"
    [[ -z "$v" ]] && v="$("$bin" --version 2>/dev/null | head -n1)"
    v="$(printf '%s' "$v" | grep -oE 'v?[0-9]+(\.[0-9]+)+[-+A-Za-z0-9.]*' | head -n1)"
    printf '%s' "${v:-未知}"
}

wait_mita_socket() {
    local timeout="${1:-30}" i=0 s
    while (( i < timeout )); do
        for s in /var/run/mita/mita.sock /run/mita/mita.sock /var/run/mita.sock; do
            [[ -S "$s" ]] && return 0
        done
        sleep 1; ((i++))
    done
    return 1
}

mieru_managed_exists() {
    [[ -f "$STATE" ]] && jq -e '.nodes | to_entries[] | select(.value.core == "mieru-managed")' "$STATE" >/dev/null 2>&1
}

mieru_links_for_node() {
    local name="$1" user="$2" pass="$3" proto="$4" port="$5" mtu="$6" host eu ep item pr po
    host="$(server_host)"
    eu="$(url_encode "$user")"; ep="$(url_encode "$pass")"
    case "$proto" in
        TCP)  set -- "TCP:${port}" ;;
        UDP)  set -- "UDP:${port}" ;;
        BOTH) set -- "TCP:${port}" "UDP:$((port+1))" ;;
        *)    set -- "${proto}:${port}" ;;
    esac
    for item in "$@"; do
        pr="${item%%:*}"; po="${item##*:}"
        printf 'mierus://%s:%s@%s:%s?handshake-mode=HANDSHAKE_STANDARD&mtu=%s&multiplexing=MULTIPLEXING_LOW&port=%s&profile=%s&protocol=%s\n' \
            "$eu" "$ep" "$host" "$po" "$mtu" "$po" "$(url_encode "$name")" "$pr"
    done
}

mieru_state_nodes_json() {
    local managed="[]" legacy="[]"
    if [[ -f "$STATE" ]]; then
        managed="$(jq -c '[.nodes | to_entries[] | select(.value.core == "mieru-managed") | (.value.extra_tag | fromjson)]' "$STATE" 2>/dev/null)"
        [[ -z "$managed" ]] && managed="[]"
    fi
    if [[ -f "$MIERU_STATE" ]]; then
        # shellcheck disable=SC1090
        source "$MIERU_STATE"
        if [[ -n "${MIERU_USER:-}" && -n "${MIERU_PASS:-}" && -n "${MIERU_PORT:-}" ]]; then
            legacy="$(jq -cn --arg user "$MIERU_USER" --arg pass "$MIERU_PASS" --arg proto "${MIERU_PROTO:-TCP}" \
                --argjson port "${MIERU_PORT}" --argjson mtu "${MIERU_MTU:-1400}" \
                '[{user:$user, pass:$pass, proto:$proto, port:$port, mtu:$mtu, legacy:true}]')"
        fi
    fi
    jq -cn --argjson legacy "$legacy" --argjson managed "$managed" '$legacy + $managed'
}

mieru_apply_from_state() {
    local bin nodes cfg count
    bin="$(mita_bin)"
    [[ -n "$bin" ]] || { err "未找到 mita 二进制。"; return 1; }
    nodes="$(mieru_state_nodes_json)"
    count="$(printf '%s' "$nodes" | jq 'length')"
    if (( count == 0 )); then
        systemctl stop "$MITA_SERVICE" 2>/dev/null || true
        return 0
    fi
    cfg="$(mktemp)" || { err "创建临时配置失败。"; return 1; }
    printf '%s' "$nodes" | jq '{
        portBindings: ([.[] | if .proto == "BOTH" then
            [{port:.port, protocol:"TCP"}, {port:(.port + 1), protocol:"UDP"}]
        else
            [{port:.port, protocol:.proto}]
        end] | add),
        users: [.[] | {name:.user, password:.pass}],
        loggingLevel: "INFO",
        mtu: ((.[0].mtu // 1400) | tonumber)
    }' > "$cfg" || { rm -f "$cfg"; err "生成 Mieru 配置失败。"; return 1; }

    systemctl enable --now "$MITA_SERVICE" >/dev/null 2>&1
    wait_mita_socket 30 || warn "mita 管理套接字未就绪, 继续尝试 apply..."
    if ! "$bin" apply config "$cfg" >/dev/null 2>&1; then
        sleep 2
        "$bin" apply config "$cfg" >/dev/null 2>&1 || { err "mita apply config 失败。"; rm -f "$cfg"; return 1; }
    fi
    rm -f "$cfg"
    "$bin" start >/dev/null 2>&1 || true
}

add_mieru_node() {
    local bin; bin="$(mita_bin)"
    [[ -n "$bin" ]] || { err "未找到 mita 二进制, 请先安装 Mieru。"; return 1; }

    echo -e "${CYAN}请选择传输协议:${NC}"
    echo -e "  ${GREEN}1.${NC} TCP 推荐   ${GREEN}2.${NC} UDP   ${GREEN}3.${NC} TCP+UDP 双协议"
    local pc proto port user pass mtu name tag link detail extra
    read -rp "$(echo -e "${CYAN}选择 (默认: 1): ${NC}")" pc
    case "$pc" in 2) proto="UDP" ;; 3) proto="BOTH" ;; *) proto="TCP" ;; esac
    ask_port "监听端口"; port="$REPLY_PORT"
    if [[ "$proto" == "BOTH" ]]; then
        if (( port >= 65535 )); then err "双协议需要 端口+1 空闲, 监听端口不能为 65535。"; return 1; fi
        port_used "$((port+1))" && { err "双协议需要 端口+1 (${port}→$((port+1))) 空闲, 请换一个端口。"; return 1; }
    fi
    ask_name "Mieru-${proto}-${port}"; name="$REPLY_NAME"
    ask_username_value "Mieru 用户名" "mieru$(openssl rand -hex 3)"; user="$REPLY_USER"
    ask_secret_value "Mieru 密码" "$(gen_pass 12)"; pass="$REPLY_PASS"
    ask_int_default "Mieru MTU" "1400" 1280 9000; mtu="$REPLY_VALUE"

    tag="mieru-${port}"
    link="$(mieru_links_for_node "$name" "$user" "$pass" "$proto" "$port" "$mtu")"
    detail="  地址: $(server_host)\n  端口: ${port}$([[ "$proto" == "BOTH" ]] && printf ' / %s' "$((port+1))")\n  用户名: ${user}\n  密码: ${pass}\n  协议: ${proto}\n  MTU : ${mtu}"
    extra="$(jq -cn --arg user "$user" --arg pass "$pass" --arg proto "$proto" --argjson port "$port" --argjson mtu "$mtu" \
        '{user:$user, pass:$pass, proto:$proto, port:$port, mtu:$mtu}')"
    save_node "mieru-managed" "$tag" "Mieru" "$name" "$link" "$detail" "$extra"
    mieru_apply_from_state || return 1
    echo; hr; ok "  ✅ Mieru 节点已添加!"; hr
    echo -e "${BOLD}分享链接:${NC}"; echo -e "${GREEN}${link}${NC}"
    hr
}

configure_mieru() {
    local bin; bin="$(mita_bin)"
    [[ -n "$bin" ]] || { err "未找到 mita 二进制, 请先安装 Mieru。"; return 1; }

    local cur_user="" cur_pass="" cur_port="" cur_proto="TCP" cur_mtu="1400"
    if [[ -f "$MIERU_STATE" ]]; then
        # shellcheck disable=SC1090
        source "$MIERU_STATE"
        cur_user="${MIERU_USER:-}"
        cur_pass="${MIERU_PASS:-}"
        cur_port="${MIERU_PORT:-}"
        cur_proto="${MIERU_PROTO:-TCP}"
        cur_mtu="${MIERU_MTU:-1400}"
    fi

    echo -e "${CYAN}请选择传输协议:${NC}"
    echo -e "  ${GREEN}1.${NC} TCP 推荐   ${GREEN}2.${NC} UDP   ${GREEN}3.${NC} TCP+UDP 双协议"
    local pc default_choice proto
    case "$cur_proto" in UDP) default_choice="2" ;; BOTH) default_choice="3" ;; *) default_choice="1" ;; esac
    read -rp "$(echo -e "${CYAN}选择 (回车使用: ${default_choice}): ${NC}")" pc
    pc="${pc:-$default_choice}"
    case "$pc" in 2) proto="UDP" ;; 3) proto="BOTH" ;; *) proto="TCP" ;; esac

    local port p
    if [[ -n "$cur_port" ]]; then
        while true; do
            read -rp "$(echo -e "${CYAN}监听端口 (回车使用: ${cur_port}): ${NC}")" p
            p="${p:-$cur_port}"
            if ! [[ "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then err "  端口无效, 请输入 1-65535。"; continue; fi
            if [[ "$p" != "$cur_port" ]] && port_used "$p"; then err "  端口 $p 已被占用, 请换一个。"; continue; fi
            port="$p"; break
        done
    else
        ask_port "监听端口"; port="$REPLY_PORT"
    fi
    if [[ "$proto" == "BOTH" ]]; then
        if (( port >= 65535 )); then err "双协议需要 端口+1 空闲, 监听端口不能为 65535。"; return 1; fi
        if port_used "$((port+1))" && ! [[ "$cur_proto" == "BOTH" && -n "$cur_port" && "$port" == "$cur_port" ]]; then
            err "双协议需要 端口+1 (${port}→$((port+1))) 空闲, 请换一个端口。"; return 1
        fi
    fi

    ask_username_value "Mieru 用户名" "${cur_user:-mieru$(openssl rand -hex 3)}"; local user="$REPLY_USER"
    ask_secret_value "Mieru 密码" "${cur_pass:-$(gen_pass 12)}"; local pass="$REPLY_PASS"
    ask_int_default "Mieru MTU" "$cur_mtu" 1280 9000; local mtu="$REPLY_VALUE"

    local cfg bindings; cfg="$(mktemp)" || { err "创建临时配置失败。"; return 1; }
    case "$proto" in
        TCP)  bindings='{ "port": '"$port"', "protocol": "TCP" }' ;;
        UDP)  bindings='{ "port": '"$port"', "protocol": "UDP" }' ;;
        BOTH) bindings='{ "port": '"$port"', "protocol": "TCP" }, { "port": '"$((port+1))"', "protocol": "UDP" }' ;;
    esac
    cat > "$cfg" <<EOF
{
  "portBindings": [ ${bindings} ],
  "users": [ { "name": "${user}", "password": "${pass}" } ],
  "loggingLevel": "INFO",
  "mtu": ${mtu}
}
EOF

    info "启动 mita 守护进程并应用配置..."
    systemctl enable --now "$MITA_SERVICE" >/dev/null 2>&1
    wait_mita_socket 30 || warn "mita 管理套接字未就绪, 继续尝试 apply..."
    if ! "$bin" apply config "$cfg" >/dev/null 2>&1; then
        sleep 2; "$bin" apply config "$cfg" >/dev/null 2>&1 || { err "mita apply config 失败。"; rm -f "$cfg"; return 1; }
    fi
    rm -f "$cfg"
    "$bin" start >/dev/null 2>&1

    mkdir -p "$STATE_DIR"
    local mver; mver="$(mieru_version)"
    cat > "$MIERU_STATE" <<EOF
MIERU_USER='${user}'
MIERU_PASS='${pass}'
MIERU_PORT=${port}
MIERU_PROTO='${proto}'
MIERU_MTU=${mtu}
MIERU_VERSION='${mver}'
EOF
    chmod 600 "$MIERU_STATE"

    echo; hr; ok "  ✅ Mieru (mita) 配置已应用!"; hr
    mieru_show_link
}

install_mieru() {
    echo -e "\n${BLUE}${BOLD}Mieru${NC} 高抗审查底层协议"
    local march deb_arch rpm_arch
    case "$ARCH" in
        amd64) march="amd64"; deb_arch="amd64"; rpm_arch="x86_64" ;;
        arm64) march="arm64"; deb_arch="arm64"; rpm_arch="aarch64" ;;
        *) err "Mieru 仅支持 amd64 / arm64 架构, 当前: ${ARCH}。"; return 1 ;;
    esac
    if mieru_installed; then
        warn "检测到 Mieru 已安装。"
        if confirm "是否新增 Mieru 节点 (不下载最新版)?" "y"; then
            add_mieru_node
            return $?
        fi
        confirm "是否继续下载并覆盖安装最新版?" "n" || return 0
    fi

    info "获取 Mieru 最新版本..."
    local tag ver; tag="$(curl -fsSL --max-time 15 https://api.github.com/repos/${MITA_REPO}/releases/latest 2>/dev/null | jq -r '.tag_name // empty')"
    [[ -z "$tag" ]] && { err "无法获取 Mieru 版本 (GitHub API 失败)。"; return 1; }
    ver="${tag#v}"

    local tmp url; tmp="$(mktemp -d)"
    if command -v dpkg >/dev/null 2>&1; then
        url="https://github.com/${MITA_REPO}/releases/download/${tag}/mita_${ver}_${deb_arch}.deb"
        info "下载并安装 deb 包: mita_${ver}_${deb_arch}.deb"
        curl -fL --max-time 120 "$url" -o "$tmp/mita.deb" || { err "下载失败: $url"; rm -rf "$tmp"; return 1; }
        DEBIAN_FRONTEND=noninteractive dpkg -i "$tmp/mita.deb" >/dev/null 2>&1 || apt-get install -f -y >/dev/null 2>&1
    elif command -v rpm >/dev/null 2>&1; then
        url="https://github.com/${MITA_REPO}/releases/download/${tag}/mita-${ver}-1.${rpm_arch}.rpm"
        info "下载并安装 rpm 包: mita-${ver}-1.${rpm_arch}.rpm"
        curl -fL --max-time 120 "$url" -o "$tmp/mita.rpm" || { err "下载失败: $url"; rm -rf "$tmp"; return 1; }
        rpm -Uvh --force "$tmp/mita.rpm" >/dev/null 2>&1 || { command -v dnf >/dev/null 2>&1 && dnf install -y "$tmp/mita.rpm" >/dev/null 2>&1; }
    else
        # 通用 tar.gz + 手写 systemd 服务
        url="https://github.com/${MITA_REPO}/releases/download/${tag}/mita_${ver}_linux_${march}.tar.gz"
        info "下载 tar.gz 并手动安装: mita_${ver}_linux_${march}.tar.gz"
        curl -fL --max-time 120 "$url" -o "$tmp/mita.tar.gz" || { err "下载失败: $url"; rm -rf "$tmp"; return 1; }
        tar -xzf "$tmp/mita.tar.gz" -C "$tmp" || { err "解压失败。"; rm -rf "$tmp"; return 1; }
        [[ -f "$tmp/mita" ]] || { err "未找到 mita 可执行文件。"; rm -rf "$tmp"; return 1; }
        install -m 755 "$tmp/mita" /usr/local/bin/mita
        cat > "$MITA_SERVICE_FILE" <<EOF
[Unit]
Description=mita proxy server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/mita run
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    rm -rf "$tmp"

    local bin; bin="$(mita_bin)"
    [[ -n "$bin" ]] || { err "mita 二进制安装失败。"; return 1; }
    add_mieru_node
}

# 读取状态并输出 mierus:// 链接 + 二维码
mieru_show_link() {
    [[ -f "$MIERU_STATE" ]] || { warn "未找到 Mieru 配置。"; return 0; }
    # shellcheck disable=SC1090
    source "$MIERU_STATE"
    local host; host="$(server_host)"
    local mtu="${MIERU_MTU:-1400}"
    local eu ep; eu="$(url_encode "$MIERU_USER")"; ep="$(url_encode "$MIERU_PASS")"
    echo -e "${BOLD}用户: ${NC}${MIERU_USER}   ${BOLD}密码: ${NC}${MIERU_PASS}   ${BOLD}协议: ${NC}${MIERU_PROTO}   ${BOLD}MTU: ${NC}${mtu}"
    local -a plist=()
    case "$MIERU_PROTO" in
        TCP)  plist=("TCP:${MIERU_PORT}") ;;
        UDP)  plist=("UDP:${MIERU_PORT}") ;;
        BOTH) plist=("TCP:${MIERU_PORT}" "UDP:$((MIERU_PORT+1))") ;;
    esac
    local item pr po link
    for item in "${plist[@]}"; do
        pr="${item%%:*}"; po="${item##*:}"
        link="mierus://${eu}:${ep}@${host}:${po}?handshake-mode=HANDSHAKE_STANDARD&mtu=${mtu}&multiplexing=MULTIPLEXING_LOW&port=${po}&profile=default&protocol=${pr}"
        echo; echo -e "${BOLD}[${pr}] 分享链接:${NC}"; echo -e "${GREEN}${link}${NC}"
    done
    echo -e "${DIM}提示: mierus:// 为客户端分享链接; 请在 mieru 客户端 / Clash Verge 等导入, 勿在服务器执行 apply。${NC}"
    echo; echo -e "${BOLD}Mihomo 配置:${NC}"
    echo -e "${GREEN}"
    for item in "${plist[@]}"; do
        pr="${item%%:*}"; po="${item##*:}"
        local mname="Mieru"; [[ "$MIERU_PROTO" == "BOTH" ]] && mname="Mieru-${pr}"
        printf '  - name: "%s"\n    type: mieru\n    server: "%s"\n    port: %s\n    transport: %s\n    username: "%s"\n    password: "%s"\n    multiplexing: MULTIPLEXING_LOW\n' "$mname" "$host" "$po" "$pr" "$MIERU_USER" "$MIERU_PASS"
    done
    echo -e "${NC}"
    if command -v qrencode >/dev/null 2>&1; then
        for item in "${plist[@]}"; do
            pr="${item%%:*}"; po="${item##*:}"
            link="mierus://${eu}:${ep}@${host}:${po}?handshake-mode=HANDSHAKE_STANDARD&mtu=${mtu}&multiplexing=MULTIPLEXING_LOW&port=${po}&profile=default&protocol=${pr}"
            echo; echo -e "${BOLD}[${pr}] 二维码:${NC}"; qrencode -t ANSIUTF8 "$link"
        done
    fi
    hr
}

uninstall_mieru() {
    mieru_installed || mieru_managed_exists || { warn "Mieru 未安装。"; return 0; }
    [[ "$1" == "quiet" ]] || confirm "确认卸载 Mieru?" "n" || return 0
    if [[ -f "$STATE" ]]; then
        local tmp
        tmp="$(mktemp)"
        jq '.nodes |= with_entries(select(.value.core != "mieru-managed"))' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    fi
    systemctl stop "$MITA_SERVICE" 2>/dev/null; systemctl disable "$MITA_SERVICE" 2>/dev/null
    dpkg -r mita >/dev/null 2>&1 || rpm -e mita >/dev/null 2>&1 || rm -f /usr/local/bin/mita /usr/bin/mita
    rm -f "$MITA_SERVICE_FILE" "$MIERU_STATE"; rm -rf /etc/mita
    systemctl daemon-reload; ok "Mieru 已卸载。"
}

# ===========================================================================
#  十一之三、WireGuard (独立内核, wg-quick)
# ===========================================================================
wg_installed() { command -v wg >/dev/null 2>&1 && [[ -f "$WG_CONF" ]]; }
wg_running()   { systemctl is-active --quiet "wg-quick@${WG_IFACE}" 2>/dev/null; }
wg_version() {
    local v
    v="$(wg --version 2>/dev/null | head -n1 | grep -oE 'v?[0-9]+(\.[0-9]+)+[-+A-Za-z0-9.]*' | head -n1)"
    printf '%s' "${v:-未知}"
}

default_iface() { ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }

REPLY_WG_PRIV=""; REPLY_WG_PUB=""
ask_wg_private_key() {
    local prompt="$1" def v pub
    def="$(wg genkey)"
    while true; do
        ask_value_default "$prompt" "$def"; v="$REPLY_VALUE"
        pub="$(printf '%s' "$v" | wg pubkey 2>/dev/null)" || pub=""
        [[ -n "$pub" ]] || { err "WireGuard 私钥无效。"; continue; }
        REPLY_WG_PRIV="$v"; REPLY_WG_PUB="$pub"; return 0
    done
}

wg_managed_exists() {
    [[ -f "$STATE" ]] && jq -e '.nodes | to_entries[] | select(.value.core == "wireguard-managed")' "$STATE" >/dev/null 2>&1
}

wg_load_server_state() {
    WG_SERVER_PRIV=""; WG_SERVER_PUB=""; WG_SERVER_ADDR=""; WG_DNS=""; WG_PORT=""; WG_OUT_IFACE=""
    WG_CLIENT_PRIV=""; WG_CLIENT_ADDR=""
    if [[ -f "$WG_STATE" ]]; then
        # shellcheck disable=SC1090
        source "$WG_STATE"
        WG_SERVER_PRIV="${WG_SERVER_PRIV:-}"
        WG_SERVER_PUB="${WG_SERVER_PUB:-}"
        WG_SERVER_ADDR="${WG_SERVER_ADDR:-}"
        WG_DNS="${WG_DNS:-1.1.1.1, 8.8.8.8}"
        WG_PORT="${WG_PORT:-}"
        WG_OUT_IFACE="${WG_OUT_IFACE:-}"
    fi
    if [[ -f "$WG_CONF" ]]; then
        [[ -z "$WG_SERVER_PRIV" ]] && WG_SERVER_PRIV="$(grep -m1 -E '^PrivateKey *= *' "$WG_CONF" | awk -F= '{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}')"
        [[ -z "$WG_SERVER_ADDR" ]] && WG_SERVER_ADDR="$(grep -m1 -E '^Address *= *' "$WG_CONF" | awk -F= '{gsub(/^[ \t]+|[ \t]+$/,"",$2); sub(/\/.*/,"",$2); print $2}')"
        [[ -z "$WG_PORT" ]] && WG_PORT="$(grep -m1 -E '^ListenPort *= *' "$WG_CONF" | awk -F= '{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}')"
        [[ -z "$WG_OUT_IFACE" ]] && WG_OUT_IFACE="$(grep -m1 -E '^PostUp *= *' "$WG_CONF" | sed -n 's/.* -o \([^ ;]*\).*/\1/p')"
    fi
    if [[ -n "$WG_SERVER_PRIV" && -z "$WG_SERVER_PUB" ]]; then
        WG_SERVER_PUB="$(printf '%s' "$WG_SERVER_PRIV" | wg pubkey 2>/dev/null)"
    fi
    [[ -n "$WG_SERVER_PRIV" && -n "$WG_SERVER_PUB" && -n "$WG_SERVER_ADDR" && -n "$WG_PORT" ]]
}

wg_save_server_state() {
    mkdir -p "$STATE_DIR"
    cat > "$WG_STATE" <<EOF
WG_SERVER_PRIV='${WG_SERVER_PRIV}'
WG_SERVER_PUB='${WG_SERVER_PUB}'
WG_SERVER_ADDR='${WG_SERVER_ADDR}'
WG_DNS='${WG_DNS}'
WG_PORT=${WG_PORT}
WG_OUT_IFACE='${WG_OUT_IFACE}'
EOF
    if [[ -n "${WG_CLIENT_PRIV:-}" && -n "${WG_CLIENT_ADDR:-}" ]]; then
        cat >> "$WG_STATE" <<EOF
WG_CLIENT_PRIV='${WG_CLIENT_PRIV}'
WG_CLIENT_ADDR='${WG_CLIENT_ADDR}'
EOF
    fi
    chmod 600 "$WG_STATE"
}

wg_ensure_server_config() {
    if wg_load_server_state; then
        wg_save_server_state
        return 0
    fi
    ask_port "监听端口 UDP"; WG_PORT="$REPLY_PORT"
    local iface; iface="$(default_iface)"; [[ -n "$iface" ]] || iface="eth0"
    ask_plain_default "出口网卡" "$iface"; WG_OUT_IFACE="$REPLY_VALUE"
    ask_plain_default "WireGuard 服务端内网 IP" "10.66.66.1"; WG_SERVER_ADDR="$REPLY_VALUE"
    ask_plain_default "WireGuard 客户端 DNS" "1.1.1.1, 8.8.8.8"; WG_DNS="$REPLY_VALUE"
    ask_wg_private_key "WireGuard 服务端私钥"; WG_SERVER_PRIV="$REPLY_WG_PRIV"; WG_SERVER_PUB="$REPLY_WG_PUB"
    wg_save_server_state
}

wg_client_config_text() {
    local client_priv="$1" client_addr="$2" dns="$3" host
    host="$(server_host)"
    cat <<EOF
[Interface]
PrivateKey = ${client_priv}
Address = ${client_addr}/24
DNS = ${dns}

[Peer]
PublicKey = ${WG_SERVER_PUB}
Endpoint = ${host}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
}

wg_apply_from_state() {
    wg_load_server_state || { err "未找到 WireGuard 服务端配置。"; return 1; }
    mkdir -p "$WG_DIR"; umask 077
    cat > "$WG_CONF" <<EOF
[Interface]
Address = ${WG_SERVER_ADDR}/24
ListenPort = ${WG_PORT}
PrivateKey = ${WG_SERVER_PRIV}
PostUp = iptables -A FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${WG_OUT_IFACE:-eth0} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${WG_OUT_IFACE:-eth0} -j MASQUERADE

EOF
    if [[ -f "$WG_STATE" ]]; then
        # shellcheck disable=SC1090
        source "$WG_STATE"
        if [[ -n "${WG_CLIENT_PRIV:-}" && -n "${WG_CLIENT_ADDR:-}" ]]; then
            local legacy_pub
            legacy_pub="$(printf '%s' "$WG_CLIENT_PRIV" | wg pubkey 2>/dev/null)"
            cat >> "$WG_CONF" <<EOF
[Peer]
# proxy-manager:legacy
PublicKey = ${legacy_pub}
AllowedIPs = ${WG_CLIENT_ADDR}/32

EOF
        fi
    fi
    if [[ -f "$STATE" ]]; then
        local row tag pub addr
        while IFS=$'\t' read -r tag pub addr; do
            [[ -z "$tag" ]] && continue
            cat >> "$WG_CONF" <<EOF
[Peer]
# proxy-manager:${tag}
PublicKey = ${pub}
AllowedIPs = ${addr}/32

EOF
        done <<< "$(jq -r '.nodes | to_entries[] | select(.value.core == "wireguard-managed") | [.key, (.value.extra_tag | fromjson | .client_pub), (.value.extra_tag | fromjson | .client_addr)] | @tsv' "$STATE" 2>/dev/null)"
    fi
    chmod 600 "$WG_CONF"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    systemctl enable --now "wg-quick@${WG_IFACE}" >/dev/null 2>&1
    systemctl restart "wg-quick@${WG_IFACE}" 2>/dev/null
    sleep 1
    wg_running || { err "WireGuard 启动失败:"; journalctl -u "wg-quick@${WG_IFACE}" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'; return 1; }
}

add_wireguard_peer() {
    wg_ensure_server_config || return 1
    local name client_addr dns c_priv c_pub tag conf detail extra
    ask_name "WireGuard-peer"; name="$REPLY_NAME"
    ask_plain_default "WireGuard 客户端内网 IP" "10.66.66.$(( $(node_count) + 2 ))"; client_addr="$REPLY_VALUE"
    ask_plain_default "WireGuard 客户端 DNS" "${WG_DNS:-1.1.1.1, 8.8.8.8}"; dns="$REPLY_VALUE"
    ask_wg_private_key "WireGuard 客户端私钥"; c_priv="$REPLY_WG_PRIV"; c_pub="$REPLY_WG_PUB"
    tag="wireguard-${client_addr//[^0-9A-Za-z]/-}"
    conf="$(wg_client_config_text "$c_priv" "$client_addr" "$dns")"
    detail="  地址: $(server_host)\n  服务端端口: ${WG_PORT}\n  客户端内网 IP: ${client_addr}\n  DNS: ${dns}\n  服务: wg-quick@${WG_IFACE}"
    extra="$(jq -cn --arg priv "$c_priv" --arg pub "$c_pub" --arg addr "$client_addr" --arg dns "$dns" \
        '{client_priv:$priv, client_pub:$pub, client_addr:$addr, dns:$dns}')"
    save_node "wireguard-managed" "$tag" "WireGuard" "$name" "$conf" "$detail" "$extra"
    wg_apply_from_state || return 1
    echo; hr; ok "  ✅ WireGuard 节点已添加!"; hr
    echo -e "${BOLD}客户端配置:${NC}"
    echo -e "${GREEN}${conf}${NC}"
    hr
}

install_wireguard() {
    echo -e "\n${BLUE}${BOLD}WireGuard${NC} 现代轻量 VPN"
    if ! command -v wg >/dev/null 2>&1; then
        info "安装 wireguard-tools..."
        pkg_install wireguard-tools || pkg_install wireguard || { err "wireguard-tools 安装失败, 请手动安装。"; return 1; }
    fi
    command -v wg >/dev/null 2>&1 || { err "未找到 wg 命令。"; return 1; }
    [[ -f "$WG_CONF" ]] && warn "检测到 WireGuard 服务端配置, 本次将新增客户端 Peer, 不覆盖已有 Peer。"
    add_wireguard_peer
}

# 输出 WireGuard 客户端配置 + 二维码
wg_show_link() {
    [[ -f "$WG_STATE" ]] || { warn "未找到 WireGuard 配置。"; return 0; }
    # shellcheck disable=SC1090
    source "$WG_STATE"
    local host; host="$(server_host)"
    local dns="${WG_DNS:-1.1.1.1, 8.8.8.8}"
    local conf
    conf="$(cat <<EOF
[Interface]
PrivateKey = ${WG_CLIENT_PRIV}
Address = ${WG_CLIENT_ADDR}/24
DNS = ${dns}

[Peer]
PublicKey = ${WG_SERVER_PUB}
Endpoint = ${host}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
)"
    echo -e "${BOLD}客户端配置, 保存为 wg-client.conf 或用 App 扫码:${NC}"
    echo -e "${GREEN}${conf}${NC}"
    echo; echo -e "${BOLD}Mihomo 配置:${NC}"
    echo -e "${GREEN}"
    printf '  - name: "WireGuard"\n    type: wireguard\n    server: "%s"\n    port: %s\n    ip: %s\n    private-key: %s\n    public-key: %s\n    udp: true\n' "$host" "$WG_PORT" "$WG_CLIENT_ADDR" "$WG_CLIENT_PRIV" "$WG_SERVER_PUB"
    echo -e "${NC}"
    if command -v qrencode >/dev/null 2>&1; then
        echo
        echo -e "${BOLD}二维码, WireGuard App 扫码导入:${NC}"
        printf '%s' "$conf" | qrencode -t ANSIUTF8
    fi
    hr
}

uninstall_wireguard() {
    wg_installed || wg_managed_exists || { warn "WireGuard 未安装/未配置。"; return 0; }
    [[ "$1" == "quiet" ]] || confirm "确认卸载 WireGuard?" "n" || return 0
    if [[ -f "$STATE" ]]; then
        local tmp
        tmp="$(mktemp)"
        jq '.nodes |= with_entries(select(.value.core != "wireguard-managed"))' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    fi
    systemctl stop "wg-quick@${WG_IFACE}" 2>/dev/null; systemctl disable "wg-quick@${WG_IFACE}" 2>/dev/null
    rm -f "$WG_CONF" "$WG_STATE"
    ok "WireGuard 已卸载 (wireguard-tools 未移除)。"
}

# ===========================================================================
#  十二、节点查看 / 管理
# ===========================================================================
node_count() { [[ -f "$STATE" ]] && jq '.nodes | length' "$STATE" 2>/dev/null || echo 0; }

view_all_nodes() {
    if [[ "$(node_count)" == "0" ]]; then
        warn "当前没有代理节点。"
    else
        local host; host="$(server_host)"
        echo -e "\n${BOLD}当前节点地址: ${GREEN}${host}${NC}  ${DIM}可在管理菜单改为域名${NC}"
        local t
        while IFS= read -r t; do
            [[ -z "$t" ]] && continue
            local type name link detail
            type="$(jq -r --arg t "$t" '.nodes[$t].type'   "$STATE")"
            name="$(jq -r --arg t "$t" '.nodes[$t].name'   "$STATE")"
            link="$(jq -r --arg t "$t" '.nodes[$t].link'   "$STATE")"
            detail="$(jq -r --arg t "$t" '.nodes[$t].detail' "$STATE")"
            echo; hr
            echo -e "${BOLD}[${type}] ${name}${NC}"
            echo -e "${GREEN}${link}${NC}"
            echo -e "${DIM}${detail}${NC}"
        done <<< "$(jq -r '.nodes | keys[]' "$STATE")"
        hr
    fi
    if snell_installed; then
        echo; hr; snell_show_link
    fi
    if [[ -f "$MIERU_STATE" ]] && grep -q '^MIERU_USER=' "$MIERU_STATE" 2>/dev/null; then
        echo; hr; echo -e "${BOLD}[Mieru]${NC}"; mieru_show_link
    fi
    if [[ -f "$WG_STATE" ]] && grep -q '^WG_CLIENT_PRIV=' "$WG_STATE" 2>/dev/null; then
        echo; hr; echo -e "${BOLD}[WireGuard]${NC}"; wg_show_link
    fi
}

manage_nodes() {
    local -a tags=() names=() cores=() types=() specials=() special_names=() special_types=() special_ports=()
    local t
    if [[ -f "$STATE" ]]; then
        while IFS= read -r t; do
            [[ -z "$t" ]] && continue
            tags+=("$t")
            names+=("$(jq -r --arg t "$t" '.nodes[$t].name' "$STATE")")
            cores+=("$(jq -r --arg t "$t" '.nodes[$t].core' "$STATE")")
            types+=("$(jq -r --arg t "$t" '.nodes[$t].type' "$STATE")")
        done <<< "$(jq -r '.nodes | keys[]' "$STATE" 2>/dev/null)"
    fi
    if snell_installed; then
        snell_load_state
        specials+=("snell"); special_names+=("Snell v${SNELL_VERSION:-?}"); special_types+=("Snell"); special_ports+=("${SNELL_PORT:-未知}")
    fi
    if [[ -f "$MIERU_STATE" ]] && grep -q '^MIERU_USER=' "$MIERU_STATE" 2>/dev/null; then
        local mp mproto
        mp="$(source "$MIERU_STATE" 2>/dev/null; echo "${MIERU_PORT:-未知}")"
        mproto="$(source "$MIERU_STATE" 2>/dev/null; echo "${MIERU_PROTO:-}")"
        specials+=("mieru"); special_names+=("Mieru${mproto:+ ${mproto}}"); special_types+=("Mieru"); special_ports+=("$mp")
    fi
    if [[ -f "$WG_STATE" ]] && grep -q '^WG_CLIENT_PRIV=' "$WG_STATE" 2>/dev/null; then
        local wp
        wp="$(source "$WG_STATE" 2>/dev/null; echo "${WG_PORT:-未知}")"
        specials+=("wireguard"); special_names+=("WireGuard"); special_types+=("WireGuard"); special_ports+=("$wp")
    fi
    local total=$(( ${#tags[@]} + ${#specials[@]} ))
    if (( total == 0 )); then warn "当前没有可管理的节点。"; return 0; fi

    echo -e "\n${BOLD}已部署节点:${NC}"
    local i n=1
    for i in "${!tags[@]}"; do
        printf "  ${GREEN}%2d.${NC} [%s] %s\n" "$n" "${types[$i]}" "${names[$i]}"
        ((n++))
    done
    for i in "${!specials[@]}"; do
        printf "  ${GREEN}%2d.${NC} [%s] %s ${DIM}端口:%s${NC}\n" "$n" "${special_types[$i]}" "${special_names[$i]}" "${special_ports[$i]}"
        ((n++))
    done
    echo -e "  ${GREEN} 0.${NC} 返回"
    local choice
    read -rp "$(echo -e "${CYAN}选择要删除的节点编号: ${NC}")" choice
    [[ "$choice" == "0" || -z "$choice" ]] && return 0
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > total )); then err "无效编号。"; return 1; fi
    if (( choice <= ${#tags[@]} )); then
        local tag="${tags[$((choice-1))]}"
        confirm "确认删除节点 [${names[$((choice-1))]}]?" "n" || return 0
        delete_node "$tag"
    else
        local idx=$((choice-${#tags[@]}-1))
        confirm "确认删除独立节点 [${special_names[$idx]}]? 这会卸载对应服务和配置。" "n" || return 0
        delete_special_node "${specials[$idx]}"
    fi
}

delete_node() {
    local tag="$1" core extra cfg bin tmp
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // "singbox"' "$STATE")"
    if [[ "$core" == "mieru-managed" ]]; then
        delete_mieru_managed_node "$tag"
        return $?
    fi
    if [[ "$core" == "wireguard-managed" ]]; then
        delete_wireguard_managed_node "$tag"
        return $?
    fi
    if [[ "$core" == "snell-managed" ]]; then
        delete_snell_managed_node "$tag"
        return $?
    fi
    if [[ "$core" == "snell-shadowtls" ]]; then
        delete_snell_shadowtls_node "$tag"
        return $?
    fi
    extra="$(jq -r --arg t "$tag" '.nodes[$t].extra_tag // empty' "$STATE")"
    if [[ -n "$extra" && "$extra" != "null" ]]; then
        local obfs_svc
        obfs_svc="$(printf '%s' "$extra" | jq -r 'try .obfs_service catch empty' 2>/dev/null)"
        [[ -n "$obfs_svc" && "$obfs_svc" != "null" ]] && remove_ss_obfs_service "$obfs_svc"
    fi
    if [[ "$core" == "xray" ]]; then cfg="$XRAY_CONFIG"; else cfg="$SB_CONFIG"; fi

    tmp="$(mktemp_json)" || { err "创建临时配置文件失败。"; return 1; }
    if [[ -n "$extra" && "$extra" != "null" ]]; then
        local extra_tag
        if [[ "$extra" == \{* || "$extra" == \[* ]]; then
            extra_tag="$(printf '%s' "$extra" | jq -r 'try (if type == "string" then . else (.extra_tag // empty) end) catch empty' 2>/dev/null)"
        else
            extra_tag="$extra"
        fi
        if [[ -n "$extra_tag" && "$extra_tag" != "null" ]]; then
            jq --arg t "$tag" --arg e "$extra_tag" '.inbounds |= map(select(.tag != $t and .tag != $e))' "$cfg" > "$tmp"
        else
            jq --arg t "$tag" '.inbounds |= map(select(.tag != $t))' "$cfg" > "$tmp"
        fi
    else
        jq --arg t "$tag" '.inbounds |= map(select(.tag != $t))' "$cfg" > "$tmp"
    fi
    if [[ "$core" == "xray" ]]; then
        "$XRAY_BIN" -test -config "$tmp" >/tmp/pm_check.log 2>&1 || { err "删除后校验失败:"; sed 's/^/    /' /tmp/pm_check.log; rm -f "$tmp"; return 1; }
    else
        "$SB_BIN" check -c "$tmp" 2>/tmp/pm_check.log || { err "删除后校验失败:"; sed 's/^/    /' /tmp/pm_check.log; rm -f "$tmp"; return 1; }
    fi
    mv "$tmp" "$cfg"; chmod 600 "$cfg"
    tmp="$(mktemp)"; jq --arg t "$tag" 'del(.nodes[$t])' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    core_restart "$core"
    ok "节点已删除。"
}

delete_state_node_only() {
    local tag="$1" tmp
    [[ -f "$STATE" ]] || return 0
    tmp="$(mktemp)"
    jq --arg t "$tag" 'del(.nodes[$t])' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
}

delete_mieru_managed_node() {
    local tag="$1"
    delete_state_node_only "$tag"
    mieru_apply_from_state || return 1
    ok "Mieru 节点已删除。"
}

delete_wireguard_managed_node() {
    local tag="$1"
    delete_state_node_only "$tag"
    wg_apply_from_state || return 1
    ok "WireGuard 节点已删除。"
}

delete_snell_managed_node() {
    local tag="$1" port svc conf tmp
    port="${tag#snell-}"
    [[ "$port" =~ ^[0-9]+$ ]] || { err "无法从节点标签解析端口: ${tag}"; return 1; }
    svc="$(snell_instance_service "$port")"
    conf="$(snell_instance_conf "$port")"

    systemctl stop "$svc" 2>/dev/null
    systemctl disable "$svc" 2>/dev/null
    rm -f "/etc/systemd/system/${svc}.service" "$conf"
    pm_remove_openrc_service "$svc"
    systemctl daemon-reload 2>/dev/null || true
    if [[ -f "$STATE" ]]; then
        tmp="$(mktemp)"
        jq --arg t "$tag" 'del(.nodes[$t])' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    fi
    ok "Snell 节点已删除。"
}

delete_snell_shadowtls_node() {
    local tag="$1" port stls_svc backend_svc conf tmp
    port="${tag#snell-shadowtls-}"
    [[ "$port" =~ ^[0-9]+$ ]] || { err "无法从节点标签解析端口: ${tag}"; return 1; }
    stls_svc="$(snell_shadowtls_service "$port")"
    backend_svc="$(snell_shadowtls_backend_service "$port")"
    conf="$(snell_shadowtls_conf "$port")"

    systemctl stop "$stls_svc" "$backend_svc" 2>/dev/null
    systemctl disable "$stls_svc" "$backend_svc" 2>/dev/null
    rm -f "/etc/systemd/system/${stls_svc}.service" "/etc/systemd/system/${backend_svc}.service" "$conf"
    pm_remove_openrc_service "$stls_svc" "$backend_svc"
    systemctl daemon-reload 2>/dev/null || true
    if [[ -f "$STATE" ]]; then
        tmp="$(mktemp)"
        jq --arg t "$tag" 'del(.nodes[$t])' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    fi
    ok "Snell+ShadowTLS 节点已删除。"
}

delete_special_node() {
    case "$1" in
        snell) uninstall_snell quiet ;;
        mieru) uninstall_mieru quiet ;;
        wireguard) uninstall_wireguard quiet ;;
        *) err "未知独立节点: $1"; return 1 ;;
    esac
}

replace_link_host() {
    local link="$1" host="$2" js prefix rest after
    if [[ "$link" == vmess://* ]]; then
        js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null | jq --arg h "$host" '.add=$h' 2>/dev/null)"
        if [[ -n "$js" ]]; then printf 'vmess://%s' "$(b64_line "$js")"; else printf '%s' "$link"; fi
        return
    fi
    [[ "$link" == *://*@* ]] || { printf '%s' "$link"; return; }
    prefix="${link%%@*}@"; rest="${link#*@}"
    if [[ "$rest" == \[*\]* ]]; then
        after="${rest#*]}"
        printf '%s%s%s' "$prefix" "$host" "$after"
    elif [[ "$rest" == *:* ]]; then
        after="${rest#*:}"
        printf '%s%s:%s' "$prefix" "$host" "$after"
    else
        printf '%s' "$link"
    fi
}

set_node_host() {
    detect_ip
    echo -e "\n当前自动探测: IPv4=${GREEN}${PUBLIC_IPV4:-无}${NC}  IPv6=${GREEN}${PUBLIC_IPV6:-无}${NC}"
    local cur; cur="$(jq -r '.meta.host // empty' "$STATE" 2>/dev/null)"
    [[ -n "$cur" ]] && echo -e "当前已设置地址: ${GREEN}${cur}${NC}"
    echo -e "${DIM}输入域名让所有节点链接使用该域名; 留空回车则清除, 恢复自动 IP。${NC}"
    local h tmp
    read -rp "$(echo -e "${CYAN}请输入节点地址 域名或 IP, 直接回车清除: ${NC}")" h
    tmp="$(mktemp)"; jq --arg h "$h" '.meta.host = $h' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    if [[ -n "$h" ]]; then ok "节点地址已设置为: $h"; else ok "已恢复自动 IP。"; fi
    rebuild_links
    ok "已同步更新全部节点链接的地址部分。"
}

rebuild_links() {
    [[ -f "$STATE" ]] || return 0
    local host; host="$(server_host)"
    local t link newlink tmp
    while IFS= read -r t; do
        [[ -z "$t" ]] && continue
        link="$(jq -r --arg t "$t" '.nodes[$t].link' "$STATE")"
        newlink="$(replace_link_host "$link" "$host")"
        tmp="$(mktemp)"; jq --arg t "$t" --arg l "$newlink" '.nodes[$t].link = $l' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    done <<< "$(jq -r '.nodes | keys[]' "$STATE" 2>/dev/null)"
}

# ===========================================================================
#  Clash / Mihomo 配置导出 (格式参考 wiki.metacubex.one)
# ===========================================================================
# 从分享链接的 query 取参数并 urldecode
clash_q() {
    local v; v="$(printf '%s' "$1" | grep -oE "[?&]$2=[^&#]*" | head -1 | cut -d= -f2-)"
    [[ -z "$v" ]] && return
    v="${v//+/ }"; printf '%b' "${v//%/\\x}" 2>/dev/null
}
# 从 link 解析 host/port (处理 ipv6 方括号), 结果写全局 CL_HOST CL_PORT
CL_HOST=""; CL_PORT=""
clash_hostport() {
    local hp="${1#*@}"; hp="${hp%%\?*}"; hp="${hp%%#*}"
    hp="${hp%%/*}"
    CL_PORT="${hp##*:}"; CL_HOST="${hp%:*}"
    CL_HOST="${CL_HOST#[}"; CL_HOST="${CL_HOST%]}"
}

# 生成单个节点的 Mihomo YAML (成功输出多行, 不支持则返回空)
clash_node_yaml() {
    local type="$1" name="$2" link="$3"
    case "$type" in
        VLESS-Reality-Vision|VLESS-XHTTP-Reality|VLESS-gRPC-Reality|VLESS-Encryption|VLESS-Encryption-XHTTP|VLESS-WS-TLS|VLESS-gRPC-TLS|VLESS-H2-TLS|VLESS-XHTTP-TLS)
            clash_hostport "$link"
            local uuid="${link#vless://}"; uuid="${uuid%%@*}"
            local security net sni pbk sid flow svc path enc allow_insecure host_header
            security="$(clash_q "$link" security)"; net="$(clash_q "$link" type)"; [[ -z "$net" ]] && net=tcp
            sni="$(clash_q "$link" sni)"; pbk="$(clash_q "$link" pbk)"; sid="$(clash_q "$link" sid)"
            flow="$(clash_q "$link" flow)"; svc="$(clash_q "$link" serviceName)"
            path="$(clash_q "$link" path)"; enc="$(clash_q "$link" encryption)"
            allow_insecure="$(clash_q "$link" allowInsecure)"; host_header="$(clash_q "$link" host)"
            [[ "$net" == "http" ]] && net="h2"
            printf '  - name: "%s"\n    type: vless\n    server: %s\n    port: %s\n    uuid: %s\n    udp: true\n    network: %s\n' \
                "$name" "$CL_HOST" "$CL_PORT" "$uuid" "$net"
            [[ -n "$flow" ]] && printf '    flow: %s\n' "$flow"
            [[ -n "$enc" ]] && printf '    encryption: "%s"\n' "$enc"
            if [[ "$security" == reality ]]; then
                printf '    tls: true\n    servername: %s\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: "%s"\n' "$sni" "$pbk" "$sid"
            elif [[ "$security" == tls ]]; then
                printf '    tls: true\n    servername: %s\n    skip-cert-verify: %s\n' "$sni" "$([[ "$allow_insecure" == "1" ]] && echo true || echo false)"
            fi
            [[ "$net" == grpc && -n "$svc" ]] && printf '    grpc-opts:\n      grpc-service-name: "%s"\n' "$svc"
            if [[ "$net" == ws && -n "$path" ]]; then
                printf '    ws-opts:\n      path: "%s"\n' "$path"
                [[ -n "$host_header" ]] && printf '      headers:\n        Host: %s\n' "$host_header"
            fi
            [[ "$net" == h2 && -n "$path" ]] && printf '    h2-opts:\n      path: "%s"\n' "$path"
            [[ "$net" == xhttp && -n "$path" ]] && printf '    xhttp-opts:\n      path: "%s"\n' "$path"
            ;;
        VMess-WS|VMess-TCP|VMess-mKCP|VMess-QUIC|VMess-WS-TLS|VMess-gRPC-TLS|VMess-H2-TLS)
            local js; js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null)"
            [[ -z "$js" ]] && return
            local net tls sni path host
            net="$(echo "$js" | jq -r '.net // "tcp"')"; tls="$(echo "$js" | jq -r '.tls // ""')"
            sni="$(echo "$js" | jq -r '.sni // empty')"; path="$(echo "$js" | jq -r '.path // empty')"; host="$(echo "$js" | jq -r '.host // empty')"
            [[ "$net" == "h2" ]] && net="h2"
            printf '  - name: "%s"\n    type: vmess\n    server: %s\n    port: %s\n    uuid: %s\n    alterId: 0\n    cipher: auto\n    udp: true\n    network: %s\n' \
                "$name" "$(echo "$js" | jq -r .add)" "$(echo "$js" | jq -r .port)" "$(echo "$js" | jq -r .id)" "$net"
            if [[ "$tls" == "tls" ]]; then
                printf '    tls: true\n    servername: %s\n    skip-cert-verify: true\n' "$sni"
            fi
            if [[ "$net" == ws && -n "$path" ]]; then
                printf '    ws-opts:\n      path: "%s"\n' "$path"
                [[ -n "$host" ]] && printf '      headers:\n        Host: %s\n' "$host"
            fi
            [[ "$net" == grpc && -n "$path" ]] && printf '    grpc-opts:\n      grpc-service-name: "%s"\n' "$path"
            [[ "$net" == h2 && -n "$path" ]] && printf '    h2-opts:\n      path: "%s"\n' "$path"
            ;;
        Trojan-Reality|Trojan-TCP-TLS|Trojan-WS-TLS|Trojan-gRPC-TLS|Trojan-H2-TLS)
            clash_hostport "$link"
            local pw="${link#trojan://}"; pw="${pw%%@*}"
            local security net sni pbk sid svc path allow_insecure host_header
            security="$(clash_q "$link" security)"; net="$(clash_q "$link" type)"; [[ -z "$net" ]] && net=tcp
            sni="$(clash_q "$link" sni)"; pbk="$(clash_q "$link" pbk)"; sid="$(clash_q "$link" sid)"
            svc="$(clash_q "$link" serviceName)"; path="$(clash_q "$link" path)"
            allow_insecure="$(clash_q "$link" allowInsecure)"; host_header="$(clash_q "$link" host)"
            [[ "$net" == "http" ]] && net="h2"
            printf '  - name: "%s"\n    type: trojan\n    server: %s\n    port: %s\n    password: "%s"\n    udp: true\n    network: %s\n    tls: true\n    sni: %s\n' \
                "$name" "$CL_HOST" "$CL_PORT" "$pw" "$net" "$sni"
            if [[ "$security" == reality ]]; then
                printf '    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: "%s"\n' "$pbk" "$sid"
            else
                printf '    skip-cert-verify: %s\n' "$([[ "$allow_insecure" == "1" ]] && echo true || echo false)"
            fi
            if [[ "$net" == ws && -n "$path" ]]; then
                printf '    ws-opts:\n      path: "%s"\n' "$path"
                [[ -n "$host_header" ]] && printf '      headers:\n        Host: %s\n' "$host_header"
            fi
            [[ "$net" == grpc && -n "$svc" ]] && printf '    grpc-opts:\n      grpc-service-name: "%s"\n' "$svc"
            [[ "$net" == h2 && -n "$path" ]] && printf '    h2-opts:\n      path: "%s"\n' "$path"
            ;;
        Shadowsocks|SS2022)
            clash_hostport "$link"
            local ui="${link#ss://}"; ui="${ui%%@*}"
            local dec; dec="$(b64_urlsafe_decode "$ui")"
            printf '  - name: "%s"\n    type: ss\n    server: %s\n    port: %s\n    cipher: %s\n    password: "%s"\n    udp: true\n' \
                "$name" "$CL_HOST" "$CL_PORT" "${dec%%:*}" "${dec#*:}"
            local plugin obfs_host
            plugin="$(clash_q "$link" plugin)"
            if [[ "$plugin" == *"obfs=http"* ]]; then
                obfs_host="$(printf '%s' "$plugin" | sed -n 's/.*obfs-host=\([^;]*\).*/\1/p')"
                [[ -z "$obfs_host" ]] && obfs_host="www.microsoft.com"
                printf '    plugin: obfs\n    plugin-opts:\n      mode: http\n      host: %s\n' "$obfs_host"
            fi
            ;;
        SOCKS5)
            clash_hostport "$link"
            local ui="${link#socks://}"; ui="${ui%%@*}"
            local dec; dec="$(b64_urlsafe_decode "$ui")"
            printf '  - name: "%s"\n    type: socks5\n    server: %s\n    port: %s\n    username: "%s"\n    password: "%s"\n    udp: true\n' \
                "$name" "$CL_HOST" "$CL_PORT" "${dec%%:*}" "${dec#*:}"
            ;;
        HTTP)
            clash_hostport "$link"
            local ui="${link#http://}"; ui="${ui%%@*}"
            printf '  - name: "%s"\n    type: http\n    server: %s\n    port: %s\n    username: "%s"\n    password: "%s"\n' \
                "$name" "$CL_HOST" "$CL_PORT" "${ui%%:*}" "${ui#*:}"
            ;;
        Hysteria2)
            clash_hostport "$link"
            local pw="${link#hysteria2://}"; pw="${pw%%@*}"
            local sni; sni="$(clash_q "$link" sni)"; [[ -z "$sni" ]] && sni="www.bing.com"
            printf '  - name: "%s"\n    type: hysteria2\n    server: %s\n    port: %s\n    password: "%s"\n    sni: %s\n    skip-cert-verify: true\n    alpn:\n      - h3\n' \
                "$name" "$CL_HOST" "$CL_PORT" "$pw" "$sni"
            ;;
        TUIC)
            clash_hostport "$link"
            local ui="${link#tuic://}"; ui="${ui%%@*}"
            local sni; sni="$(clash_q "$link" sni)"; [[ -z "$sni" ]] && sni="www.bing.com"
            printf '  - name: "%s"\n    type: tuic\n    server: %s\n    port: %s\n    uuid: %s\n    password: "%s"\n    sni: %s\n    skip-cert-verify: true\n    udp-relay-mode: native\n    congestion-controller: bbr\n    alpn:\n      - h3\n' \
                "$name" "$CL_HOST" "$CL_PORT" "${ui%%:*}" "${ui#*:}" "$sni"
            ;;
        AnyTLS)
            clash_hostport "$link"
            local pw="${link#anytls://}"; pw="${pw%%@*}"
            local sni; sni="$(clash_q "$link" sni)"; [[ -z "$sni" ]] && sni="www.bing.com"
            printf '  - name: "%s"\n    type: anytls\n    server: %s\n    port: %s\n    password: "%s"\n    sni: %s\n    skip-cert-verify: true\n    client-fingerprint: chrome\n    udp: true\n' \
                "$name" "$CL_HOST" "$CL_PORT" "$pw" "$sni"
            ;;
        *) return ;;  # ShadowTLS / NaïveProxy 等 Mihomo 不便直接导出
    esac
}

# ---- 编辑节点配置 ----
node_get_port() {
    local tag="$1" core="$2"
    if [[ "$core" == "mieru-managed" ]]; then
        printf '%s\n' "${tag#mieru-}"
    elif [[ "$core" == "wireguard-managed" ]]; then
        jq -r --arg t "$tag" '.nodes[$t].extra_tag | fromjson | .client_addr // empty' "$STATE" 2>/dev/null
    elif [[ "$core" == "snell-managed" ]]; then
        printf '%s\n' "${tag#snell-}"
    elif [[ "$core" == "snell-shadowtls" ]]; then
        printf '%s\n' "${tag#snell-shadowtls-}"
    elif [[ "$core" == "xray" ]]; then
        jq -r --arg t "$tag" '.inbounds[]|select(.tag==$t).port // empty' "$XRAY_CONFIG" 2>/dev/null
    else
        jq -r --arg t "$tag" '.inbounds[]|select(.tag==$t).listen_port // empty' "$SB_CONFIG" 2>/dev/null
    fi
}

# 应用配置文件变更: 校验 -> 备份 -> 生效 -> 重启 -> 失败回滚
core_apply_file() {
    local core="$1" tmp="$2" cfg check_tmp
    if [[ "$core" == "xray" ]]; then
        cfg="$XRAY_CONFIG"
        check_tmp="$tmp"
        if [[ "$check_tmp" != *.json ]]; then
            check_tmp="$(mktemp_json)" || { err "创建临时配置文件失败。"; rm -f "$tmp"; return 1; }
            cp "$tmp" "$check_tmp" || { err "复制临时配置文件失败。"; rm -f "$tmp" "$check_tmp"; return 1; }
        fi
        "$XRAY_BIN" -test -config "$check_tmp" >/tmp/pm_check.log 2>&1 || { err "配置校验失败:"; sed 's/^/    /' /tmp/pm_check.log; rm -f "$tmp"; [[ "$check_tmp" != "$tmp" ]] && rm -f "$check_tmp"; return 1; }
        [[ "$check_tmp" != "$tmp" ]] && rm -f "$check_tmp"
    else
        cfg="$SB_CONFIG"
        "$SB_BIN" check -c "$tmp" 2>/tmp/pm_check.log || { err "配置校验失败:"; sed 's/^/    /' /tmp/pm_check.log; rm -f "$tmp"; return 1; }
    fi
    cp "$cfg" "${cfg}.bak" 2>/dev/null
    mv "$tmp" "$cfg"; chmod 600 "$cfg"
    core_restart "$core" || { warn "启动失败, 回滚配置..."; mv "${cfg}.bak" "$cfg" 2>/dev/null; core_restart "$core"; return 1; }
}

# 同步更新 state 中链接与 detail 的端口
state_update_link_port() {
    local tag="$1" np="$2" link newlink tmp js
    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    if [[ "$link" == vmess://* ]]; then
        js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null | jq --arg p "$np" '.port=$p' 2>/dev/null)"
        [[ -n "$js" ]] && newlink="vmess://$(b64_line "$js")" || newlink="$link"
    else
        newlink="$(printf '%s' "$link" | sed -E "s#(@[^?#]*:)[0-9]+#\1${np}#")"
    fi
    tmp="$(mktemp)"
    jq --arg t "$tag" --arg l "$newlink" --arg p "$np" \
       '.nodes[$t].link=$l | .nodes[$t].detail=(.nodes[$t].detail | gsub("端口: [0-9]+"; "端口: "+$p))' \
       "$STATE" > "$tmp" && mv "$tmp" "$STATE"
}

change_node_port() {
    local tag="$1" core old cfg tmp
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // "singbox"' "$STATE")"
    old="$(node_get_port "$tag" "$core")"
    echo -e "当前端口: ${GREEN}${old:-未知}${NC}"
    ask_port "新端口"; local np="$REPLY_PORT"
    if [[ "$core" == "xray" ]]; then cfg="$XRAY_CONFIG"; else cfg="$SB_CONFIG"; fi
    tmp="$(mktemp)"
    if [[ "$core" == "xray" ]]; then
        jq --arg t "$tag" --argjson p "$np" '(.inbounds[]|select(.tag==$t).port)=$p' "$cfg" > "$tmp"
    else
        jq --arg t "$tag" --argjson p "$np" '(.inbounds[]|select(.tag==$t).listen_port)=$p' "$cfg" > "$tmp"
    fi
    core_apply_file "$core" "$tmp" || return 1
    state_update_link_port "$tag" "$np"
    ok "端口已改为 ${np}。请用[查看全部节点]查看新链接与二维码。"
}

change_node_name() {
    local tag="$1" cur new link newlink tmp js
    cur="$(jq -r --arg t "$tag" '.nodes[$t].name' "$STATE")"
    echo -e "当前备注名: ${GREEN}${cur}${NC}"
    read -rp "$(echo -e "${CYAN}新备注名: ${NC}")" new
    [[ -z "$new" ]] && { warn "未修改。"; return 0; }
    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    if [[ "$link" == vmess://* ]]; then
        js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null | jq --arg n "$new" '.ps=$n')"
        newlink="vmess://$(b64_line "$js")"
    else
        newlink="$(printf '%s' "$link" | sed -E "s/#.*/#$(url_encode "$new")/")"
    fi
    tmp="$(mktemp)"
    jq --arg t "$tag" --arg n "$new" --arg l "$newlink" '.nodes[$t].name=$n | .nodes[$t].link=$l' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    ok "备注名已改为 ${new}。"
}

link_set_query_param() {
    local link="$1" key="$2" val="$3" enc base fragment prefix query newq kv k found=""
    enc="$(url_encode "$val")"
    if [[ "$link" == *#* ]]; then
        fragment="#${link#*#}"
        base="${link%%#*}"
    else
        fragment=""
        base="$link"
    fi
    if [[ "$base" != *\?* ]]; then
        printf '%s?%s=%s%s' "$base" "$key" "$enc" "$fragment"
        return
    fi
    prefix="${base%%\?*}"
    query="${base#*\?}"
    IFS='&' read -r -a pairs <<< "$query"
    newq=""
    for kv in "${pairs[@]}"; do
        k="${kv%%=*}"
        [[ -n "$newq" ]] && newq+="&"
        if [[ "$k" == "$key" ]]; then
            newq+="${key}=${enc}"
            found="1"
        else
            newq+="$kv"
        fi
    done
    if [[ -z "$found" ]]; then
        [[ -n "$newq" ]] && newq+="&"
        newq+="${key}=${enc}"
    fi
    printf '%s?%s%s' "$prefix" "$newq" "$fragment"
}

link_set_userinfo() {
    local link="$1" userinfo="$2" scheme rest
    [[ "$link" == *://*@* ]] || { printf '%s' "$link"; return; }
    scheme="${link%%://*}"
    rest="${link#*://}"
    printf '%s://%s@%s' "$scheme" "$userinfo" "${rest#*@}"
}

state_set_link_and_gsub() {
    local tag="$1" link="$2" pattern="$3" replacement="$4" tmp
    tmp="$(mktemp)"
    jq --arg t "$tag" --arg l "$link" --arg pat "$pattern" --arg rep "$replacement" \
       '.nodes[$t].link=$l | .nodes[$t].detail=(.nodes[$t].detail | gsub($pat; $rep))' \
       "$STATE" > "$tmp" && mv "$tmp" "$STATE"
}

state_gsub_detail() {
    local tag="$1" pattern="$2" replacement="$3" tmp
    tmp="$(mktemp)"
    jq --arg t "$tag" --arg pat "$pattern" --arg rep "$replacement" \
       '.nodes[$t].detail=(.nodes[$t].detail | gsub($pat; $rep))' \
       "$STATE" > "$tmp" && mv "$tmp" "$STATE"
}

node_stream_network() {
    local tag="$1" core="$2" cfg
    [[ "$core" == "xray" ]] && cfg="$XRAY_CONFIG" || cfg="$SB_CONFIG"
    jq -r --arg t "$tag" '.inbounds[]? | select(.tag==$t) | (.streamSettings.network // .type // empty)' "$cfg" 2>/dev/null
}

change_node_uuid() {
    local tag="$1" core type cfg tmp uuid link newlink js
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // empty' "$STATE")"
    type="$(jq -r --arg t "$tag" '.nodes[$t].type // empty' "$STATE")"
    [[ "$core" == "xray" && ( "$type" == VLESS-* || "$type" == VMess-* ) ]] || { warn "该节点不支持修改 UUID。"; return 0; }
    read -rp "$(echo -e "${CYAN}新 UUID, 回车随机生成: ${NC}")" uuid
    [[ -z "$uuid" ]] && uuid="$(gen_uuid)"
    [[ "$uuid" =~ ^[0-9a-fA-F-]{32,36}$ ]] || { err "UUID 格式不正确。"; return 1; }
    cfg="$XRAY_CONFIG"; tmp="$(mktemp)"
    jq --arg t "$tag" --arg v "$uuid" '(.inbounds[]|select(.tag==$t).settings.clients[]?.id)=$v' "$cfg" > "$tmp"
    core_apply_file "$core" "$tmp" || return 1

    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    if [[ "$link" == vmess://* ]]; then
        js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null | jq --arg v "$uuid" '.id=$v' 2>/dev/null)"
        [[ -n "$js" ]] && newlink="vmess://$(b64_line "$js")" || newlink="$link"
    else
        newlink="$(link_set_userinfo "$link" "$uuid")"
    fi
    state_set_link_and_gsub "$tag" "$newlink" "UUID: [^\n]+" "UUID: ${uuid}"
    ok "UUID 已更新。"
}

change_node_password() {
    local tag="$1" core type cfg tmp new link newlink ui dec method user uuid js
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // empty' "$STATE")"
    type="$(jq -r --arg t "$tag" '.nodes[$t].type // empty' "$STATE")"
    read -rp "$(echo -e "${CYAN}新密码, 回车随机生成: ${NC}")" new
    if [[ -z "$new" ]]; then
        if [[ "$type" == "SS2022" ]]; then
            method="$(jq -r --arg t "$tag" '.inbounds[]|select(.tag==$t).settings.method // empty' "$XRAY_CONFIG" 2>/dev/null)"
            new="$(gen_b64 "$(ss2022_key_bytes "$method")")"
        else
            new="$(gen_pass 16)"
        fi
    fi
    [[ "$new" == *"@"* || "$new" == *"#"* || "$new" == *" "* ]] && { err "密码不能包含 @、# 或空格。"; return 1; }
    if [[ "$type" == "SS2022" ]]; then
        [[ -n "$method" ]] || method="$(jq -r --arg t "$tag" '.inbounds[]|select(.tag==$t).settings.method // empty' "$XRAY_CONFIG" 2>/dev/null)"
        ss2022_psk_valid "$method" "$new" || { err "SS2022 密码必须是 $(ss2022_key_bytes "$method") 字节随机值的 base64 PSK。"; return 1; }
    fi
    [[ "$core" == "xray" ]] && cfg="$XRAY_CONFIG" || cfg="$SB_CONFIG"
    tmp="$(mktemp)"
    case "$type" in
        Trojan-*)
            [[ "$core" == "xray" ]] || { warn "该节点不支持修改密码。"; rm -f "$tmp"; return 0; }
            jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).settings.clients[]?.password)=$v' "$cfg" > "$tmp"
            ;;
        Shadowsocks|SS2022)
            jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).settings.password)=$v' "$cfg" > "$tmp"
            ;;
        SOCKS5|HTTP)
            jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).settings.accounts[]?.pass)=$v' "$cfg" > "$tmp"
            ;;
        Hysteria2|TUIC|AnyTLS)
            jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).users[]?.password)=$v' "$cfg" > "$tmp"
            ;;
        NaïveProxy)
            jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).users[]?.password)=$v' "$cfg" > "$tmp"
            ;;
        *)
            warn "该节点不支持修改密码。"; rm -f "$tmp"; return 0 ;;
    esac
    core_apply_file "$core" "$tmp" || return 1

    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    case "$type" in
        Trojan-*|Hysteria2|AnyTLS) newlink="$(link_set_userinfo "$link" "$new")" ;;
        Shadowsocks|SS2022)
            ui="${link#ss://}"; ui="${ui%%@*}"; dec="$(b64_urlsafe_decode "$ui")"; method="${dec%%:*}"
            newlink="$(link_set_userinfo "$link" "$(b64_urlsafe "${method}:${new}")")"
            ;;
        SOCKS5)
            ui="${link#socks://}"; ui="${ui%%@*}"; dec="$(b64_urlsafe_decode "$ui")"; user="${dec%%:*}"
            newlink="$(link_set_userinfo "$link" "$(b64_urlsafe "${user}:${new}")")"
            ;;
        HTTP|NaïveProxy)
            ui="${link#*://}"; ui="${ui%%@*}"; user="${ui%%:*}"
            newlink="$(link_set_userinfo "$link" "${user}:${new}")"
            ;;
        TUIC)
            ui="${link#tuic://}"; ui="${ui%%@*}"; uuid="${ui%%:*}"
            newlink="$(link_set_userinfo "$link" "${uuid}:${new}")"
            ;;
    esac
    state_set_link_and_gsub "$tag" "$newlink" "密码: [^\n]+" "密码: ${new}"
    ok "密码已更新。"
}

change_node_username() {
    local tag="$1" core type cfg tmp new link newlink ui dec pass
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // empty' "$STATE")"
    type="$(jq -r --arg t "$tag" '.nodes[$t].type // empty' "$STATE")"
    case "$type" in SOCKS5|HTTP|NaïveProxy) ;; *) warn "该节点不支持修改用户名。"; return 0 ;; esac
    read -rp "$(echo -e "${CYAN}新用户名: ${NC}")" new
    [[ -z "$new" ]] && { warn "未修改。"; return 0; }
    [[ "$new" == *":"* || "$new" == *"@"* || "$new" == *"#"* || "$new" == *" "* ]] && { err "用户名不能包含 :、@、# 或空格。"; return 1; }
    [[ "$core" == "xray" ]] && cfg="$XRAY_CONFIG" || cfg="$SB_CONFIG"
    tmp="$(mktemp)"
    case "$type" in
        SOCKS5|HTTP) jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).settings.accounts[]?.user)=$v' "$cfg" > "$tmp" ;;
        NaïveProxy) jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).users[]?.username)=$v' "$cfg" > "$tmp" ;;
    esac
    core_apply_file "$core" "$tmp" || return 1

    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    case "$type" in
        SOCKS5)
            ui="${link#socks://}"; ui="${ui%%@*}"; dec="$(b64_urlsafe_decode "$ui")"; pass="${dec#*:}"
            newlink="$(link_set_userinfo "$link" "$(b64_urlsafe "${new}:${pass}")")"
            ;;
        HTTP|NaïveProxy)
            ui="${link#*://}"; ui="${ui%%@*}"; pass="${ui#*:}"
            newlink="$(link_set_userinfo "$link" "${new}:${pass}")"
            ;;
    esac
    state_set_link_and_gsub "$tag" "$newlink" "用户名: [^\n]+" "用户名: ${new}"
    ok "用户名已更新。"
}

change_node_path() {
    local tag="$1" core type cfg tmp net new key link newlink js
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // empty' "$STATE")"
    type="$(jq -r --arg t "$tag" '.nodes[$t].type // empty' "$STATE")"
    [[ "$core" == "xray" ]] || { warn "该节点不支持修改路径。"; return 0; }
    net="$(node_stream_network "$tag" "$core")"
    case "$net" in ws|http|xhttp|grpc) ;; *) warn "该节点没有可修改的 Path/serviceName。"; return 0 ;; esac
    if [[ "$net" == "grpc" ]]; then
        read -rp "$(echo -e "${CYAN}新的 gRPC serviceName: ${NC}")" new
        key="serviceName"
    else
        read -rp "$(echo -e "${CYAN}新的 Path, 回车随机: ${NC}")" new
        [[ -z "$new" ]] && new="/$(openssl rand -hex 4)"
        [[ "$new" == /* ]] || new="/${new}"
        key="path"
    fi
    [[ -z "$new" ]] && { warn "未修改。"; return 0; }
    cfg="$XRAY_CONFIG"; tmp="$(mktemp)"
    case "$net" in
        ws)    jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).streamSettings.wsSettings.path)=$v' "$cfg" > "$tmp" ;;
        http)  jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).streamSettings.httpSettings.path)=$v' "$cfg" > "$tmp" ;;
        xhttp) jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).streamSettings.xhttpSettings.path)=$v' "$cfg" > "$tmp" ;;
        grpc)  jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).streamSettings.grpcSettings.serviceName)=$v' "$cfg" > "$tmp" ;;
    esac
    core_apply_file "$core" "$tmp" || return 1

    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    if [[ "$link" == vmess://* ]]; then
        js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null | jq --arg v "$new" '.path=$v' 2>/dev/null)"
        [[ -n "$js" ]] && newlink="vmess://$(b64_line "$js")" || newlink="$link"
    else
        newlink="$(link_set_query_param "$link" "$key" "$new")"
    fi
    if [[ "$net" == "grpc" ]]; then
        state_set_link_and_gsub "$tag" "$newlink" "serviceName: [^\n]+" "serviceName: ${new}"
    else
        state_set_link_and_gsub "$tag" "$newlink" "Path: [^ \n]+" "Path: ${new}"
    fi
    ok "Path/serviceName 已更新。"
}

change_node_sni() {
    local tag="$1" core cfg tmp net security new link newlink js
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // empty' "$STATE")"
    [[ "$core" == "xray" ]] || { warn "该节点不支持修改 SNI/Host。"; return 0; }
    cfg="$XRAY_CONFIG"
    security="$(jq -r --arg t "$tag" '.inbounds[]|select(.tag==$t).streamSettings.security // empty' "$cfg" 2>/dev/null)"
    net="$(node_stream_network "$tag" "$core")"
    [[ "$security" == "reality" || "$security" == "tls" ]] || { warn "该节点没有 SNI/Host。"; return 0; }
    read -rp "$(echo -e "${CYAN}新的 SNI/Host: ${NC}")" new
    [[ -z "$new" ]] && { warn "未修改。"; return 0; }
    tmp="$(mktemp)"
    jq --arg t "$tag" --arg v "$new" '
      (.inbounds[]|select(.tag==$t).streamSettings) |=
      (if .security=="reality" then
          .realitySettings.serverNames=[$v] | .realitySettings.dest=($v+":443")
       elif .security=="tls" and .httpSettings? then
          .httpSettings.host=[$v]
       else . end)' "$cfg" > "$tmp"
    core_apply_file "$core" "$tmp" || return 1

    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    if [[ "$link" == vmess://* ]]; then
        js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null | jq --arg v "$new" '.sni=$v | if (.net=="ws" or .net=="h2") then .host=$v else . end' 2>/dev/null)"
        [[ -n "$js" ]] && newlink="vmess://$(b64_line "$js")" || newlink="$link"
    else
        newlink="$(link_set_query_param "$link" "sni" "$new")"
        if [[ "$newlink" == *"host="* ]]; then
            newlink="$(link_set_query_param "$newlink" "host" "$new")"
        fi
    fi
    state_set_link_and_gsub "$tag" "$newlink" "SNI ?: [^\n]+" "SNI : ${new}"
    state_gsub_detail "$tag" "TLS SNI: [^\n]+" "TLS SNI: ${new}"
    ok "SNI/Host 已更新。"
}

change_node_method() {
    local tag="$1" type cfg tmp choice method pw link newlink
    type="$(jq -r --arg t "$tag" '.nodes[$t].type // empty' "$STATE")"
    [[ "$type" == "Shadowsocks" || "$type" == "SS2022" ]] || { warn "仅 Shadowsocks 节点支持修改加密方式。"; return 0; }
    echo -e "${CYAN}选择加密方式:${NC}"
    if [[ "$type" == "SS2022" ]]; then
        echo -e "  ${GREEN}1.${NC} 2022-blake3-aes-128-gcm"
        echo -e "  ${GREEN}2.${NC} 2022-blake3-aes-256-gcm"
        echo -e "  ${GREEN}3.${NC} 2022-blake3-chacha20-poly1305"
        read -rp "$(echo -e "${CYAN}请选择 [1-3]: ${NC}")" choice
        case "$choice" in
            1) method="2022-blake3-aes-128-gcm"; pw="$(gen_b64 "$(ss2022_key_bytes "$method")")" ;;
            2) method="2022-blake3-aes-256-gcm"; pw="$(gen_b64 "$(ss2022_key_bytes "$method")")" ;;
            3) method="2022-blake3-chacha20-poly1305"; pw="$(gen_b64 "$(ss2022_key_bytes "$method")")" ;;
            *) err "无效选项。"; return 1 ;;
        esac
    else
        echo -e "  ${GREEN}1.${NC} aes-128-gcm"
        echo -e "  ${GREEN}2.${NC} aes-256-gcm"
        echo -e "  ${GREEN}3.${NC} chacha20-poly1305"
        read -rp "$(echo -e "${CYAN}请选择 [1-3, 默认2]: ${NC}")" choice
        case "$choice" in
            1) method="aes-128-gcm" ;;
            3) method="chacha20-poly1305" ;;
            *) method="aes-256-gcm" ;;
        esac
        pw="$(gen_pass 16)"
    fi
    cfg="$XRAY_CONFIG"; tmp="$(mktemp)"
    jq --arg t "$tag" --arg m "$method" --arg p "$pw" '(.inbounds[]|select(.tag==$t).settings.method)=$m | (.inbounds[]|select(.tag==$t).settings.password)=$p' "$cfg" > "$tmp"
    core_apply_file "xray" "$tmp" || return 1
    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    newlink="$(link_set_userinfo "$link" "$(b64_urlsafe "${method}:${pw}")")"
    state_set_link_and_gsub "$tag" "$newlink" "加密: [^\n]+" "加密: ${method}"
    state_gsub_detail "$tag" "密码: [^\n]+" "密码: ${pw}"
    ok "加密方式已更新, 新密码已按所选算法重新生成。"
}

change_node_obfs_type() {
    local tag="$1" core type cfg tmp net choice new link newlink js
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // empty' "$STATE")"
    type="$(jq -r --arg t "$tag" '.nodes[$t].type // empty' "$STATE")"
    [[ "$core" == "xray" && ( "$type" == "VMess-TCP" || "$type" == "VMess-mKCP" || "$type" == "VMess-QUIC" ) ]] || { warn "仅 VMess TCP/mKCP/QUIC 支持修改伪装类型。"; return 0; }
    net="$(node_stream_network "$tag" "$core")"
    echo -e "${CYAN}选择伪装类型:${NC}"
    if [[ "$net" == "tcp" ]]; then
        echo -e "  ${GREEN}1.${NC} none   ${GREEN}2.${NC} http"
        read -rp "$(echo -e "${CYAN}请选择 [1-2]: ${NC}")" choice
        case "$choice" in 2) new="http" ;; 1|"") new="none" ;; *) err "无效选项。"; return 1 ;; esac
    else
        echo -e "  ${GREEN}1.${NC} none   ${GREEN}2.${NC} srtp   ${GREEN}3.${NC} utp   ${GREEN}4.${NC} wechat-video   ${GREEN}5.${NC} dtls   ${GREEN}6.${NC} wireguard"
        read -rp "$(echo -e "${CYAN}请选择 [1-6]: ${NC}")" choice
        case "$choice" in
            2) new="srtp" ;; 3) new="utp" ;; 4) new="wechat-video" ;; 5) new="dtls" ;; 6) new="wireguard" ;; 1|"") new="none" ;;
            *) err "无效选项。"; return 1 ;;
        esac
    fi
    cfg="$XRAY_CONFIG"; tmp="$(mktemp)"
    case "$net" in
        tcp)  jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).streamSettings.tcpSettings.header.type)=$v' "$cfg" > "$tmp" ;;
        kcp)  jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).streamSettings.kcpSettings.header.type)=$v' "$cfg" > "$tmp" ;;
        quic) jq --arg t "$tag" --arg v "$new" '(.inbounds[]|select(.tag==$t).streamSettings.quicSettings.header.type)=$v' "$cfg" > "$tmp" ;;
    esac
    core_apply_file "$core" "$tmp" || return 1
    link="$(jq -r --arg t "$tag" '.nodes[$t].link' "$STATE")"
    js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null | jq --arg v "$new" '.type=$v' 2>/dev/null)"
    [[ -n "$js" ]] && newlink="vmess://$(b64_line "$js")" || newlink="$link"
    state_set_link_and_gsub "$tag" "$newlink" "header: [^\n]+" "header: ${new}"
    state_gsub_detail "$tag" "security/header: [^\n]+" "security/header: ${new}"
    ok "伪装类型已更新。"
}

node_has_path() {
    local tag="$1" core="$2" net
    [[ "$core" == "xray" ]] || return 1
    net="$(node_stream_network "$tag" "$core")"
    [[ "$net" == "ws" || "$net" == "http" || "$net" == "xhttp" || "$net" == "grpc" ]]
}

node_has_sni() {
    local tag="$1" core="$2" cfg security
    [[ "$core" == "xray" ]] || return 1
    cfg="$XRAY_CONFIG"
    security="$(jq -r --arg t "$tag" '.inbounds[]|select(.tag==$t).streamSettings.security // empty' "$cfg" 2>/dev/null)"
    [[ "$security" == "reality" || "$security" == "tls" ]]
}

add_edit_option() {
    EDIT_LABELS+=("$1")
    EDIT_FUNCS+=("$2")
}

PICKED_TAG=""; PICKED_SPECIAL=""
pick_node() {
    PICKED_TAG=""; PICKED_SPECIAL=""
    local -a tags=() specials=(); local t
    while IFS= read -r t; do [[ -z "$t" ]] && continue; tags+=("$t"); done <<< "$(jq -r '.nodes|keys[]' "$STATE" 2>/dev/null)"
    snell_installed && specials+=("snell")
    [[ -f "$MIERU_STATE" ]] && grep -q '^MIERU_USER=' "$MIERU_STATE" 2>/dev/null && specials+=("mieru")
    [[ -f "$WG_STATE" ]] && grep -q '^WG_CLIENT_PRIV=' "$WG_STATE" 2>/dev/null && specials+=("wireguard")
    if (( ${#tags[@]} + ${#specials[@]} == 0 )); then warn "当前没有可编辑的节点。"; return 1; fi
    echo -e "\n${BOLD}请选择要修改的节点:${NC}"
    local i type name core port n=1
    for i in "${!tags[@]}"; do
        type="$(jq -r --arg t "${tags[$i]}" '.nodes[$t].type' "$STATE")"
        name="$(jq -r --arg t "${tags[$i]}" '.nodes[$t].name' "$STATE")"
        core="$(jq -r --arg t "${tags[$i]}" '.nodes[$t].core' "$STATE")"
        port="$(node_get_port "${tags[$i]}" "$core")"
        printf "  ${GREEN}%2d.${NC} %-26s %-24s ${DIM}端口:%s${NC}\n" "$n" "[$type]" "$name" "${port:-未知}"
        ((n++))
    done
    for type in "${specials[@]}"; do
        case "$type" in
            snell) snell_load_state; name="Snell v${SNELL_VERSION:-?}"; port="${SNELL_PORT:-未知}" ;;
            mieru) name="Mieru"; port="$(source "$MIERU_STATE" 2>/dev/null; echo "${MIERU_PORT:-未知}")" ;;
            wireguard) name="WireGuard"; port="$(source "$WG_STATE" 2>/dev/null; echo "${WG_PORT:-未知}")" ;;
        esac
        printf "  ${GREEN}%2d.${NC} %-26s %-24s ${DIM}端口:%s${NC}\n" "$n" "[独立协议]" "$name" "$port"
        ((n++))
    done
    echo -e "  ${GREEN} 0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}选择节点编号: ${NC}")" c
    [[ "$c" == "0" || -z "$c" ]] && return 1
    if ! [[ "$c" =~ ^[0-9]+$ ]] || (( c<1 || c>=n )); then err "无效编号。"; return 1; fi
    if (( c <= ${#tags[@]} )); then
        PICKED_TAG="${tags[$((c-1))]}"
    else
        PICKED_SPECIAL="${specials[$((c-${#tags[@]}-1))]}"
    fi
}

edit_special_node() {
    case "$1" in
        snell)
            confirm "Snell 为独立服务, 将进入安装流程覆盖当前配置, 是否继续?" "n" && install_snell
            ;;
        mieru)
            confirm "Mieru 为独立服务, 将重新应用配置覆盖当前节点, 是否继续?" "n" && configure_mieru
            ;;
        wireguard)
            confirm "WireGuard 为独立服务, 将覆盖重建当前配置, 是否继续?" "n" && install_wireguard
            ;;
    esac
}

edit_single_node() {
    local tag="$1" core type name port i c fn
    [[ -n "$tag" ]] || return 0
    core="$(jq -r --arg t "$tag" '.nodes[$t].core' "$STATE")"
    type="$(jq -r --arg t "$tag" '.nodes[$t].type' "$STATE")"
    name="$(jq -r --arg t "$tag" '.nodes[$t].name' "$STATE")"
    port="$(node_get_port "$tag" "$core")"
    EDIT_LABELS=()
    EDIT_FUNCS=()
    if [[ "$core" == "snell-managed" || "$core" == "snell-shadowtls" || "$core" == "mieru-managed" || "$core" == "wireguard-managed" ]]; then
        add_edit_option "修改备注名" "change_node_name"
    else
        add_edit_option "修改端口" "change_node_port"
        add_edit_option "修改备注名" "change_node_name"
        case "$type" in
            VLESS-*|VMess-*) add_edit_option "修改 UUID" "change_node_uuid" ;;
        esac
        case "$type" in
            Trojan-*|Shadowsocks|SS2022|SOCKS5|HTTP|Hysteria2|TUIC|AnyTLS|NaïveProxy)
                add_edit_option "修改密码" "change_node_password" ;;
        esac
        case "$type" in
            SOCKS5|HTTP|NaïveProxy) add_edit_option "修改用户名" "change_node_username" ;;
        esac
        node_has_path "$tag" "$core" && add_edit_option "修改 Path/serviceName" "change_node_path"
        node_has_sni "$tag" "$core" && add_edit_option "修改 SNI/Host" "change_node_sni"
        case "$type" in
            Shadowsocks|SS2022) add_edit_option "修改加密方式" "change_node_method" ;;
            VMess-TCP|VMess-mKCP|VMess-QUIC) add_edit_option "修改伪装类型" "change_node_obfs_type" ;;
        esac
    fi

    echo -e "\n${BOLD}编辑节点: [${type}] ${name}   当前端口: ${port:-未知}${NC}"
    for i in "${!EDIT_LABELS[@]}"; do
        printf "  ${GREEN}%2d.${NC} %s\n" "$((i+1))" "${EDIT_LABELS[$i]}"
    done
    echo -e "  ${GREEN}0.${NC} 返回"
    read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    [[ "$c" == "0" || -z "$c" ]] && return 0
    if ! [[ "$c" =~ ^[0-9]+$ ]] || (( c < 1 || c > ${#EDIT_LABELS[@]} )); then err "无效编号。"; return 1; fi
    fn="${EDIT_FUNCS[$((c-1))]}"
    "$fn" "$tag"
}

edit_node_menu() {
    echo -e "\n${YELLOW}${BOLD}=== 编辑节点配置 ===${NC}"
    echo -e "  ${GREEN}1.${NC} 修改节点地址, 域名或 IP"
    echo -e "  ${GREEN}2.${NC} 选择节点并编辑配置"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) set_node_host ;;
        2) pick_node && { [[ -n "$PICKED_SPECIAL" ]] && edit_special_node "$PICKED_SPECIAL" || edit_single_node "$PICKED_TAG"; } ;;
        *) return 0 ;;
    esac
}

# ===========================================================================
#  十三、卸载 / 系统优化 / 快捷命令
# ===========================================================================
uninstall_menu() {
    echo -e "\n${YELLOW}${BOLD}=== 卸载 ===${NC}"
    echo -e "  ${GREEN}1.${NC} 卸载 sing-box, 同时删除其节点"
    echo -e "  ${GREEN}2.${NC} 卸载 Xray, 同时删除其节点"
    echo -e "  ${GREEN}3.${NC} 卸载 Snell"
    echo -e "  ${GREEN}4.${NC} 卸载 Mieru"
    echo -e "  ${GREEN}5.${NC} 卸载 WireGuard"
    echo -e "  ${GREEN}6.${NC} 卸载端口流量计费管理"
    echo -e "  ${RED}7.${NC} 全部卸载"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) uninstall_core_singbox ;;
        2) uninstall_core_xray ;;
        3) uninstall_snell ;;
        4) uninstall_mieru ;;
        5) uninstall_wireguard ;;
        6) uninstall_ptm ;;
        7) uninstall_all ;;
        *) return 0 ;;
    esac
}

uninstall_all() {
    confirm "确认全部卸载并清理脚本环境? 这会删除本脚本创建的服务、配置、状态与 pm 快捷命令。" "n" || return 0
    local had_wg_state=""
    [[ -f "$WG_STATE" || -f "$WG_CONF" ]] && had_wg_state="1"

    uninstall_core_singbox quiet
    uninstall_core_xray quiet
    if [[ -f "$STATE" ]]; then
        local t
        while IFS= read -r t; do
            [[ -n "$t" ]] && delete_snell_managed_node "$t" >/dev/null 2>&1 || true
        done <<< "$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-managed") | .key' "$STATE" 2>/dev/null)"
        while IFS= read -r t; do
            [[ -n "$t" ]] && delete_snell_shadowtls_node "$t" >/dev/null 2>&1 || true
        done <<< "$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-shadowtls") | .key' "$STATE" 2>/dev/null)"
    fi
    uninstall_snell quiet
    uninstall_mieru quiet
    uninstall_wireguard quiet
    uninstall_ptm quiet

    systemctl stop "$SB_SERVICE" "$XRAY_SERVICE" "$SNELL_SERVICE" "$MITA_SERVICE" "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
    systemctl disable "$SB_SERVICE" "$XRAY_SERVICE" "$SNELL_SERVICE" "$MITA_SERVICE" "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
    rm -f "$SB_SERVICE_FILE" "$XRAY_SERVICE_FILE" "$SNELL_SERVICE_FILE" "$MITA_SERVICE_FILE"
    rm -f "$SB_BIN" "$XRAY_BIN" "$SNELL_BIN" "$SHADOWTLS_BIN" /usr/local/bin/snell-server-v4 /usr/local/bin/snell-server-v5 /usr/local/bin/mita /usr/bin/mita
    rm -f "$SHORTCUT" /tmp/pm_check.log
    rm -f "$WG_CONF" "$SNELL_STATE" "$MIERU_STATE" "$WG_STATE"
    rm -rf "$SB_DIR" "$XRAY_DIR" "$XRAY_SHARE" "$(dirname "$SNELL_CONF")" /etc/mita "$STATE_DIR"
    find /tmp -maxdepth 1 -type f -name 'proxy-manager.*.json' -delete 2>/dev/null || true
    rmdir "$WG_DIR" 2>/dev/null || true
    if [[ -n "$had_wg_state" && -f /etc/sysctl.conf ]]; then
        sed -i '/^net\.ipv4\.ip_forward=1$/d' /etc/sysctl.conf 2>/dev/null || true
        sysctl -p >/dev/null 2>&1 || true
    fi
    systemctl daemon-reload 2>/dev/null || true
    ok "已全部卸载并清理脚本环境。"
}

uninstall_core_singbox() {
    sb_installed || { warn "sing-box 未安装。"; return 0; }
    [[ "$1" == "quiet" ]] || confirm "确认卸载 sing-box?" "n" || return 0
    systemctl stop "$SB_SERVICE" 2>/dev/null; systemctl disable "$SB_SERVICE" 2>/dev/null
    rm -f "$SB_SERVICE_FILE" "$SB_BIN"; rm -rf "$SB_DIR"; systemctl daemon-reload
    # 清除 state 中 singbox 节点
    [[ -f "$STATE" ]] && { local tmp; tmp="$(mktemp)"; jq '.nodes |= with_entries(select(.value.core != "singbox"))' "$STATE" > "$tmp" && mv "$tmp" "$STATE"; }
    ok "sing-box 已卸载。"
}

uninstall_core_xray() {
    xray_installed || { warn "Xray 未安装。"; return 0; }
    [[ "$1" == "quiet" ]] || confirm "确认卸载 Xray?" "n" || return 0
    systemctl stop "$XRAY_SERVICE" 2>/dev/null; systemctl disable "$XRAY_SERVICE" 2>/dev/null
    rm -f "$XRAY_SERVICE_FILE" "$XRAY_BIN"; rm -rf "$XRAY_DIR" "$XRAY_SHARE"; systemctl daemon-reload
    [[ -f "$STATE" ]] && { local tmp; tmp="$(mktemp)"; jq '.nodes |= with_entries(select(.value.core != "xray"))' "$STATE" > "$tmp" && mv "$tmp" "$STATE"; }
    ok "Xray 已卸载。"
}

restart_snell() {
    systemctl restart "$SNELL_SERVICE" 2>/dev/null; sleep 1
    if snell_running; then ok "Snell 服务运行中。"; return 0
    else err "Snell 启动失败! 最近日志:"; journalctl -u "$SNELL_SERVICE" -n 15 --no-pager 2>/dev/null | sed 's/^/    /'; return 1; fi
}

restart_mieru() {
    local bin; bin="$(mita_bin)"
    systemctl restart "$MITA_SERVICE" 2>/dev/null; sleep 1
    wait_mita_socket 10 >/dev/null 2>&1 || true
    [[ -n "$bin" ]] && "$bin" start >/dev/null 2>&1 || true
    if mieru_running; then ok "Mieru 服务运行中。"; return 0
    else err "Mieru 启动失败! 最近日志:"; journalctl -u "$MITA_SERVICE" -n 15 --no-pager 2>/dev/null | sed 's/^/    /'; return 1; fi
}

restart_wireguard() {
    systemctl restart "wg-quick@${WG_IFACE}" 2>/dev/null; sleep 1
    if wg_running; then ok "WireGuard 服务运行中。"; return 0
    else err "WireGuard 启动失败! 最近日志:"; journalctl -u "wg-quick@${WG_IFACE}" -n 15 --no-pager 2>/dev/null | sed 's/^/    /'; return 1; fi
}

restart_all() {
    local count=0 t port svc stls_svc backend_svc
    sb_installed && { ((count++)); restart_singbox; }
    xray_installed && { ((count++)); restart_xray; }
    snell_installed && { ((count++)); restart_snell; }
    mieru_installed && { ((count++)); restart_mieru; }
    wg_installed && { ((count++)); restart_wireguard; }
    if [[ -f "$STATE" ]]; then
        while IFS= read -r t; do
            [[ -z "$t" ]] && continue
            port="${t#snell-}"
            svc="$(snell_instance_service "$port")"
            systemctl restart "$svc" 2>/dev/null
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                ok "Snell ${port} 服务运行中。"
            else
                err "Snell ${port} 启动失败! 最近日志:"
                journalctl -u "$svc" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'
            fi
            ((count++))
        done <<< "$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-managed") | .key' "$STATE" 2>/dev/null)"
        while IFS= read -r t; do
            [[ -z "$t" ]] && continue
            port="${t#snell-shadowtls-}"
            stls_svc="$(snell_shadowtls_service "$port")"
            backend_svc="$(snell_shadowtls_backend_service "$port")"
            systemctl restart "$backend_svc" 2>/dev/null
            systemctl restart "$stls_svc" 2>/dev/null
            if systemctl is-active --quiet "$backend_svc" 2>/dev/null && systemctl is-active --quiet "$stls_svc" 2>/dev/null; then
                ok "Snell+ShadowTLS ${port} 服务运行中。"
            else
                err "Snell+ShadowTLS ${port} 启动失败! 最近日志:"
                journalctl -u "$stls_svc" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'
            fi
            ((count++))
        done <<< "$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-shadowtls") | .key' "$STATE" 2>/dev/null)"
    fi
    (( count > 0 )) || warn "尚未安装任何可重启的服务。"
}

service_state_text() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${RED}已停止${NC}"
    fi
}

core_service_block() {
    local name="$1" status="$2" version="$3" service="$4" config="$5" extra="$6"
    echo -e "  ${GREEN}●${NC} ${BOLD}${name}${NC}"
    echo -e "      ${DIM}状态:${NC} ${status}"
    [[ -n "$version" ]] && echo -e "      ${DIM}版本:${NC} ${GREEN}${version}${NC}"
    [[ -n "$service" ]] && echo -e "      ${DIM}服务:${NC} ${service}"
    [[ -n "$config" ]] && echo -e "      ${DIM}配置:${NC} ${config}"
    [[ -n "$extra" ]] && echo -e "      ${DIM}${extra}${NC}"
}

core_not_installed_block() {
    local name="$1"
    echo -e "  ${YELLOW}○${NC} ${BOLD}${name}${NC}"
    echo -e "      ${DIM}状态:${NC} ${YELLOW}未安装${NC}"
}

show_core_service_info() {
    echo -e "\n${BLUE}${BOLD}╭─ 核心状态${NC}"
    if xray_installed; then
        core_service_block "Xray" "$(service_state_text "$XRAY_SERVICE")" "$(xray_version)" "$XRAY_SERVICE" "$XRAY_CONFIG" ""
    else
        core_not_installed_block "Xray"
    fi
    if sb_installed; then
        core_service_block "sing-box" "$(service_state_text "$SB_SERVICE")" "$(sb_version)" "$SB_SERVICE" "$SB_CONFIG" ""
    else
        core_not_installed_block "sing-box"
    fi
    if snell_installed; then
        local sport; snell_load_state >/dev/null 2>&1; sport="${SNELL_PORT:-未知}"
        core_service_block "Snell" "$(service_state_text "$SNELL_SERVICE")" "$(snell_version)" "$SNELL_SERVICE" "" "端口: ${sport}"
    fi
    if mieru_installed; then
        local mport mproto
        mport="$(source "$MIERU_STATE" 2>/dev/null; echo "${MIERU_PORT:-未知}")"
        mproto="$(source "$MIERU_STATE" 2>/dev/null; echo "${MIERU_PROTO:-未知}")"
        core_service_block "Mieru" "$(service_state_text "$MITA_SERVICE")" "$(mieru_version)" "$MITA_SERVICE" "" "协议/端口: ${mproto}/${mport}"
    fi
    if wg_installed; then
        local wport; wport="$(source "$WG_STATE" 2>/dev/null; echo "${WG_PORT:-未知}")"
        core_service_block "WireGuard" "$(service_state_text "wg-quick@${WG_IFACE}")" "$(wg_version)" "wg-quick@${WG_IFACE}" "$WG_CONF" "端口: ${wport}"
    fi

    echo -e "\n${YELLOW}${BOLD}╭─ 节点概览${NC}"
    if [[ -f "$STATE" ]]; then
        local snell_ports stls_ports mieru_ports wg_peers
        snell_ports="$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-managed") | .key | sub("^snell-"; "")' "$STATE" 2>/dev/null | paste -sd, -)"
        [[ -n "$snell_ports" ]] && echo -e "  ${GREEN}Snell节点${NC}      端口: ${snell_ports}"
        stls_ports="$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-shadowtls") | .key | sub("^snell-shadowtls-"; "")' "$STATE" 2>/dev/null | paste -sd, -)"
        [[ -n "$stls_ports" ]] && echo -e "  ${GREEN}Snell+STLS${NC}    端口: ${stls_ports}"
        mieru_ports="$(jq -r '.nodes | to_entries[] | select(.value.core == "mieru-managed") | .key | sub("^mieru-"; "")' "$STATE" 2>/dev/null | paste -sd, -)"
        [[ -n "$mieru_ports" ]] && echo -e "  ${GREEN}Mieru节点${NC}      端口: ${mieru_ports}"
        wg_peers="$(jq -r '[.nodes | to_entries[] | select(.value.core == "wireguard-managed")] | length' "$STATE" 2>/dev/null)"
        [[ -n "$wg_peers" && "$wg_peers" != "0" ]] && echo -e "  ${GREEN}WG Peers${NC}       数量: ${wg_peers}"
    fi
    if shadowtls_installed; then
        echo -e "  ${GREEN}ShadowTLS${NC}      版本: $(shadowtls_version)  路径: ${SHADOWTLS_BIN}"
    fi
    echo -e "  ${GREEN}节点数量${NC}       $(node_count)"
}

core_manage_menu() {
    clear 2>/dev/null || true
    echo -e "\n${YELLOW}${BOLD}=== 内核与服务管理 ===${NC}"
    show_core_service_info
    echo
    echo -e "${BLUE}${BOLD}╭─ 操作${NC}"
    echo -e "  ${GREEN}1.${NC} 安装 / 更新 Xray 内核"
    echo -e "  ${GREEN}2.${NC} 安装 / 更新 sing-box 内核"
    echo -e "  ${GREEN}3.${NC} 重启所有服务"
    echo -e "  ${GREEN}0.${NC} 返回"
    hr
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) install_xray ;;
        2) install_singbox ;;
        3) restart_all ;;
        *) return 0 ;;
    esac
}

install_shortcut() {
    [[ -f "$SHORTCUT" ]] && return 0
    [[ -f "$SCRIPT_PATH" ]] || return 0
    cp "$SCRIPT_PATH" "$SHORTCUT" && chmod +x "$SHORTCUT" \
        && ok "已安装快捷命令: 以后直接输入 ${BOLD}pm${NC}${GREEN} 即可打开本菜单。${NC}"
}

download_latest_script() {
    local tmp="$1"
    if command -v wget >/dev/null 2>&1; then
        wget -O "$tmp" "$SCRIPT_UPDATE_URL" >/dev/null 2>&1 || { err "下载失败: $SCRIPT_UPDATE_URL"; rm -f "$tmp"; return 1; }
    else
        pkg_install wget >/dev/null 2>&1 || true
        if command -v wget >/dev/null 2>&1; then
            wget -O "$tmp" "$SCRIPT_UPDATE_URL" >/dev/null 2>&1 || { err "下载失败: $SCRIPT_UPDATE_URL"; rm -f "$tmp"; return 1; }
        elif command -v curl >/dev/null 2>&1; then
            curl -fsSL --max-time 60 "$SCRIPT_UPDATE_URL" -o "$tmp" || { err "下载失败: $SCRIPT_UPDATE_URL"; rm -f "$tmp"; return 1; }
        else
            err "未找到 wget/curl, 无法更新脚本。"; rm -f "$tmp"; return 1
        fi
    fi
    [[ -s "$tmp" ]] || { err "下载结果为空, 已取消更新。"; rm -f "$tmp"; return 1; }
}

apply_script_update() {
    local target="$1" tmp="$2"
    if ! bash -n "$tmp" >/tmp/pm_update_check.log 2>&1; then
        err "下载的新脚本语法检查失败, 已取消更新:"
        sed 's/^/    /' /tmp/pm_update_check.log
        rm -f "$tmp"
        return 1
    fi
    chmod +x "$tmp"
    if [[ -f "$target" ]] && cmp -s "$tmp" "$target"; then
        rm -f "$tmp"
        return 2
    fi
    cp "$tmp" "$target" || { err "覆盖脚本失败: $target"; rm -f "$tmp"; return 1; }
    chmod +x "$target"
    [[ "$target" != "$SHORTCUT" && -f "$SHORTCUT" ]] && cp "$target" "$SHORTCUT" 2>/dev/null && chmod +x "$SHORTCUT" 2>/dev/null
    rm -f "$tmp"
    return 0
}

is_pm_invocation() {
    [[ "$SCRIPT_PATH" == "$SHORTCUT" || "$(basename "$0")" == "pm" ]]
}

auto_update_setting() {
    jq -r '.meta.auto_update_on_pm // empty' "$STATE" 2>/dev/null
}

set_auto_update_setting() {
    local enabled="$1" tmp
    init_state
    tmp="$(mktemp)"
    jq --argjson v "$enabled" '.meta.auto_update_on_pm=$v' "$STATE" > "$tmp" && mv "$tmp" "$STATE"
    chmod 600 "$STATE"
}

prompt_auto_update_setting() {
    [[ -n "$(auto_update_setting)" ]] && return 0
    if confirm "是否开启快捷命令启动时自动同步最新版脚本? 开启后打开菜单会先拉取更新" "y"; then
        set_auto_update_setting true
        ok "已开启脚本自动同步。"
    else
        set_auto_update_setting false
        warn "已关闭脚本自动同步, 可在菜单中重新开启。"
    fi
}

toggle_auto_update_setting() {
    local cur
    cur="$(auto_update_setting)"
    if [[ "$cur" == "true" ]]; then
        set_auto_update_setting false
        warn "脚本自动同步已关闭。"
    else
        set_auto_update_setting true
        ok "脚本自动同步已开启。"
    fi
}

auto_update_on_pm_start() {
    is_pm_invocation || return 0
    [[ "${!AUTO_UPDATE_ENV:-}" == "1" ]] && return 0
    [[ "$(auto_update_setting)" == "true" ]] || return 0
    local tmp target
    target="$SHORTCUT"
    tmp="$(mktemp)" || { warn "自动同步: 创建临时文件失败, 已跳过。"; return 0; }
    info "脚本自动同步: 正在检查更新..."
    if ! download_latest_script "$tmp"; then
        warn "脚本自动同步失败, 继续使用本地脚本。"
        return 0
    fi
    apply_script_update "$target" "$tmp"
    case "$?" in
        0)
            ok "脚本自动同步完成, 正在加载最新版..."
            export "$AUTO_UPDATE_ENV=1"
            exec "$target" "$@"
            ;;
        2)
            ok "脚本自动同步: 当前已是最新版。"
            ;;
        *)
            warn "脚本自动同步失败, 继续使用本地脚本。"
            ;;
    esac
}

script_update_menu() {
    echo -e "\n${YELLOW}${BOLD}=== 更新脚本 ===${NC}"
    echo -e "  ${GREEN}1.${NC} 手动同步最新脚本"
    echo -e "  ${GREEN}2.${NC} 自动同步脚本 ${DIM}(当前: $( [[ "$(auto_update_setting)" == "true" ]] && echo 开启 || echo 关闭 ))${NC}"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c
    read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) update_script ;;
        2) toggle_auto_update_setting ;;
        *) return 0 ;;
    esac
}

update_script() {
    confirm "确认从 GitHub 拉取最新脚本并重启菜单?" "n" || return 0
    local target tmp rc
    target="$SCRIPT_PATH"
    [[ -n "$target" ]] || target="./proxy-manager.sh"
    tmp="$(mktemp)" || { err "创建临时文件失败。"; return 1; }

    info "正在下载最新脚本..."
    download_latest_script "$tmp" || return 1
    apply_script_update "$target" "$tmp"; rc=$?
    if [[ "$rc" == "2" ]]; then
        ok "当前脚本已是最新版。"
        return 0
    elif [[ "$rc" != "0" ]]; then
        return 1
    fi
    ok "脚本已更新, 正在重新打开..."
    exec "$target"
}

vless_menu() {
    echo -e "\n${BLUE}${BOLD}=== VLESS 协议 ===${NC}"
    echo -e "  ${GREEN}1.${NC} VLESS-Reality-Vision"
    echo -e "  ${GREEN}2.${NC} VLESS-XHTTP-Reality"
    echo -e "  ${GREEN}3.${NC} VLESS-gRPC-Reality"
    echo -e "  ${GREEN}4.${NC} VLESS-Encryption"
    echo -e "  ${GREEN}5.${NC} VLESS-Encryption-XHTTP"
    echo -e "  ${GREEN}6.${NC} VLESS-WS-TLS"
    echo -e "  ${GREEN}7.${NC} VLESS-gRPC-TLS"
    echo -e "  ${GREEN}8.${NC} VLESS-H2-TLS"
    echo -e "  ${GREEN}9.${NC} VLESS-XHTTP-TLS"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) add_xray_vision_reality ;;
        2) add_xray_xhttp_reality ;;
        3) add_vless_grpc_reality ;;
        4) add_xray_vless_encryption ;;
        5) add_vless_encryption_xhttp ;;
        6) add_vless_tls ws ;;
        7) add_vless_tls grpc ;;
        8) add_vless_tls h2 ;;
        9) add_vless_tls xhttp ;;
        *) return 0 ;;
    esac
}

finalmask_menu() {
    echo -e "\n${BLUE}${BOLD}=== FinalMask 抗审查 ===${NC}"
    echo -e "  ${GREEN}1.${NC} VLESS-Encryption-XHTTP-FinalMask"
    echo -e "  ${GREEN}2.${NC} VLESS-Encryption-FinalMask sudoku"
    echo -e "  ${GREEN}3.${NC} FullStack REALITY+XHTTP+FinalMask"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) add_vless_enc_xhttp_finalmask ;;
        2) add_vless_enc_finalmask ;;
        3) add_vless_fullstack ;;
        *) return 0 ;;
    esac
}

vmess_menu() {
    echo -e "\n${MAGENTA}${BOLD}=== VMess 协议 ===${NC}"
    echo -e "  ${GREEN}1.${NC} VMess-TCP"
    echo -e "  ${GREEN}2.${NC} VMess-mKCP"
    echo -e "  ${GREEN}3.${NC} VMess-QUIC"
    echo -e "  ${GREEN}4.${NC} VMess-WebSocket"
    echo -e "  ${GREEN}5.${NC} VMess-WS-TLS"
    echo -e "  ${GREEN}6.${NC} VMess-gRPC-TLS"
    echo -e "  ${GREEN}7.${NC} VMess-H2-TLS"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) add_vmess_plain tcp ;;
        2) add_vmess_plain kcp ;;
        3) add_vmess_plain quic ;;
        4) add_vmess_ws ;;
        5) add_vmess_tls ws ;;
        6) add_vmess_tls grpc ;;
        7) add_vmess_tls h2 ;;
        *) return 0 ;;
    esac
}

trojan_menu() {
    echo -e "\n${MAGENTA}${BOLD}=== Trojan 协议 ===${NC}"
    echo -e "  ${GREEN}1.${NC} Trojan-Reality"
    echo -e "  ${GREEN}2.${NC} Trojan-TCP-TLS"
    echo -e "  ${GREEN}3.${NC} Trojan-WS-TLS"
    echo -e "  ${GREEN}4.${NC} Trojan-gRPC-TLS"
    echo -e "  ${GREEN}5.${NC} Trojan-H2-TLS"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) add_trojan_reality ;;
        2) add_trojan_tls tcp ;;
        3) add_trojan_tls ws ;;
        4) add_trojan_tls grpc ;;
        5) add_trojan_tls h2 ;;
        *) return 0 ;;
    esac
}

proxy_menu() {
    echo -e "\n${MAGENTA}${BOLD}=== SOCKS5 / HTTP ===${NC}"
    echo -e "  ${GREEN}1.${NC} SOCKS5"
    echo -e "  ${GREEN}2.${NC} HTTP Proxy"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) add_socks ;;
        2) add_http_proxy ;;
        *) return 0 ;;
    esac
}

#=============================================================================
# 端口流量计费与到期管理 (Port Traffic Monitor)
#=============================================================================
# 基于 nftables 计数器/配额 + tc 限速实现按端口流量计费、配额管控、到期自动停机。
# 独立模块，不依赖任何外部私有脚本或联动接口。

PTM_CONFIG_DIR="/etc/ptm"
PTM_CONFIG_FILE="${PTM_CONFIG_DIR}/config.json"
PTM_LOG_DIR="${PTM_CONFIG_DIR}/logs"
PTM_NOTIFICATION_LOG="${PTM_LOG_DIR}/notification.log"
PTM_RESET_HISTORY_LOG="${PTM_CONFIG_DIR}/reset_history.log"
PTM_TABLE_NAME="ptm_traffic"
PTM_TABLE_FAMILY="inet"
PTM_CONFIG_LOCK_FILE="/var/run/ptm-config.lock"
PTM_DAILY_SCRIPT="/usr/local/bin/ptm-daily-check.sh"
PTM_RESET_SCRIPT="/usr/local/bin/ptm-reset-check.sh"
PTM_TG_BOT_SCRIPT="/usr/local/bin/ptm-telegram-bot.sh"
PTM_TG_SERVICE="ptm-telegram-bot"
PTM_TG_SERVICE_FILE="/etc/systemd/system/${PTM_TG_SERVICE}.service"
PTM_EMAIL_MAX_RETRIES=2
PTM_EMAIL_CONNECT_TIMEOUT=10
PTM_EMAIL_MAX_TIMEOUT=30

# ---- 基础工具 ----

ptm_beijing_time() {
    if [[ "${1:-}" == "-Iseconds" ]]; then
        TZ='Asia/Shanghai' date '+%Y-%m-%dT%H:%M:%S%z'
        return
    fi
    TZ='Asia/Shanghai' date "$@"
}

ptm_date_epoch() { pm_date_epoch "$1"; }
ptm_date_valid() { pm_date_valid "$1"; }
ptm_days_in_month() { pm_days_in_month "$1" "$2"; }

ptm_log_notification() {
    local message="$1"
    local timestamp
    timestamp=$(ptm_beijing_time '+%Y-%m-%d %H:%M:%S')
    mkdir -p "$PTM_LOG_DIR"
    echo "[$timestamp] $message" >> "$PTM_NOTIFICATION_LOG"
    if [ -f "$PTM_NOTIFICATION_LOG" ] && [ "$(wc -l < "$PTM_NOTIFICATION_LOG")" -gt 1000 ]; then
        tail -n 500 "$PTM_NOTIFICATION_LOG" > "${PTM_NOTIFICATION_LOG}.tmp"
        mv "${PTM_NOTIFICATION_LOG}.tmp" "$PTM_NOTIFICATION_LOG"
    fi
}

ptm_check_dependencies() {
    install_package nft tc jq
}

ptm_acquire_config_lock() {
    exec 233>"$PTM_CONFIG_LOCK_FILE"
    flock -w 60 233 || {
        echo -e "${gl_hong}获取配置锁超时${gl_bai}" >&2
        return 1
    }
}

ptm_release_config_lock() {
    flock -u 233 2>/dev/null || true
}

ptm_update_config() {
    local jq_expression="$1"
    local tmp_file="${PTM_CONFIG_FILE}.tmp"

    ptm_acquire_config_lock || return 1

    if jq "$jq_expression" "$PTM_CONFIG_FILE" > "$tmp_file" 2>/dev/null && [ -s "$tmp_file" ]; then
        chmod 600 "$tmp_file"
        mv "$tmp_file" "$PTM_CONFIG_FILE"
        ptm_release_config_lock
    else
        rm -f "$tmp_file"
        ptm_release_config_lock
        echo -e "${gl_hong}配置更新失败，保留原配置${gl_bai}" >&2
        return 1
    fi
}

ptm_ensure_config_schema() {
    [ -f "$PTM_CONFIG_FILE" ] || return 0
    jq -e . "$PTM_CONFIG_FILE" >/dev/null 2>&1 || return 0

    local tmp_file="${PTM_CONFIG_FILE}.tmp"
    ptm_acquire_config_lock || return 1
    if jq '
        .notify = (.notify // {}) |
        .notify.enabled = (.notify.enabled // false) |
        .notify.resend_api_key = (.notify.resend_api_key // "") |
        .notify.email_from = (.notify.email_from // "") |
        .notify.email_from_name = (.notify.email_from_name // "") |
        .notify.admin_email = (.notify.admin_email // "") |
        .notify.telegram = (.notify.telegram // {}) |
        .notify.telegram.enabled = (.notify.telegram.enabled // false) |
        .notify.telegram.bot_token = (.notify.telegram.bot_token // "") |
        .notify.telegram.admin_chat_id = (.notify.telegram.admin_chat_id // "") |
        .notify.telegram.expire_warning_days = (.notify.telegram.expire_warning_days // 3) |
        .notify.telegram.daily_report_enabled = (.notify.telegram.daily_report_enabled // false) |
        .notify.telegram.report_enabled = (.notify.telegram.report_enabled // .notify.telegram.daily_report_enabled // false) |
        .notify.telegram.report_schedule = (.notify.telegram.report_schedule // "daily") |
        .notify.telegram.last_report_dates = (.notify.telegram.last_report_dates // {}) |
        .notify.telegram.update_offset = (.notify.telegram.update_offset // 0) |
        .notify.telegram.sessions = (.notify.telegram.sessions // {}) |
        .ports = ((.ports // {}) | with_entries(.value.telegram_report_schedule = (.value.telegram_report_schedule // "inherit")))
    ' "$PTM_CONFIG_FILE" > "$tmp_file" 2>/dev/null && [ -s "$tmp_file" ]; then
        chmod 600 "$tmp_file"
        mv "$tmp_file" "$PTM_CONFIG_FILE"
    else
        rm -f "$tmp_file"
        ptm_release_config_lock
        return 1
    fi
    ptm_release_config_lock
}

ptm_init_config() {
    mkdir -p "$PTM_CONFIG_DIR" "$PTM_LOG_DIR"
    if [ ! -f "$PTM_CONFIG_FILE" ]; then
        cat > "$PTM_CONFIG_FILE" <<'PTMEOF'
{
  "ports": {},
  "notify": {
    "enabled": false,
    "resend_api_key": "",
    "email_from": "",
    "email_from_name": "",
    "admin_email": "",
    "telegram": {
      "enabled": false,
      "bot_token": "",
      "admin_chat_id": "",
      "expire_warning_days": 3,
      "daily_report_enabled": false,
      "report_enabled": false,
      "report_schedule": "daily",
      "last_report_dates": {},
      "update_offset": 0,
      "sessions": {}
    }
  }
}
PTMEOF
        chmod 600 "$PTM_CONFIG_FILE"
    fi
    ptm_ensure_config_schema
    ptm_init_nftables
}

ptm_init_nftables() {
    nft add table $PTM_TABLE_FAMILY $PTM_TABLE_NAME 2>/dev/null || true
    nft add chain $PTM_TABLE_FAMILY $PTM_TABLE_NAME input { type filter hook input priority 0\; } 2>/dev/null || true
    nft add chain $PTM_TABLE_FAMILY $PTM_TABLE_NAME output { type filter hook output priority 0\; } 2>/dev/null || true
    nft add chain $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward { type filter hook forward priority 0\; } 2>/dev/null || true
    # prerouting 优先级 -150：在 conntrack(-200) 之后、DNAT(-100) 之前拦截，兼容 Docker 端口映射场景
    nft add chain $PTM_TABLE_FAMILY $PTM_TABLE_NAME prerouting { type filter hook prerouting priority -150\; } 2>/dev/null || true
}

ptm_get_default_interface() {
    local iface
    iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -n "$iface" ]; then
        echo "$iface"
        return
    fi
    ip link show | grep "state UP" | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v '^lo$' | head -n1
}

ptm_format_bytes() {
    local bytes=$1
    [[ "$bytes" =~ ^[0-9]+$ ]] || bytes=0
    if [ "$bytes" -ge 1073741824 ]; then
        awk -v b="$bytes" 'BEGIN{printf "%.2fGB", b/1073741824}'
    elif [ "$bytes" -ge 1048576 ]; then
        awk -v b="$bytes" 'BEGIN{printf "%.2fMB", b/1048576}'
    elif [ "$bytes" -ge 1024 ]; then
        awk -v b="$bytes" 'BEGIN{printf "%.2fKB", b/1024}'
    else
        echo "${bytes}B"
    fi
}

ptm_parse_size_to_bytes() {
    local size_str=$1
    local number unit
    number=$(echo "$size_str" | grep -o '^[0-9]\+')
    unit=$(echo "$size_str" | grep -o '[A-Za-z]\+$' | tr '[:lower:]' '[:upper:]')
    [ -z "$number" ] && echo "0" && return 1
    case $unit in
        "MB"|"M") echo $((number * 1048576)) ;;
        "GB"|"G") echo $((number * 1073741824)) ;;
        "TB"|"T") echo $((number * 1099511627776)) ;;
        *) echo "0" ;;
    esac
}

# 校验配额格式，只接受 unlimited 或 数字+MB/GB/TB（大小写不敏感）
# 格式不合法时 ptm_parse_size_to_bytes 会静默返回0，等价于"over 0 bytes"立即封锁，
# 必须在入口拦截，否则用户手误输入会导致端口被意外瞬间封锁且无明显报错
# 校验配额格式：0(无限制) 或 数字+MB/GB/TB(也接受单字母M/G/T)，大小写不敏感，与 dog 原版 validate_quota 一致
ptm_validate_quota() {
    local input="$1"
    [ "$input" = "0" ] && return 0
    local lower_input
    lower_input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
    [[ "$lower_input" =~ ^[0-9]+(mb|gb|tb|m|g|t)$ ]]
}

# 校验带宽格式：0(无限制) 或 数字+Kbps/Mbps/Gbps，大小写不敏感，与 dog 原版 validate_bandwidth 一致
# 用户输入/存储都是 Kbps/Mbps/Gbps，实际下发 tc 时才转换成 tc 原生的 kbit/mbit/gbit（见 ptm_rate_to_tc）
ptm_validate_rate() {
    local input="$1"
    [ "$input" = "0" ] && return 0
    local lower_input
    lower_input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
    [[ "$lower_input" =~ ^[0-9]+(kbps|mbps|gbps)$ ]]
}

# 把用户输入/存储的 Kbps/Mbps/Gbps 转换成 tc 原生单位 kbit/mbit/gbit
ptm_rate_to_tc() {
    local input="$1"
    local lower_input
    lower_input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
    if [[ "$lower_input" =~ kbps$ ]]; then
        echo "${lower_input%kbps}kbit"
    elif [[ "$lower_input" =~ mbps$ ]]; then
        echo "${lower_input%mbps}mbit"
    elif [[ "$lower_input" =~ gbps$ ]]; then
        echo "${lower_input%gbps}gbit"
    fi
}

# ---- 端口粒度（单端口 / 端口段 100-200 / 端口组 101,102,105） ----

ptm_is_port_range() {
    [[ "$1" =~ ^[0-9]+-[0-9]+$ ]]
}

ptm_is_port_group() {
    [[ "$1" =~ , ]] && ! ptm_is_port_range "$1"
}

ptm_get_group_ports() {
    local port_key=$1
    if ptm_is_port_group "$port_key"; then
        echo "$port_key" | tr ',' ' '
    elif ptm_is_port_range "$port_key"; then
        seq "${port_key%-*}" "${port_key#*-}" | tr '\n' ' '
    else
        echo "$port_key"
    fi
}

# 统一的安全命名：逗号和连字符都替换为下划线（单端口不含这两种字符，原样返回）
ptm_safe_name() {
    echo "$1" | tr ',-' '__'
}

ptm_get_active_ports() {
    [ -f "$PTM_CONFIG_FILE" ] || return 1
    jq -r '.ports | keys[]' "$PTM_CONFIG_FILE" 2>/dev/null | sort -n
}

# ---- 计费核心 ----

ptm_calculate_total_traffic() {
    local input_bytes=$1 output_bytes=$2 billing_mode=${3:-"double"}
    case $billing_mode in
        "double")
            # 双向统计：(入站 + 出站) × 2，适用于全程走公网的转发场景
            echo $(( (input_bytes + output_bytes) * 2 ))
            ;;
        "premium")
            # 内网中转：(入站 + 出站) × 1，中转段走内网不计费
            echo $(( input_bytes + output_bytes ))
            ;;
        "single"|*)
            # 仅出站统计：出站 × 2
            echo $(( output_bytes * 2 ))
            ;;
    esac
}

ptm_format_billing_mode() {
    case "${1:-double}" in
        double) echo "双向" ;;
        single) echo "仅出站" ;;
        premium) echo "内网中转" ;;
        *) echo "${1:-未知}" ;;
    esac
}

ptm_format_reset_day_text() {
    local reset_day="$1" y m today_day day last effective_day ny nm next_last next_day
    if [ -z "$reset_day" ] || [ "$reset_day" = "null" ] || [ "$reset_day" = "未设置" ]; then
        echo "未设置"
        return
    fi
    if ! [[ "$reset_day" =~ ^[0-9]+$ ]] || [ "$reset_day" -lt 1 ]; then
        echo "$reset_day"
        return
    fi
    y=$(ptm_beijing_time +%Y)
    m=$(ptm_beijing_time +%m)
    today_day=$(ptm_beijing_time +%d | sed 's/^0//')
    day=$((10#$reset_day))
    last=$(ptm_days_in_month "$y" "$m")
    effective_day=$day
    [ "$effective_day" -gt "$last" ] && effective_day="$last"
    if [ "$today_day" -le "$effective_day" ]; then
        printf '%d-%d-%d' "$((10#$y))" "$((10#$m))" "$effective_day"
        return
    fi
    if [ "$m" = "12" ]; then
        ny=$((10#$y + 1))
        nm=1
    else
        ny=$((10#$y))
        nm=$((10#$m + 1))
    fi
    next_last=$(ptm_days_in_month "$ny" "$nm")
    next_day=$day
    [ "$next_day" -gt "$next_last" ] && next_day="$next_last"
    printf '%d-%d-%d' "$ny" "$nm" "$next_day"
}

ptm_get_port_traffic() {
    local port=$1
    local port_safe
    port_safe=$(ptm_safe_name "$port")
    local input_bytes output_bytes
    input_bytes=$(nft list counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_in" 2>/dev/null | grep -o 'bytes [0-9]*' | awk '{print $2}')
    output_bytes=$(nft list counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_out" 2>/dev/null | grep -o 'bytes [0-9]*' | awk '{print $2}')
    echo "${input_bytes:-0} ${output_bytes:-0}"
}

# 用指定的历史流量值重建计数器（合并端口为组时用于继承已有流量总量）
ptm_restore_counter_value() {
    local port=$1 target_input=$2 target_output=$3
    local port_safe
    port_safe=$(ptm_safe_name "$port")
    nft delete counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_out" 2>/dev/null || true
    nft add counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_in" "{ packets 0 bytes $target_input }" 2>/dev/null || true
    nft add counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_out" "{ packets 0 bytes $target_output }" 2>/dev/null || true
}

# 显示带序号的端口列表，让用户按序号多选（逗号分隔），结果写入全局数组 PTM_PICKED_PORTS
# 对应 dog 原版 show_port_list + parse_multi_choice_input 的组合用法
# $1: 提示语  $2(可选): "single_only" 则只列出单端口(排除已有的端口组/端口段，供"合并为组"使用)
ptm_pick_ports() {
    local prompt="$1" filter="${2:-}"
    PTM_PICKED_PORTS=()
    local all_active=($(ptm_get_active_ports))
    local candidates=()
    local port
    for port in "${all_active[@]}"; do
        if [ "$filter" = "single_only" ] && { ptm_is_port_group "$port" || ptm_is_port_range "$port"; }; then
            continue
        fi
        candidates+=("$port")
    done
    if [ ${#candidates[@]} -eq 0 ]; then
        echo -e "${gl_huang}暂无可选端口${gl_bai}"
        return 1
    fi
    echo "端口列表:"
    local i
    for i in "${!candidates[@]}"; do
        port=${candidates[$i]}
        local remark status
        remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$PTM_CONFIG_FILE")
        status=$(ptm_format_running_status "$(ptm_get_port_running_status "$port")")
        if [ -n "$remark" ] && [ "$remark" != "null" ]; then
            echo "$((i+1)). 端口 $port [$remark] $status"
        else
            echo "$((i+1)). 端口 $port $status"
        fi
    done
    echo ""
    local choice_input
    read -e -p "$prompt" choice_input
    [ -z "$choice_input" ] && return 1
    local old_ifs="$IFS"
    IFS=','
    local parts=($choice_input)
    IFS="$old_ifs"
    local c
    for c in "${parts[@]}"; do
        c=$(echo "$c" | tr -d ' ')
        if [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -ge 1 ] && [ "$c" -le "${#candidates[@]}" ]; then
            PTM_PICKED_PORTS+=("${candidates[$((c-1))]}")
        fi
    done
    [ ${#PTM_PICKED_PORTS[@]} -eq 0 ] && return 1
    return 0
}

ptm_add_node_port_candidate() {
    local port="$1" label="$2"
    [[ "$port" =~ ^[0-9]+$ ]] || return 0
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 0
    [[ " ${PTM_NODE_PORT_SEEN:-} " == *" ${port} "* ]] && return 0
    PTM_NODE_PORT_CANDIDATES+=("$port")
    PTM_NODE_PORT_LABELS+=("$label")
    PTM_NODE_PORT_SEEN="${PTM_NODE_PORT_SEEN:-} ${port}"
}

ptm_collect_node_port_candidates() {
    PTM_NODE_PORT_CANDIDATES=()
    PTM_NODE_PORT_LABELS=()
    PTM_NODE_PORT_SEEN=""

    if [ -f "$STATE" ]; then
        local tag type name detail extra
        while IFS=$'\t' read -r tag type name detail extra; do
            [ -n "$tag" ] || continue
            local label="${name:-$tag} / ${type:-未知}"
            local extra_port extra_proto
            if [ -n "$extra" ] && [ "$extra" != "null" ]; then
                extra_port=$(printf '%s' "$extra" | jq -r 'try (.port // empty) catch empty' 2>/dev/null)
                extra_proto=$(printf '%s' "$extra" | jq -r 'try (.proto // empty) catch empty' 2>/dev/null)
                ptm_add_node_port_candidate "$extra_port" "$label"
                if [ "$extra_proto" = "BOTH" ] && [[ "$extra_port" =~ ^[0-9]+$ ]]; then
                    ptm_add_node_port_candidate "$((extra_port + 1))" "$label"
                fi
            fi

            local p
            while IFS= read -r p; do
                ptm_add_node_port_candidate "$p" "$label"
            done < <(printf '%s\n' "$detail" | tr '|' '\n' | grep '端口' | grep -oE '[0-9]{1,5}' 2>/dev/null || true)

            local tag_port
            tag_port=$(printf '%s\n' "$tag" | grep -oE '[0-9]{1,5}$' 2>/dev/null || true)
            ptm_add_node_port_candidate "$tag_port" "$label"
        done < <(jq -r '.nodes | to_entries[] | [.key, .value.type, .value.name, (.value.detail | gsub("\n"; " | ")), (.value.extra_tag // "")] | @tsv' "$STATE" 2>/dev/null)
    fi

    if snell_installed 2>/dev/null && snell_load_state >/dev/null 2>&1; then
        ptm_add_node_port_candidate "${SNELL_PORT:-}" "Snell v${SNELL_VERSION:-?}"
    fi
    if [ -f "$MIERU_STATE" ] && grep -q '^MIERU_PORT=' "$MIERU_STATE" 2>/dev/null; then
        local mp mproto
        mp="$(source "$MIERU_STATE" 2>/dev/null; echo "${MIERU_PORT:-}")"
        mproto="$(source "$MIERU_STATE" 2>/dev/null; echo "${MIERU_PROTO:-}")"
        ptm_add_node_port_candidate "$mp" "Mieru${mproto:+ $mproto}"
        if [ "$mproto" = "BOTH" ] && [[ "$mp" =~ ^[0-9]+$ ]]; then
            ptm_add_node_port_candidate "$((mp + 1))" "Mieru $mproto"
        fi
    fi
    if [ -f "$WG_STATE" ] && grep -q '^WG_PORT=' "$WG_STATE" 2>/dev/null; then
        local wp
        wp="$(source "$WG_STATE" 2>/dev/null; echo "${WG_PORT:-}")"
        ptm_add_node_port_candidate "$wp" "WireGuard"
    fi
}

ptm_prompt_monitor_port() {
    PTM_SELECTED_MONITOR_PORT=""
    ptm_collect_node_port_candidates
    if [ "${#PTM_NODE_PORT_CANDIDATES[@]}" -gt 0 ]; then
        echo "检测到当前已部署节点端口:"
        local i port label monitored
        for i in "${!PTM_NODE_PORT_CANDIDATES[@]}"; do
            port="${PTM_NODE_PORT_CANDIDATES[$i]}"
            label="${PTM_NODE_PORT_LABELS[$i]}"
            monitored=""
            jq -e ".ports | has(\"$port\")" "$PTM_CONFIG_FILE" >/dev/null 2>&1 && monitored=" ${gl_huang}(已监控)${gl_bai}"
            printf "%2d. %s [%s]%b\n" "$((i + 1))" "$port" "$label" "$monitored"
        done
        echo " m. 手动输入端口/端口段/端口组"
        local choice
        read -e -p "请选择要监控的端口编号，或直接输入端口: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#PTM_NODE_PORT_CANDIDATES[@]}" ]; then
            PTM_SELECTED_MONITOR_PORT="${PTM_NODE_PORT_CANDIDATES[$((choice - 1))]}"
            return 0
        fi
        if [ "$choice" = "m" ] || [ "$choice" = "M" ] || [ -z "$choice" ]; then
            read -e -p "请输入要监控的端口号/端口段/端口组: " PTM_SELECTED_MONITOR_PORT
            return 0
        fi
        PTM_SELECTED_MONITOR_PORT="$choice"
        return 0
    fi

    read -e -p "请输入要监控的端口号: " PTM_SELECTED_MONITOR_PORT
}

ptm_get_port_monthly_usage() {
    local port=$1
    local traffic=($(ptm_get_port_traffic "$port"))
    local billing_mode
    billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE")
    ptm_calculate_total_traffic "${traffic[0]:-0}" "${traffic[1]:-0}" "$billing_mode"
}

# 返回: running / blocked_quota / blocked_expired / rate_limited:<rate> / quota_warning / expiring_soon:<days>
ptm_get_port_running_status() {
    local port=$1
    local port_safe
    port_safe=$(ptm_safe_name "$port")

    if nft list quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_block_quota" &>/dev/null; then
        echo "blocked_expired"
        return
    fi

    local quota_limit
    quota_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE")
    if [ "$quota_limit" != "unlimited" ]; then
        local quota_info
        quota_info=$(nft list quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_quota" 2>/dev/null || true)
        if [ -n "$quota_info" ]; then
            local over_bytes used_bytes
            over_bytes=$(echo "$quota_info" | grep -oE 'over [0-9]+ bytes' | grep -oE '[0-9]+' | head -n1)
            used_bytes=$(echo "$quota_info" | grep -oE 'used [0-9]+ bytes' | grep -oE '[0-9]+' | head -n1)
            if [ -n "$over_bytes" ] && [ -n "$used_bytes" ] && [ "$over_bytes" -gt 0 ]; then
                if [ "$used_bytes" -ge "$over_bytes" ]; then
                    echo "blocked_quota"
                    return
                fi
                local warning_threshold=$((over_bytes * 80 / 100))
                if [ "$used_bytes" -ge "$warning_threshold" ]; then
                    echo "quota_warning"
                    return
                fi
            fi
        else
            local current_usage limit_bytes
            current_usage=$(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo "0")
            limit_bytes=$(ptm_parse_size_to_bytes "$quota_limit" 2>/dev/null || echo "0")
            if [ "$limit_bytes" -gt 0 ] && [ "$current_usage" -ge "$limit_bytes" ]; then
                echo "blocked_quota"
                return
            fi
        fi
    fi

    local bandwidth_enabled
    bandwidth_enabled=$(jq -r ".ports.\"$port\".bandwidth_limit.enabled // false" "$PTM_CONFIG_FILE")
    if [ "$bandwidth_enabled" = "true" ]; then
        local rate
        rate=$(jq -r ".ports.\"$port\".bandwidth_limit.rate // \"unlimited\"" "$PTM_CONFIG_FILE")
        [ "$rate" != "unlimited" ] && { echo "rate_limited:$rate"; return; }
    fi

    local expire_date
    expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$PTM_CONFIG_FILE")
    if [ -n "$expire_date" ] && [ "$expire_date" != "null" ]; then
        local today expire_epoch today_epoch
        today=$(ptm_beijing_time +%Y-%m-%d)
        expire_epoch=$(ptm_date_epoch "$expire_date" 2>/dev/null || echo "0")
        today_epoch=$(ptm_date_epoch "$today" 2>/dev/null || echo "0")
        if [ "$expire_epoch" -gt 0 ] && [ "$today_epoch" -gt 0 ]; then
            local diff_days=$(( (expire_epoch - today_epoch) / 86400 ))
            local warning_days
            warning_days=$(jq -r '.notify.telegram.expire_warning_days // 3' "$PTM_CONFIG_FILE" 2>/dev/null)
            [[ "$warning_days" =~ ^[0-9]+$ ]] || warning_days=3
            if [ "$diff_days" -le "$warning_days" ] && [ "$diff_days" -ge 0 ]; then
                echo "expiring_soon:$diff_days"
                return
            fi
        fi
    fi

    echo "running"
}

ptm_format_running_status() {
    case "$1" in
        "running") echo "🟢正常" ;;
        "blocked_expired") echo "🔴过期封锁" ;;
        "blocked_quota") echo "🔴配额用尽" ;;
        "quota_warning") echo "🟡即将用尽" ;;
        rate_limited:*) echo "🟡限速${1#rate_limited:}" ;;
        expiring_soon:*)
            local days="${1#expiring_soon:}"
            [ "$days" -eq 0 ] && echo "🟡今天到期" || echo "🟡${days}天到期"
            ;;
        *) echo "⚪未知" ;;
    esac
}

ptm_get_port_usage_percent() {
    local port=$1
    local monthly_limit current_usage limit_bytes
    monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    current_usage=$(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo "0")
    if [ "$monthly_limit" = "unlimited" ]; then
        echo "0"
        return
    fi
    limit_bytes=$(ptm_parse_size_to_bytes "$monthly_limit" 2>/dev/null || echo "0")
    if [ "$limit_bytes" -le 0 ]; then
        echo "0"
        return
    fi
    echo $((current_usage * 100 / limit_bytes))
}

ptm_get_port_remaining_text() {
    local port=$1
    local monthly_limit current_usage limit_bytes remaining
    monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    if [ "$monthly_limit" = "unlimited" ]; then
        echo "无限制"
        return
    fi
    current_usage=$(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo "0")
    limit_bytes=$(ptm_parse_size_to_bytes "$monthly_limit" 2>/dev/null || echo "0")
    if [ "$limit_bytes" -le 0 ]; then
        echo "未知"
        return
    fi
    remaining=$((limit_bytes - current_usage))
    [ "$remaining" -lt 0 ] && remaining=0
    ptm_format_bytes "$remaining"
}

ptm_get_port_expire_left_text() {
    local port=$1
    local expire_date
    expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    if [ -z "$expire_date" ] || [ "$expire_date" = "null" ]; then
        echo "永久"
        return
    fi
    local today expire_epoch today_epoch diff_days
    today=$(ptm_beijing_time +%Y-%m-%d)
    expire_epoch=$(ptm_date_epoch "$expire_date" 2>/dev/null || echo "0")
    today_epoch=$(ptm_date_epoch "$today" 2>/dev/null || echo "0")
    if [ "$expire_epoch" -le 0 ] || [ "$today_epoch" -le 0 ]; then
        echo "$expire_date"
        return
    fi
    diff_days=$(( (expire_epoch - today_epoch) / 86400 ))
    if [ "$diff_days" -lt 0 ]; then
        echo "$expire_date（已过期 $((-diff_days)) 天）"
    elif [ "$diff_days" -eq 0 ]; then
        echo "$expire_date（今天到期）"
    else
        echo "$expire_date（剩余 ${diff_days} 天）"
    fi
}

ptm_port_exists() {
    local port=$1
    jq -e --arg port "$port" '.ports | has($port)' "$PTM_CONFIG_FILE" >/dev/null 2>&1
}

ptm_json_string() {
    jq -Rn --arg v "$1" '$v'
}

ptm_normalize_report_schedule() {
    local input="$1" allow_inherit="${2:-false}"
    input="$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]' | tr '-' '_')"
    case "$input" in
        ""|inherit|default|默认|继承)
            [[ "$allow_inherit" == "true" ]] && echo "inherit" || echo ""
            ;;
        off|disable|disabled|none|no|关闭|不推送) echo "off" ;;
        daily|day|每天|每日) echo "daily" ;;
        weekly|week|每周|周报) echo "weekly" ;;
        month_end|monthly|month|月底|月末|每月) echo "month_end" ;;
        *) echo "" ;;
    esac
}

ptm_report_schedule_label() {
    case "$1" in
        inherit) echo "继承全局" ;;
        off) echo "关闭" ;;
        daily) echo "每日" ;;
        weekly) echo "每周一" ;;
        month_end) echo "每月最后一天" ;;
        *) echo "${1:-未设置}" ;;
    esac
}

ptm_prompt_report_schedule() {
    local prompt="$1" current="${2:-daily}" allow_inherit="${3:-false}" choice normalized
    echo "$prompt"
    echo "当前: $(ptm_report_schedule_label "$current")"
    if [[ "$allow_inherit" == "true" ]]; then
        echo "1. 继承全局"
        echo "2. 每日推送"
        echo "3. 每周一推送"
        echo "4. 每月最后一天推送"
        echo "5. 关闭该用户概览"
        read -e -p "请选择 [1-5] (留空不改): " choice
        case "$choice" in
            1) normalized="inherit" ;;
            2) normalized="daily" ;;
            3) normalized="weekly" ;;
            4) normalized="month_end" ;;
            5) normalized="off" ;;
            "") normalized="" ;;
            *) normalized="$(ptm_normalize_report_schedule "$choice" true)" ;;
        esac
    else
        echo "1. 每日推送"
        echo "2. 每周一推送"
        echo "3. 每月最后一天推送"
        echo "4. 关闭概览推送"
        read -e -p "请选择 [1-4] (留空不改): " choice
        case "$choice" in
            1) normalized="daily" ;;
            2) normalized="weekly" ;;
            3) normalized="month_end" ;;
            4) normalized="off" ;;
            "") normalized="" ;;
            *) normalized="$(ptm_normalize_report_schedule "$choice" false)" ;;
        esac
    fi
    REPLY_VALUE="$normalized"
}

ptm_is_month_end_today() {
    local y m d last
    y=$(ptm_beijing_time +%Y)
    m=$(ptm_beijing_time +%m)
    d=$(ptm_beijing_time +%d | sed 's/^0//')
    last=$(ptm_days_in_month "$y" "$m")
    [[ "$d" == "$last" ]]
}

ptm_report_schedule_due() {
    case "$1" in
        daily) return 0 ;;
        weekly) [[ "$(ptm_beijing_time +%u 2>/dev/null || echo 1)" == "1" ]] ;;
        month_end) ptm_is_month_end_today ;;
        *) return 1 ;;
    esac
}

ptm_should_send_scheduled_report() {
    local scope="$1" schedule="$2" force="${3:-}" today last
    [[ "$force" == "force" ]] && return 0
    ptm_report_schedule_due "$schedule" || return 1
    today=$(ptm_beijing_time +%Y-%m-%d)
    last=$(jq -r --arg scope "$scope" '.notify.telegram.last_report_dates[$scope] // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    [[ "$last" != "$today" ]]
}

ptm_mark_scheduled_report_sent() {
    local scope="$1" today scope_json today_json
    today=$(ptm_beijing_time +%Y-%m-%d)
    scope_json=$(ptm_json_string "$scope")
    today_json=$(ptm_json_string "$today")
    ptm_update_config ".notify.telegram.last_report_dates[$scope_json] = $today_json" >/dev/null 2>&1 || true
}

ptm_get_effective_port_report_schedule() {
    local port="$1" schedule global_schedule
    schedule=$(jq -r ".ports.\"$port\".telegram_report_schedule // \"inherit\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    schedule=$(ptm_normalize_report_schedule "$schedule" true)
    [[ -n "$schedule" ]] || schedule="inherit"
    if [[ "$schedule" == "inherit" ]]; then
        global_schedule=$(jq -r '.notify.telegram.report_schedule // "daily"' "$PTM_CONFIG_FILE" 2>/dev/null)
        schedule=$(ptm_normalize_report_schedule "$global_schedule" false)
        [[ -n "$schedule" ]] || schedule="daily"
    fi
    echo "$schedule"
}

ptm_build_port_plain_message() {
    local port=$1 title="${2:-节点使用情况}"
    if ! ptm_port_exists "$port"; then
        echo "未找到端口 $port"
        return 1
    fi

    local remark billing_mode status usage quota remaining expire reset_day usage_percent
    remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    billing_mode=$(ptm_format_billing_mode "$billing_mode")
    status=$(ptm_format_running_status "$(ptm_get_port_running_status "$port")")
    usage=$(ptm_format_bytes "$(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo 0)")
    quota=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    remaining=$(ptm_get_port_remaining_text "$port")
    expire=$(ptm_get_port_expire_left_text "$port")
    reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // \"未设置\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    reset_day=$(ptm_format_reset_day_text "$reset_day")
    usage_percent=$(ptm_get_port_usage_percent "$port")
    [ "$quota" = "unlimited" ] && quota="无限制"

    cat <<EOF
${title}
━━━━━━━━━━━━━━━━
端口        ${port}
备注        ${remark:-无}
状态        ${status}
计费模式    ${billing_mode}
已用流量    ${usage}
流量配额    ${quota}
剩余流量    ${remaining}
使用比例    ${usage_percent}%
到期时间    ${expire}
流量重置日期 ${reset_day}
EOF
}

ptm_build_port_user_message() {
    local port=$1 title="${2:-节点使用情况}"
    if ! ptm_port_exists "$port"; then
        echo "未找到节点"
        return 1
    fi

    local remark billing_mode status usage quota remaining expire reset_day usage_percent
    remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    billing_mode=$(ptm_format_billing_mode "$billing_mode")
    status=$(ptm_format_running_status "$(ptm_get_port_running_status "$port")")
    usage=$(ptm_format_bytes "$(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo 0)")
    quota=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    remaining=$(ptm_get_port_remaining_text "$port")
    expire=$(ptm_get_port_expire_left_text "$port")
    reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // \"未设置\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    reset_day=$(ptm_format_reset_day_text "$reset_day")
    usage_percent=$(ptm_get_port_usage_percent "$port")
    [ "$quota" = "unlimited" ] && quota="无限制"

    cat <<EOF
${title}
━━━━━━━━━━━━━━━━
节点        ${remark:-未设置备注}
状态        ${status}
计费模式    ${billing_mode}
已用流量    ${usage}
流量配额    ${quota}
剩余流量    ${remaining}
使用比例    ${usage_percent}%
到期时间    ${expire}
流量重置日期 ${reset_day}
EOF
}

ptm_get_telegram_chat_for_port() {
    local port=$1
    jq -r ".ports.\"$port\".telegram_chat_id // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null
}

ptm_get_telegram_bound_ports() {
    local chat_id=$1
    jq -r --arg chat "$chat_id" '.ports | to_entries[] | select((.value.telegram_chat_id // "") == $chat) | .key' "$PTM_CONFIG_FILE" 2>/dev/null | sort -n
}

ptm_send_telegram_to_chat() {
    local chat_id="$1" text="$2"
    local enabled bot_token
    enabled=$(jq -r '.notify.telegram.enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ "$enabled" = "true" ] || return 1
    bot_token=$(jq -r '.notify.telegram.bot_token // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ -z "$bot_token" ] || [ "$bot_token" = "null" ] || [ -z "$chat_id" ] || [ "$chat_id" = "null" ] || [ -z "$text" ] && return 1

    local json_body response
    json_body=$(jq -n --arg chat_id "$chat_id" --arg text "$text" \
        '{chat_id: $chat_id, text: $text, disable_web_page_preview: true}')
    response=$(curl -s --connect-timeout 10 --max-time 30 \
        -X POST "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -H "Content-Type: application/json" -d "$json_body" 2>/dev/null)
    if echo "$response" | jq -e '.ok == true' >/dev/null 2>&1; then
        ptm_log_notification "[TG通知] 发送成功: chat_id=${chat_id}"
        return 0
    fi
    ptm_log_notification "[TG通知] 发送失败: chat_id=${chat_id}"
    return 1
}

ptm_send_telegram_with_keyboard() {
    local chat_id="$1" text="$2" reply_markup="$3"
    local enabled bot_token
    enabled=$(jq -r '.notify.telegram.enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ "$enabled" = "true" ] || return 1
    bot_token=$(jq -r '.notify.telegram.bot_token // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ -z "$bot_token" ] || [ "$bot_token" = "null" ] || [ -z "$chat_id" ] || [ -z "$text" ] || [ -z "$reply_markup" ] && return 1

    local json_body response
    json_body=$(jq -n --arg chat_id "$chat_id" --arg text "$text" --argjson reply_markup "$reply_markup" \
        '{chat_id: $chat_id, text: $text, reply_markup: $reply_markup, disable_web_page_preview: true}')
    response=$(curl -s --connect-timeout 10 --max-time 30 \
        -X POST "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -H "Content-Type: application/json" -d "$json_body" 2>/dev/null)
    echo "$response" | jq -e '.ok == true' >/dev/null 2>&1
}

ptm_answer_telegram_callback() {
    local callback_id="$1" text="${2:-}"
    local bot_token
    bot_token=$(jq -r '.notify.telegram.bot_token // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ -z "$bot_token" ] || [ "$bot_token" = "null" ] || [ -z "$callback_id" ] && return 1
    local json_body
    json_body=$(jq -n --arg callback_query_id "$callback_id" --arg text "$text" \
        '{callback_query_id: $callback_query_id, text: $text, show_alert: false}')
    curl -s --connect-timeout 10 --max-time 20 \
        -X POST "https://api.telegram.org/bot${bot_token}/answerCallbackQuery" \
        -H "Content-Type: application/json" -d "$json_body" >/dev/null 2>&1
}

ptm_set_telegram_commands() {
    local scope_json="$1" commands_json="$2"
    local bot_token json_body response
    bot_token=$(jq -r '.notify.telegram.bot_token // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ -z "$bot_token" ] || [ "$bot_token" = "null" ] || [ -z "$commands_json" ] && return 1
    json_body=$(jq -n --argjson scope "$scope_json" --argjson commands "$commands_json" \
        '{scope: $scope, commands: $commands}')
    response=$(curl -s --connect-timeout 10 --max-time 30 \
        -X POST "https://api.telegram.org/bot${bot_token}/setMyCommands" \
        -H "Content-Type: application/json" -d "$json_body" 2>/dev/null)
    echo "$response" | jq -e '.ok == true' >/dev/null 2>&1
}

ptm_setup_telegram_commands() {
    local user_commands admin_commands admin_chat admin_scope
    user_commands=$(jq -cn '[
        {command:"start", description:"显示帮助和 Chat ID"},
        {command:"id", description:"查看当前 Chat ID"},
        {command:"status", description:"查看我的节点用量"},
        {command:"help", description:"查看帮助"}
    ]')
    ptm_set_telegram_commands '{"type":"default"}' "$user_commands" || true

    admin_chat=$(jq -r '.notify.telegram.admin_chat_id // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ -n "$admin_chat" ] && [ "$admin_chat" != "null" ] || return 0
    admin_commands=$(jq -cn '[
        {command:"start", description:"显示帮助和 Chat ID"},
        {command:"id", description:"查看当前 Chat ID"},
        {command:"adduser", description:"分步添加或绑定用户"},
        {command:"users", description:"显示所有用户并点选查看"},
        {command:"ports", description:"查看全部端口概览"},
        {command:"port", description:"查看指定端口详情"},
        {command:"renew", description:"为端口续期"},
        {command:"expire", description:"设置端口到期日"},
        {command:"report", description:"发送一次用量报告"},
        {command:"reporton", description:"开启周期概览推送"},
        {command:"reportoff", description:"关闭周期概览推送"},
        {command:"schedule", description:"设置概览推送周期"},
        {command:"cancel", description:"取消当前分步操作"},
        {command:"help", description:"查看帮助"}
    ]')
    admin_scope=$(jq -cn --arg chat_id "$admin_chat" '{type:"chat", chat_id:$chat_id}')
    ptm_set_telegram_commands "$admin_scope" "$admin_commands" || true
}

ptm_send_telegram_long() {
    local chat_id="$1" text="$2"
    [ -n "$chat_id" ] && [ -n "$text" ] || return 1
    local chunk sent=false
    while [ -n "$text" ]; do
        chunk="${text:0:3900}"
        if ptm_send_telegram_to_chat "$chat_id" "$chunk"; then
            sent=true
        fi
        text="${text:3900}"
    done
    [ "$sent" = true ]
}

ptm_send_telegram_to_port() {
    local port="$1" text="$2"
    local chat_id
    chat_id=$(ptm_get_telegram_chat_for_port "$port")
    [ -n "$chat_id" ] && [ "$chat_id" != "null" ] || return 1
    ptm_send_telegram_to_chat "$chat_id" "$text"
}

ptm_build_ports_summary_text() {
    local title="${1:-端口使用概览}" ports="$2"
    local msg="${title}"$'\n━━━━━━━━━━━━━━━━'$'\n'
    local port
    for port in $ports; do
        local remark billing_mode status usage quota remaining expire reset_day usage_percent
        remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        billing_mode=$(ptm_format_billing_mode "$billing_mode")
        status=$(ptm_format_running_status "$(ptm_get_port_running_status "$port")")
        usage=$(ptm_format_bytes "$(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo 0)")
        quota=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        [ "$quota" = "unlimited" ] && quota="无限制"
        remaining=$(ptm_get_port_remaining_text "$port")
        expire=$(ptm_get_port_expire_left_text "$port")
        reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // \"未设置\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        reset_day=$(ptm_format_reset_day_text "$reset_day")
        usage_percent=$(ptm_get_port_usage_percent "$port")
        if [ -n "$remark" ] && [ "$remark" != "null" ]; then
            msg+=$'\n'"端口 ${port}｜${remark}"
        else
            msg+=$'\n'"端口 ${port}"
        fi
        msg+=$'\n'"状态 ${status}"
        msg+=$'\n'"计费 ${billing_mode}"
        msg+=$'\n'"流量 ${usage} / ${quota} (${usage_percent}%)"
        msg+=$'\n'"剩余 ${remaining}"
        msg+=$'\n'"到期 ${expire}"
        msg+=$'\n'"流量重置日期 ${reset_day}"$'\n'
    done
    echo "$msg"
}

ptm_build_user_ports_summary_text() {
    local title="${1:-我的节点}" ports="$2"
    local msg="${title}"$'\n━━━━━━━━━━━━━━━━'$'\n'
    local port index=1
    for port in $ports; do
        local remark billing_mode status usage quota remaining expire reset_day usage_percent
        remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        billing_mode=$(ptm_format_billing_mode "$billing_mode")
        status=$(ptm_format_running_status "$(ptm_get_port_running_status "$port")")
        usage=$(ptm_format_bytes "$(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo 0)")
        quota=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        [ "$quota" = "unlimited" ] && quota="无限制"
        remaining=$(ptm_get_port_remaining_text "$port")
        expire=$(ptm_get_port_expire_left_text "$port")
        reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // \"未设置\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        reset_day=$(ptm_format_reset_day_text "$reset_day")
        usage_percent=$(ptm_get_port_usage_percent "$port")
        msg+=$'\n'"节点 ${index}｜${remark:-未设置备注}"
        msg+=$'\n'"状态 ${status}"
        msg+=$'\n'"计费 ${billing_mode}"
        msg+=$'\n'"流量 ${usage} / ${quota} (${usage_percent}%)"
        msg+=$'\n'"剩余 ${remaining}"
        msg+=$'\n'"到期 ${expire}"
        msg+=$'\n'"流量重置日期 ${reset_day}"$'\n'
        index=$((index + 1))
    done
    echo "$msg"
}

ptm_send_daily_telegram_reports() {
    local force="${1:-}" enabled global_schedule
    enabled=$(jq -r '.notify.telegram.report_enabled // .notify.telegram.daily_report_enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ "$enabled" = "true" ] || return 0
    global_schedule=$(jq -r '.notify.telegram.report_schedule // "daily"' "$PTM_CONFIG_FILE" 2>/dev/null)
    global_schedule=$(ptm_normalize_report_schedule "$global_schedule" false)
    [[ -n "$global_schedule" ]] || global_schedule="daily"

    local chat_id
    for chat_id in $(jq -r '.ports | to_entries[] | .value.telegram_chat_id // empty' "$PTM_CONFIG_FILE" 2>/dev/null | sort -u); do
        [ -n "$chat_id" ] || continue
        local ports="" port schedule msg
        for port in $(ptm_get_telegram_bound_ports "$chat_id"); do
            schedule=$(ptm_get_effective_port_report_schedule "$port")
            [[ "$schedule" == "off" ]] && continue
            ptm_should_send_scheduled_report "user:${chat_id}" "$schedule" "$force" || continue
            ports+="${port}"$'\n'
        done
        [ -n "$ports" ] || continue
        msg=$(ptm_build_user_ports_summary_text "节点用量概览" "$ports")
        if ptm_send_telegram_long "$chat_id" "$msg"; then
            [[ "$force" == "force" ]] || ptm_mark_scheduled_report_sent "user:${chat_id}"
        fi
    done

    local admin_chat all_ports admin_msg
    admin_chat=$(jq -r '.notify.telegram.admin_chat_id // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    all_ports=$(ptm_get_active_ports 2>/dev/null)
    if [ -n "$admin_chat" ] && [ "$admin_chat" != "null" ] && [ -n "$all_ports" ] && \
        ptm_should_send_scheduled_report "admin" "$global_schedule" "$force"; then
        admin_msg=$(ptm_build_ports_summary_text "车主用量概览" "$all_ports")
        if ptm_send_telegram_long "$admin_chat" "$admin_msg"; then
            [[ "$force" == "force" ]] || ptm_mark_scheduled_report_sent "admin"
        fi
    fi
}

ptm_send_telegram_to_admin() {
    local text="$1"
    local chat_id
    chat_id=$(jq -r '.notify.telegram.admin_chat_id // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ -n "$chat_id" ] && [ "$chat_id" != "null" ] || return 1
    ptm_send_telegram_to_chat "$chat_id" "$text"
}

# ---- nftables 流量计数规则 ----

ptm_add_nftables_rules() {
    local port=$1
    local port_safe
    port_safe=$(ptm_safe_name "$port")

    nft list counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_in" >/dev/null 2>&1 || \
        nft add counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_in" 2>/dev/null || true
    nft list counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_out" >/dev/null 2>&1 || \
        nft add counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_out" 2>/dev/null || true

    if ptm_is_port_group "$port"; then
        local single_port
        for single_port in $(ptm_get_group_ports "$port"); do
            nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input tcp dport $single_port counter name "port_${port_safe}_in" 2>/dev/null || true
            nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input udp dport $single_port counter name "port_${port_safe}_in" 2>/dev/null || true
            nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp dport $single_port counter name "port_${port_safe}_in" 2>/dev/null || true
            nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp dport $single_port counter name "port_${port_safe}_in" 2>/dev/null || true
            nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output tcp sport $single_port counter name "port_${port_safe}_out" 2>/dev/null || true
            nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output udp sport $single_port counter name "port_${port_safe}_out" 2>/dev/null || true
            nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp sport $single_port counter name "port_${port_safe}_out" 2>/dev/null || true
            nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp sport $single_port counter name "port_${port_safe}_out" 2>/dev/null || true
        done
    else
        # 端口段用 nftables 原生 range 语法（如 8000-8100），单端口同理直接可用
        nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input tcp dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input udp dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output tcp sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output udp sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
    fi
}

ptm_remove_nftables_rules() {
    local port=$1
    local port_safe
    port_safe=$(ptm_safe_name "$port")
    local search_pattern="port_${port_safe}_"
    local deleted_count=0

    while true; do
        local handle
        handle=$(nft -a list table $PTM_TABLE_FAMILY $PTM_TABLE_NAME 2>/dev/null | \
            grep -E "(tcp|udp).*(dport|sport).*$search_pattern" | head -n1 | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
        [ -z "$handle" ] && break
        local deleted=false
        local chain
        for chain in input output forward prerouting; do
            if nft delete rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME $chain handle $handle 2>/dev/null; then
                deleted=true
                deleted_count=$((deleted_count + 1))
                break
            fi
        done
        [ "$deleted" = false ] && break
        [ "$deleted_count" -ge 200 ] && break
    done

    nft delete counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_out" 2>/dev/null || true
}

ptm_is_port_rules_exist() {
    local port_safe
    port_safe=$(ptm_safe_name "$1")
    nft list counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_in" >/dev/null 2>&1
}

# ---- 配额（nftables quota 对象） ----

ptm__apply_quota_rules_for_single_port() {
    local single_port=$1 quota_name=$2 billing_mode=$3
    if [ "$billing_mode" = "single" ]; then
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
    elif [ "$billing_mode" = "premium" ]; then
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
    else
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME input udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
    fi
}

ptm_apply_quota() {
    local port=$1 quota_limit=$2
    local billing_mode
    billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE")
    local quota_bytes
    quota_bytes=$(ptm_parse_size_to_bytes "$quota_limit")

    # 用当前已有流量作为配额初始 used 值，避免续费/重设配额后立即误触发
    local traffic=($(ptm_get_port_traffic "$port"))
    local current_total
    current_total=$(ptm_calculate_total_traffic "${traffic[0]:-0}" "${traffic[1]:-0}" "$billing_mode")

    local port_safe
    port_safe=$(ptm_safe_name "$port")
    local quota_name="port_${port_safe}_quota"

    nft delete quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME $quota_name 2>/dev/null || true
    nft add quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME $quota_name { over $quota_bytes bytes used $current_total bytes } 2>/dev/null || true

    if ptm_is_port_group "$port"; then
        local single_port
        for single_port in $(ptm_get_group_ports "$port"); do
            ptm__apply_quota_rules_for_single_port "$single_port" "$quota_name" "$billing_mode"
        done
    else
        ptm__apply_quota_rules_for_single_port "$port" "$quota_name" "$billing_mode"
    fi

    if ! nft list quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME "$quota_name" >/dev/null 2>&1; then
        echo -e "${gl_hong}⚠ 配额对象未生效: $quota_name${gl_bai}" >&2
    fi
}

ptm_remove_quota() {
    local port=$1
    local port_safe
    port_safe=$(ptm_safe_name "$port")
    local quota_name="port_${port_safe}_quota"
    local deleted_count=0
    while true; do
        local handle
        handle=$(nft -a list table $PTM_TABLE_FAMILY $PTM_TABLE_NAME 2>/dev/null | grep "quota name \"$quota_name\"" | head -n1 | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
        [ -z "$handle" ] && break
        local deleted=false
        local chain
        for chain in input output forward; do
            if nft delete rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME $chain handle $handle 2>/dev/null; then
                deleted=true
                deleted_count=$((deleted_count + 1))
                break
            fi
        done
        [ "$deleted" = false ] && break
        [ "$deleted_count" -ge 100 ] && break
    done
    nft delete quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME "$quota_name" 2>/dev/null || true
}

# ---- 到期封锁（复用 quota over 0 bytes 机制，第一个包即触发 drop） ----

ptm_block_port() {
    local port=$1
    ptm_init_nftables
    local port_safe
    port_safe=$(ptm_safe_name "$port")
    ptm_remove_nftables_rules "$port"

    local quota_name="port_${port_safe}_block_quota"
    nft delete quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME $quota_name 2>/dev/null || true
    nft add quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME $quota_name { over 0 bytes\; } 2>/dev/null || \
        nft add quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME $quota_name { over 0 bytes } 2>/dev/null || true

    local ports_to_block
    if ptm_is_port_group "$port"; then
        ports_to_block=$(ptm_get_group_ports "$port")
    else
        ports_to_block="$port"
    fi
    local single_port chain
    for single_port in $ports_to_block; do
        for chain in input forward prerouting; do
            nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME $chain tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME $chain udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        done
        for chain in output forward; do
            nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME $chain tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME $chain udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        done
    done
}

ptm_unblock_port() {
    local port=$1
    local port_safe
    port_safe=$(ptm_safe_name "$port")
    local quota_name="port_${port_safe}_block_quota"
    local deleted_count=0
    while true; do
        local handle
        handle=$(nft -a list table $PTM_TABLE_FAMILY $PTM_TABLE_NAME 2>/dev/null | grep "quota name \"$quota_name\"" | head -n1 | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
        [ -z "$handle" ] && break
        local deleted=false
        local chain
        for chain in input output forward prerouting; do
            if nft delete rule $PTM_TABLE_FAMILY $PTM_TABLE_NAME $chain handle $handle 2>/dev/null; then
                deleted=true
                deleted_count=$((deleted_count + 1))
                break
            fi
        done
        [ "$deleted" = false ] && break
        [ "$deleted_count" -ge 100 ] && break
    done
    nft delete quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME "$quota_name" 2>/dev/null || true
    ptm_add_nftables_rules "$port"
    local monthly_limit
    monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE")
    [ "$monthly_limit" != "unlimited" ] && ptm_apply_quota "$port" "$monthly_limit"
}

# ---- tc 带宽限速 ----

ptm_generate_mark() {
    local hash
    hash=$(echo -n "$(ptm_safe_name "$1")" | cksum | cut -d' ' -f1)
    echo $(( hash % 65000 + 1000 ))
}

ptm_generate_tc_class_id() {
    local port=$1
    if ptm_is_port_group "$port" || ptm_is_port_range "$port"; then
        local mark_id
        mark_id=$(ptm_generate_mark "$port")
        echo "1:$(printf '%x' $((0x2000 + (mark_id % 4096))))"
    else
        echo "1:$(printf '%x' $((0x1000 + port)))"
    fi
}

ptm_calculate_tc_burst() {
    local base_rate=$1
    local rate_bytes_per_sec=$((base_rate * 1000 / 8))
    local burst_by_formula=$((rate_bytes_per_sec / 20))
    local min_burst=$((2 * 1500))
    [ "$burst_by_formula" -gt "$min_burst" ] && echo "$burst_by_formula" || echo "$min_burst"
}

ptm_format_tc_burst() {
    local burst_bytes=$1
    if [ "$burst_bytes" -lt 1024 ]; then
        echo "${burst_bytes}"
    elif [ "$burst_bytes" -lt 1048576 ]; then
        echo "$((burst_bytes / 1024))k"
    else
        echo "$((burst_bytes / 1048576))m"
    fi
}

ptm_parse_tc_rate_to_kbps() {
    local total_limit=$1
    if [[ "$total_limit" =~ gbit$ ]]; then
        echo $(( ${total_limit%gbit} * 1000000 ))
    elif [[ "$total_limit" =~ mbit$ ]]; then
        echo $(( ${total_limit%mbit} * 1000 ))
    else
        echo "${total_limit%kbit}"
    fi
}

ptm_apply_tc_limit() {
    local port=$1 total_limit=$2
    local interface
    interface=$(ptm_get_default_interface)

    tc qdisc add dev "$interface" root handle 1: htb default 30 2>/dev/null || true
    tc class add dev "$interface" parent 1: classid 1:1 htb rate 1000mbit 2>/dev/null || true

    local class_id
    class_id=$(ptm_generate_tc_class_id "$port")
    tc class del dev "$interface" classid "$class_id" 2>/dev/null || true

    local base_rate burst_bytes burst_size
    base_rate=$(ptm_parse_tc_rate_to_kbps "$total_limit")
    burst_bytes=$(ptm_calculate_tc_burst "$base_rate")
    burst_size=$(ptm_format_tc_burst "$burst_bytes")

    if ! tc class add dev "$interface" parent 1:1 classid "$class_id" htb rate "$total_limit" ceil "$total_limit" burst "$burst_size" 2>/dev/null; then
        echo -e "${gl_hong}设置带宽限制失败，请检查网络设备${gl_bai}" >&2
        return 1
    fi

    if ptm_is_port_group "$port" || ptm_is_port_range "$port"; then
        local mark_id
        mark_id=$(ptm_generate_mark "$port")
        tc filter add dev "$interface" protocol ip parent 1:0 prio 1 handle "$mark_id" fw flowid "$class_id" 2>/dev/null || true
    else
        local filter_prio=$((port % 1000 + 1))
        tc filter add dev "$interface" protocol ip parent 1:0 prio "$filter_prio" u32 \
            match ip protocol 6 0xff match ip sport "$port" 0xffff flowid "$class_id" 2>/dev/null || true
        tc filter add dev "$interface" protocol ip parent 1:0 prio "$filter_prio" u32 \
            match ip protocol 6 0xff match ip dport "$port" 0xffff flowid "$class_id" 2>/dev/null || true
        tc filter add dev "$interface" protocol ip parent 1:0 prio $((filter_prio + 1000)) u32 \
            match ip protocol 17 0xff match ip sport "$port" 0xffff flowid "$class_id" 2>/dev/null || true
        tc filter add dev "$interface" protocol ip parent 1:0 prio $((filter_prio + 1000)) u32 \
            match ip protocol 17 0xff match ip dport "$port" 0xffff flowid "$class_id" 2>/dev/null || true
    fi
}

ptm_remove_tc_limit() {
    local port=$1
    local interface class_id
    interface=$(ptm_get_default_interface)
    class_id=$(ptm_generate_tc_class_id "$port")
    tc filter del dev "$interface" 2>/dev/null || true
    tc class del dev "$interface" classid "$class_id" 2>/dev/null || true
}

# ---- 到期日 / 计费周期计算 ----

ptm_calculate_next_expiration() {
    local base_date="$1" months="$2" target_day="$3"
    pm_add_months "$base_date" "$months" "$target_day"
}

# 计算当前计费周期的起始日期（YYYY-MM-DD），reset_day 超过当月天数时收敛到月末，
# 避免生成 2月31日 这类非法日期；据此判断是否需要重置可自动补偿关机/cron漏跑错过的重置。
ptm_get_billing_cycle_start() {
    local reset_day=${1:-1}
    local today_day year month
    today_day=$(ptm_beijing_time +%d | sed 's/^0//')
    year=$(ptm_beijing_time +%Y)
    month=$(ptm_beijing_time +%m)

    local cur_last
    cur_last=$(ptm_days_in_month "$year" "$month")
    [[ "$cur_last" =~ ^[0-9]+$ ]] || cur_last=28
    local cur_effective=$reset_day
    [ "$reset_day" -gt "$cur_last" ] && cur_effective=$cur_last

    if [ "$today_day" -ge "$cur_effective" ]; then
        printf "%s-%s-%02d" "$year" "$month" "$cur_effective"
    else
        if [ "$month" = "01" ]; then
            month="12"; year=$((year - 1))
        else
            month=$(printf "%02d" $((10#$month - 1)))
        fi
        local prev_last
        prev_last=$(ptm_days_in_month "$year" "$month")
        [[ "$prev_last" =~ ^[0-9]+$ ]] || prev_last=28
        local prev_effective=$reset_day
        [ "$reset_day" -gt "$prev_last" ] && prev_effective=$prev_last
        printf "%s-%s-%02d" "$year" "$month" "$prev_effective"
    fi
}

ptm_record_reset_history() {
    local port=$1 traffic_bytes=$2
    local timestamp
    timestamp=$(ptm_beijing_time +%s)
    echo "${timestamp}|${port}|${traffic_bytes}" >> "$PTM_RESET_HISTORY_LOG"
    if [ -f "$PTM_RESET_HISTORY_LOG" ] && [ "$(wc -l < "$PTM_RESET_HISTORY_LOG")" -gt 100 ]; then
        tail -n 100 "$PTM_RESET_HISTORY_LOG" > "${PTM_RESET_HISTORY_LOG}.tmp"
        mv "${PTM_RESET_HISTORY_LOG}.tmp" "$PTM_RESET_HISTORY_LOG"
    fi
}

ptm_reset_port_counters() {
    local port=$1
    local port_safe
    port_safe=$(ptm_safe_name "$port")
    nft reset counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_in" >/dev/null 2>&1 || true
    nft reset counter $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_out" >/dev/null 2>&1 || true
    nft reset quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_quota" >/dev/null 2>&1 || true
}

ptm_auto_reset_port() {
    local port="$1"
    local traffic=($(ptm_get_port_traffic "$port"))
    local billing_mode total_bytes
    billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE")
    total_bytes=$(ptm_calculate_total_traffic "${traffic[0]:-0}" "${traffic[1]:-0}" "$billing_mode")
    ptm_reset_port_counters "$port"
    ptm_record_reset_history "$port" "$total_bytes"
    ptm_log_notification "端口 $port 自动重置完成，重置前流量: $(ptm_format_bytes "$total_bytes")"
}

# 按计费周期批量重置到期端口，可补偿关机/cron漏跑导致的错过重置
ptm_reset_all_due_ports() {
    local port reset_count=0
    for port in $(ptm_get_active_ports); do
        local reset_day_raw
        reset_day_raw=$(jq -r ".ports.\"$port\".quota.reset_day" "$PTM_CONFIG_FILE" 2>/dev/null)
        [ "$reset_day_raw" = "null" ] || [ -z "$reset_day_raw" ] && continue

        local current_cycle last_cycle
        current_cycle=$(ptm_get_billing_cycle_start "$reset_day_raw")
        last_cycle=$(jq -r ".ports.\"$port\".quota.last_reset_cycle // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)

        if [ -z "$last_cycle" ] || [ "$last_cycle" = "null" ]; then
            ptm_update_config ".ports.\"$port\".quota.last_reset_cycle = \"$current_cycle\"" || true
            continue
        fi

        if [ "$last_cycle" != "$current_cycle" ]; then
            if ptm_auto_reset_port "$port"; then
                ptm_update_config ".ports.\"$port\".quota.last_reset_cycle = \"$current_cycle\"" || true
                reset_count=$((reset_count + 1))
            fi
        fi
    done
    [ "$reset_count" -gt 0 ] && ptm_log_notification "[批量重置] 本次成功重置 $reset_count 个端口"
}

# ---- 邮件通知 (Resend API) ----

ptm_send_email() {
    local title="$1" html_content="$2" target_email="$3"
    local api_key email_from email_from_name
    api_key=$(jq -r '.notify.resend_api_key // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    email_from=$(jq -r '.notify.email_from // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    email_from_name=$(jq -r '.notify.email_from_name // ""' "$PTM_CONFIG_FILE" 2>/dev/null)

    if [ -z "$api_key" ] || [ -z "$email_from" ] || [ -z "$target_email" ]; then
        return 1
    fi

    local from_address="$email_from"
    [ -n "$email_from_name" ] && [ "$email_from_name" != "null" ] && from_address="${email_from_name} <${email_from}>"

    local json_body
    json_body=$(jq -n --arg from "$from_address" --arg to "$target_email" --arg subject "$title" \
        --arg html "$html_content" --arg text "请使用支持HTML的邮箱客户端查看此邮件。" \
        '{from: $from, to: $to, subject: $subject, html: $html, text: $text}')

    local retry=0
    while [ "$retry" -le "$PTM_EMAIL_MAX_RETRIES" ]; do
        local response
        response=$(curl -s --connect-timeout "$PTM_EMAIL_CONNECT_TIMEOUT" --max-time "$PTM_EMAIL_MAX_TIMEOUT" \
            -X POST "https://api.resend.com/emails" \
            -H "Authorization: Bearer ${api_key}" -H "Content-Type: application/json" \
            -d "$json_body" 2>/dev/null)
        if echo "$response" | grep -q '"id"'; then
            ptm_log_notification "[邮件通知] 发送成功: $title"
            return 0
        fi
        retry=$((retry + 1))
        [ "$retry" -le "$PTM_EMAIL_MAX_RETRIES" ] && sleep 2
    done
    ptm_log_notification "[邮件通知] 发送失败: $title"
    return 1
}

# ---- 每日检查：到期预警/停机/超期清理 + 配额80%/100%预警 ----

ptm_check_all_expiration() {
    local today today_epoch admin_email tg_warning_days
    today=$(ptm_beijing_time +%Y-%m-%d)
    today_epoch=$(ptm_date_epoch "$today" 2>/dev/null || echo "0")
    admin_email=$(jq -r '.notify.admin_email // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    tg_warning_days=$(jq -r '.notify.telegram.expire_warning_days // 3' "$PTM_CONFIG_FILE" 2>/dev/null)
    [[ "$tg_warning_days" =~ ^[0-9]+$ ]] || tg_warning_days=3
    local ports_to_cleanup=()

    local port
    for port in $(ptm_get_active_ports); do
        local expire_date
        expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$PTM_CONFIG_FILE")
        [ -z "$expire_date" ] || [ "$expire_date" = "null" ] && continue

        local user_email expire_epoch
        user_email=$(jq -r ".ports.\"$port\".email // \"\"" "$PTM_CONFIG_FILE")
        expire_epoch=$(ptm_date_epoch "$expire_date" 2>/dev/null || echo "0")
        [ "$expire_epoch" -eq 0 ] && continue

        # 预警天数由车主配置，默认 3 天以保持原行为。
        local warning_epoch=$((expire_epoch - tg_warning_days * 86400))
        if [ "$today_epoch" -ge "$warning_epoch" ] && [ "$today_epoch" -lt "$expire_epoch" ]; then
            local last_warning_target
            last_warning_target=$(jq -r ".ports.\"$port\".last_warning_target_date // \"\"" "$PTM_CONFIG_FILE")
            if [ "$last_warning_target" != "$expire_date" ]; then
                local warning_sent=false
                if [ -n "$user_email" ] && [ "$user_email" != "null" ]; then
                    if ptm_send_email "【租期提醒】端口 $port 即将到期" \
                        "<h1>⚠️ 续费提醒</h1><p>您租用的端口 <strong>$port</strong> 即将到期 (<strong>$expire_date</strong>)，请及时续费。</p>" \
                        "$user_email"; then
                        warning_sent=true
                    fi
                fi
                if ptm_send_telegram_to_port "$port" "$(ptm_build_port_user_message "$port" "续费提醒")"; then
                    warning_sent=true
                fi
                [ "$warning_sent" = true ] && ptm_update_config ".ports.\"$port\".last_warning_target_date = \"$expire_date\""
                [ -n "$admin_email" ] && [ "$admin_email" != "null" ] && ptm_send_email "[租期预警] 端口 $port 即将到期" \
                    "<p>端口 $port 到期日: $expire_date</p>" "$admin_email"
                ptm_send_telegram_to_admin "租期预警
端口：$port
到期日：$expire_date"
            fi
        fi

        if [ "$today_epoch" -gt "$expire_epoch" ]; then
            local days_expired=$(( (today_epoch - expire_epoch) / 86400 ))
            if [ "$days_expired" -ge 3 ]; then
                ports_to_cleanup+=("$port")
                continue
            fi
            if ptm_is_port_rules_exist "$port"; then
                ptm_log_notification "[租期管理] 端口 $port 已到期 ($expire_date)，执行停机"
                [ -n "$user_email" ] && [ "$user_email" != "null" ] && ptm_send_email "【服务暂停】端口 $port 已到期停机" \
                    "<p>您租用的端口 $port 已到期 ($expire_date)，服务已暂停，请联系管理员续费。</p>" "$user_email"
                ptm_send_telegram_to_port "$port" "$(ptm_build_port_user_message "$port" "服务暂停")"
                [ -n "$admin_email" ] && [ "$admin_email" != "null" ] && ptm_send_email "[到期封锁] 端口 $port 已停机" \
                    "<p>端口 $port 到期日 $expire_date 已停机</p>" "$admin_email"
                ptm_send_telegram_to_admin "到期封锁
端口：$port
到期日：$expire_date
状态：已停机"
            fi
            ptm_block_port "$port"
            ptm_remove_tc_limit "$port"
        fi
    done

    for port in "${ports_to_cleanup[@]}"; do
        ptm_cleanup_expired_port "$port"
    done
}

ptm_check_all_quota() {
    local admin_email
    admin_email=$(jq -r '.notify.admin_email // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    local port
    for port in $(ptm_get_active_ports); do
        local quota_enabled monthly_limit
        quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // true" "$PTM_CONFIG_FILE")
        monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE")
        [ "$quota_enabled" != "true" ] || [ "$monthly_limit" = "unlimited" ] && continue

        local user_email user_tg_chat
        user_email=$(jq -r ".ports.\"$port\".email // \"\"" "$PTM_CONFIG_FILE")
        user_tg_chat=$(ptm_get_telegram_chat_for_port "$port")
        if { [ -z "$user_email" ] || [ "$user_email" = "null" ]; } && { [ -z "$user_tg_chat" ] || [ "$user_tg_chat" = "null" ]; }; then
            continue
        fi

        local current_usage limit_bytes
        current_usage=$(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo "0")
        limit_bytes=$(ptm_parse_size_to_bytes "$monthly_limit" 2>/dev/null || echo "0")
        [ "$limit_bytes" -le 0 ] && continue

        local usage_percent=$((current_usage * 100 / limit_bytes))
        local reset_day cycle_start
        reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // 1" "$PTM_CONFIG_FILE")
        cycle_start=$(ptm_get_billing_cycle_start "$reset_day")

        # 用百分比（95%）而非固定字节数做"已用尽"阈值，避免小额配额端口被误判
        local block_threshold=$((limit_bytes * 95 / 100))
        if [ "$current_usage" -ge "$block_threshold" ]; then
            local last_block_cycle
            last_block_cycle=$(jq -r ".ports.\"$port\".last_quota_block_notify_cycle // \"\"" "$PTM_CONFIG_FILE")
            if [ "$last_block_cycle" != "$cycle_start" ]; then
                local block_sent=false
                if [ -n "$user_email" ] && [ "$user_email" != "null" ] && ptm_send_email "【流量超限】端口 $port 已被暂停" \
                    "<p>端口 $port 本月流量配额已用完 (${usage_percent}%)，已被暂停服务。</p>" "$user_email"; then
                    block_sent=true
                fi
                if ptm_send_telegram_to_port "$port" "$(ptm_build_port_user_message "$port" "流量超限")"; then
                    block_sent=true
                fi
                if [ "$block_sent" = true ]; then
                    ptm_update_config ".ports.\"$port\".last_quota_block_notify_cycle = \"$cycle_start\""
                fi
            fi
        elif [ "$usage_percent" -ge 80 ]; then
            local last_warn_cycle
            last_warn_cycle=$(jq -r ".ports.\"$port\".last_quota_warning_cycle // \"\"" "$PTM_CONFIG_FILE")
            if [ "$last_warn_cycle" != "$cycle_start" ]; then
                local warn_sent=false
                if [ -n "$user_email" ] && [ "$user_email" != "null" ] && ptm_send_email "【流量预警】端口 $port 配额即将用完" \
                    "<p>端口 $port 本月流量配额已使用 ${usage_percent}%。</p>" "$user_email"; then
                    warn_sent=true
                fi
                if ptm_send_telegram_to_port "$port" "$(ptm_build_port_user_message "$port" "流量预警")"; then
                    warn_sent=true
                fi
                if [ "$warn_sent" = true ]; then
                    ptm_update_config ".ports.\"$port\".last_quota_warning_cycle = \"$cycle_start\""
                fi
            fi
        fi
    done
}

ptm_cleanup_expired_port() {
    local port=$1
    local user_email admin_email remark expire_date
    user_email=$(jq -r ".ports.\"$port\".email // \"\"" "$PTM_CONFIG_FILE")
    admin_email=$(jq -r '.notify.admin_email // ""' "$PTM_CONFIG_FILE")
    remark=$(jq -r ".ports.\"$port\".remark // \"$port\"" "$PTM_CONFIG_FILE")
    expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$PTM_CONFIG_FILE")

    local port_backup
    port_backup=$(jq ".ports.\"$port\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    ptm_log_notification "[自动清理-备份] 端口 $port 清理前配置快照: $port_backup"
    ptm_log_notification "[自动清理] 端口 $port ($remark) 过期超3天，开始自动清理"

    ptm_remove_nftables_rules "$port"
    ptm_remove_quota "$port"
    ptm_remove_tc_limit "$port"

    if command -v conntrack >/dev/null 2>&1; then
        local p
        for p in $(ptm_get_group_ports "$port"); do
            conntrack -D -p tcp --dport "$p" 2>/dev/null || true
            conntrack -D -p udp --dport "$p" 2>/dev/null || true
        done
    fi

    ptm_update_config "del(.ports.\"$port\")"

    if [ -f "$PTM_RESET_HISTORY_LOG" ]; then
        grep -v "|${port}|" "$PTM_RESET_HISTORY_LOG" > "${PTM_RESET_HISTORY_LOG}.tmp" 2>/dev/null || true
        mv "${PTM_RESET_HISTORY_LOG}.tmp" "$PTM_RESET_HISTORY_LOG" 2>/dev/null || true
    fi

    [ -n "$admin_email" ] && [ "$admin_email" != "null" ] && ptm_send_email "[自动清理] 端口 $port ($remark) 已回收" \
        "<p>端口 $port ($remark) 到期日 $expire_date，已自动清理监控。</p>" "$admin_email"
    ptm_send_telegram_to_admin "自动清理
端口：$port
备注：${remark}
到期日：${expire_date}
状态：已回收"

    ptm_log_notification "[自动清理] 端口 $port ($remark) 清理完成"
}

# 重启/进程恢复后重建规则：已过期的端口重新封锁而非放行，避免出现免费可用窗口
ptm_restore_monitoring_if_needed() {
    local port
    for port in $(ptm_get_active_ports); do
        local expire_date today_epoch expire_epoch
        expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$PTM_CONFIG_FILE")
        if [ -n "$expire_date" ] && [ "$expire_date" != "null" ]; then
            today_epoch=$(ptm_date_epoch "$(ptm_beijing_time +%Y-%m-%d)" 2>/dev/null || echo "0")
            expire_epoch=$(ptm_date_epoch "$expire_date" 2>/dev/null || echo "0")
            if [ "$expire_epoch" -gt 0 ] && [ "$today_epoch" -gt "$expire_epoch" ]; then
                ptm_block_port "$port"
                continue
            fi
        fi
        if ! ptm_is_port_rules_exist "$port"; then
            ptm_add_nftables_rules "$port"
            local monthly_limit
            monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE")
            [ "$monthly_limit" != "unlimited" ] && ptm_apply_quota "$port" "$monthly_limit"
            local rate_enabled
            rate_enabled=$(jq -r ".ports.\"$port\".bandwidth_limit.enabled // false" "$PTM_CONFIG_FILE")
            if [ "$rate_enabled" = "true" ]; then
                local rate
                rate=$(jq -r ".ports.\"$port\".bandwidth_limit.rate // \"\"" "$PTM_CONFIG_FILE")
                [ -n "$rate" ] && [ "$rate" != "unlimited" ] && ptm_apply_tc_limit "$port" "$(ptm_rate_to_tc "$rate")"
            fi
        fi
    done
}

# ---- Telegram Bot 交互服务 ----

ptm_telegram_is_admin() {
    local chat_id="$1" admin_chat
    admin_chat=$(jq -r '.notify.telegram.admin_chat_id // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    [ -n "$admin_chat" ] && [ "$admin_chat" != "null" ] && [ "$chat_id" = "$admin_chat" ]
}

ptm_telegram_help_text() {
    local role="$1"
    if [ "$role" = "admin" ]; then
        cat <<'EOF'
管理员命令：
/id - 查看当前 Chat ID
/adduser - 分步添加/绑定用户
/ports - 查看全部端口概览
/port 端口 - 查看指定端口详情
/users - 显示所有用户并点选查看详情
/bind 端口 ChatID - 绑定用户 Telegram
/unbind 端口 - 解除端口 Telegram 绑定
/renew 端口 月数 - 为端口续期
/expire 端口 YYYY-MM-DD - 设置到期日
/expire 端口 permanent - 设置为永久
/report - 手动发送一次用量概览
/reporton - 开启周期概览推送
/reportoff - 关闭周期概览推送
/schedule daily|weekly|month_end - 设置全局推送周期
/schedule 端口 inherit|daily|weekly|month_end|off - 设置单用户周期
/cancel - 取消当前分步操作
EOF
    else
        cat <<'EOF'
用户命令：
/id - 查看当前 Chat ID，发给车主绑定
/status - 查看自己的节点用量
EOF
    fi
}

ptm_telegram_format_port_choices() {
    local msg="当前可选端口："$'\n'
    local port
    for port in $(ptm_get_active_ports 2>/dev/null); do
        local remark
        remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        if [ -n "$remark" ] && [ "$remark" != "null" ]; then
            msg+="- ${port} [${remark}]"$'\n'
        else
            msg+="- ${port}"$'\n'
        fi
    done
    echo "$msg"
}

ptm_telegram_session_step() {
    local chat_id="$1"
    jq -r ".notify.telegram.sessions.\"$chat_id\".step // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null
}

ptm_telegram_clear_session() {
    local chat_id="$1"
    ptm_update_config "del(.notify.telegram.sessions.\"$chat_id\")" >/dev/null 2>&1 || true
}

ptm_telegram_start_adduser() {
    local chat_id="$1"
    if ! ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_to_chat "$chat_id" "只有管理员可以添加用户。"
        return
    fi
    if [ -z "$(ptm_get_active_ports 2>/dev/null)" ]; then
        ptm_send_telegram_to_chat "$chat_id" "暂无可绑定端口，请先在脚本菜单添加端口监控。"
        return
    fi
    ptm_update_config ".notify.telegram.sessions.\"$chat_id\" = {\"flow\":\"adduser\",\"step\":\"port\"}" >/dev/null 2>&1 || true
    ptm_send_telegram_to_chat "$chat_id" "添加用户 1/3
请输入要绑定的端口。

$(ptm_telegram_format_port_choices)
发送 /cancel 取消。"
}

ptm_telegram_handle_adduser_step() {
    local chat_id="$1" text="$2"
    local step
    step=$(ptm_telegram_session_step "$chat_id")
    case "$step" in
        port)
            if ! ptm_port_exists "$text"; then
                ptm_send_telegram_to_chat "$chat_id" "未找到端口：$text

请重新输入要绑定的端口，或发送 /cancel 取消。"
                return
            fi
            local port_json
            port_json=$(ptm_json_string "$text")
            ptm_update_config ".notify.telegram.sessions.\"$chat_id\".port = $port_json | .notify.telegram.sessions.\"$chat_id\".step = \"chat_id\"" >/dev/null 2>&1 || true
            ptm_send_telegram_to_chat "$chat_id" "添加用户 2/3
请输入用户 Telegram Chat ID。

让用户先给 Bot 发送 /id，然后把返回的 Chat ID 发到这里。
发送 /cancel 取消。"
            ;;
        chat_id)
            if ! [[ "$text" =~ ^-?[0-9]+$ ]]; then
                ptm_send_telegram_to_chat "$chat_id" "Chat ID 格式错误，请重新输入数字 Chat ID，或发送 /cancel 取消。"
                return
            fi
            local target_json
            target_json=$(ptm_json_string "$text")
            ptm_update_config ".notify.telegram.sessions.\"$chat_id\".target_chat_id = $target_json | .notify.telegram.sessions.\"$chat_id\".step = \"remark\"" >/dev/null 2>&1 || true
            ptm_send_telegram_to_chat "$chat_id" "添加用户 3/3
请输入用户备注。

备注会作为用户在 Bot 里的醒目名称；输入 - 则保留原备注。
发送 /cancel 取消。"
            ;;
        remark)
            local port target_chat remark_json chat_json
            port=$(jq -r ".notify.telegram.sessions.\"$chat_id\".port // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)
            target_chat=$(jq -r ".notify.telegram.sessions.\"$chat_id\".target_chat_id // \"\"" "$PTM_CONFIG_FILE" 2>/dev/null)
            if [ -z "$port" ] || [ -z "$target_chat" ] || ! ptm_port_exists "$port"; then
                ptm_telegram_clear_session "$chat_id"
                ptm_send_telegram_to_chat "$chat_id" "添加流程状态异常，已取消。请重新发送 /adduser。"
                return
            fi
            chat_json=$(ptm_json_string "$target_chat")
            if [ "$text" = "-" ]; then
                ptm_update_config ".ports.\"$port\".telegram_chat_id = $chat_json" >/dev/null 2>&1
            else
                remark_json=$(ptm_json_string "$text")
                ptm_update_config ".ports.\"$port\".telegram_chat_id = $chat_json | .ports.\"$port\".remark = $remark_json" >/dev/null 2>&1
            fi
            ptm_telegram_clear_session "$chat_id"
            ptm_send_telegram_to_chat "$chat_id" "用户添加完成。

$(ptm_build_port_plain_message "$port" "用户绑定信息")"
            ptm_send_telegram_to_chat "$target_chat" "$(ptm_build_port_user_message "$port" "绑定成功")" || true
            ;;
        *)
            ptm_telegram_clear_session "$chat_id"
            ptm_send_telegram_to_chat "$chat_id" "当前没有进行中的添加流程。发送 /adduser 开始。"
            ;;
    esac
}

ptm_telegram_can_access_port() {
    local chat_id="$1" port="$2" bound_chat
    ptm_telegram_is_admin "$chat_id" && return 0
    bound_chat=$(ptm_get_telegram_chat_for_port "$port")
    [ -n "$bound_chat" ] && [ "$bound_chat" = "$chat_id" ]
}

ptm_telegram_send_port() {
    local chat_id="$1" port="$2"
    if ! ptm_port_exists "$port"; then
        ptm_send_telegram_to_chat "$chat_id" "未找到端口：$port"
        return
    fi
    if ! ptm_telegram_can_access_port "$chat_id" "$port"; then
        ptm_send_telegram_to_chat "$chat_id" "无权查看端口：$port"
        return
    fi
    if ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_long "$chat_id" "$(ptm_build_port_plain_message "$port" "节点使用情况")"
    else
        ptm_send_telegram_long "$chat_id" "$(ptm_build_port_user_message "$port" "节点使用情况")"
    fi
}

ptm_telegram_send_ports_summary() {
    local chat_id="$1" ports="$2" title="$3"
    if [ -z "$ports" ]; then
        ptm_send_telegram_to_chat "$chat_id" "暂无可查看的端口。"
        return
    fi
    if ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_long "$chat_id" "$(ptm_build_ports_summary_text "$title" "$ports")"
    else
        ptm_send_telegram_long "$chat_id" "$(ptm_build_user_ports_summary_text "$title" "$ports")"
    fi
}

ptm_telegram_send_users() {
    local chat_id="$1"
    local count keyboard
    count=$(jq '[.ports | to_entries[] | select((.value.telegram_chat_id // "") != "")] | length' "$PTM_CONFIG_FILE" 2>/dev/null || echo 0)
    if [ "$count" -eq 0 ]; then
        ptm_send_telegram_to_chat "$chat_id" "当前没有已绑定 Telegram 的用户。发送 /adduser 添加。"
        return
    fi
    keyboard=$(jq -c '
        [.ports | to_entries | sort_by(.key) | map(select((.value.telegram_chat_id // "") != "")) | to_entries[] |
            [ {
                text: (((.value.value.remark // "") as $r | if $r == "" then ("端口 " + .value.key) else $r end) + "｜" + (.value.value.telegram_chat_id // "")),
                callback_data: ("ptm_user_idx:" + (.key | tostring))
            } ]
        ] | {inline_keyboard: .}
    ' "$PTM_CONFIG_FILE" 2>/dev/null)
    if [ -z "$keyboard" ] || [ "$keyboard" = "null" ]; then
        ptm_send_telegram_to_chat "$chat_id" "用户列表生成失败，请稍后重试。"
        return
    fi
    ptm_send_telegram_with_keyboard "$chat_id" "当前共有 ${count} 个用户，点击查看使用情况：" "$keyboard"
}

ptm_telegram_handle_callback() {
    local callback_id="$1" chat_id="$2" data="$3"
    ptm_answer_telegram_callback "$callback_id" "" || true
    if ! ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_to_chat "$chat_id" "只有管理员可以查看用户详情。"
        return
    fi
    case "$data" in
        ptm_user_idx:*)
            local idx="${data#ptm_user_idx:}" port
            if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
                ptm_send_telegram_to_chat "$chat_id" "用户索引无效。"
                return
            fi
            port=$(jq -r --argjson idx "$idx" '.ports | to_entries | sort_by(.key) | map(select((.value.telegram_chat_id // "") != "")) | .[$idx].key // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
            if [ -z "$port" ] || [ "$port" = "null" ] || ! ptm_port_exists "$port"; then
                ptm_send_telegram_to_chat "$chat_id" "该用户已不存在，请重新发送 /users 刷新列表。"
                return
            fi
            ptm_send_telegram_long "$chat_id" "$(ptm_build_port_plain_message "$port" "用户使用情况")"
            ;;
        ptm_user:*)
            local port="${data#ptm_user:}"
            if ! ptm_port_exists "$port"; then
                ptm_send_telegram_to_chat "$chat_id" "该用户对应的端口已不存在。"
                return
            fi
            ptm_send_telegram_long "$chat_id" "$(ptm_build_port_plain_message "$port" "用户使用情况")"
            ;;
        *)
            ptm_send_telegram_to_chat "$chat_id" "未知操作。"
            ;;
    esac
}

ptm_telegram_bind_port() {
    local chat_id="$1" port="$2" target_chat="$3"
    if ! ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_to_chat "$chat_id" "只有管理员可以绑定用户。"
        return
    fi
    if ! ptm_port_exists "$port"; then
        ptm_send_telegram_to_chat "$chat_id" "未找到端口：$port"
        return
    fi
    if ! [[ "$target_chat" =~ ^-?[0-9]+$ ]]; then
        ptm_send_telegram_to_chat "$chat_id" "Chat ID 格式错误。"
        return
    fi
    local chat_json
    chat_json=$(ptm_json_string "$target_chat")
    if ptm_update_config ".ports.\"$port\".telegram_chat_id = $chat_json"; then
        ptm_send_telegram_to_chat "$chat_id" "已绑定端口 $port 到 Chat ID：$target_chat"
        ptm_send_telegram_to_chat "$target_chat" "$(ptm_build_port_user_message "$port" "绑定成功")" || true
    else
        ptm_send_telegram_to_chat "$chat_id" "绑定失败，请稍后重试。"
    fi
}

ptm_telegram_unbind_port() {
    local chat_id="$1" port="$2"
    if ! ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_to_chat "$chat_id" "只有管理员可以解除绑定。"
        return
    fi
    if ! ptm_port_exists "$port"; then
        ptm_send_telegram_to_chat "$chat_id" "未找到端口：$port"
        return
    fi
    if ptm_update_config ".ports.\"$port\".telegram_chat_id = \"\""; then
        ptm_send_telegram_to_chat "$chat_id" "已解除端口 $port 的 Telegram 绑定。"
    else
        ptm_send_telegram_to_chat "$chat_id" "解除绑定失败，请稍后重试。"
    fi
}

ptm_telegram_renew_port() {
    local chat_id="$1" port="$2" months="$3"
    if ! ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_to_chat "$chat_id" "只有管理员可以续期。"
        return
    fi
    if ! ptm_port_exists "$port"; then
        ptm_send_telegram_to_chat "$chat_id" "未找到端口：$port"
        return
    fi
    if ! [[ "$months" =~ ^[0-9]+$ ]] || [ "$months" -lt 1 ] || [ "$months" -gt 120 ]; then
        ptm_send_telegram_to_chat "$chat_id" "续期月数需为 1-120 的整数。"
        return
    fi
    if ptm_do_renew_months "$port" "$months" >/dev/null 2>&1; then
        ptm_send_telegram_to_chat "$chat_id" "$(ptm_build_port_plain_message "$port" "续期成功")"
        ptm_send_telegram_to_port "$port" "$(ptm_build_port_user_message "$port" "续费已更新")" || true
    else
        ptm_send_telegram_to_chat "$chat_id" "续期失败，请回到脚本菜单检查端口状态。"
    fi
}

ptm_telegram_set_expire_port() {
    local chat_id="$1" port="$2" expire_date="$3"
    if ! ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_to_chat "$chat_id" "只有管理员可以设置到期日。"
        return
    fi
    if ! ptm_port_exists "$port"; then
        ptm_send_telegram_to_chat "$chat_id" "未找到端口：$port"
        return
    fi
    case "$expire_date" in
        permanent|forever|永久)
            if ptm_update_config ".ports.\"$port\".expiration_date = \"\""; then
                [ "$(ptm_get_port_running_status "$port")" = "blocked_expired" ] && ptm_unblock_port "$port"
                ptm_send_telegram_to_chat "$chat_id" "$(ptm_build_port_plain_message "$port" "已设置为永久")"
            else
                ptm_send_telegram_to_chat "$chat_id" "设置失败，请稍后重试。"
            fi
            ;;
        *)
            if ! ptm_date_valid "$expire_date"; then
                ptm_send_telegram_to_chat "$chat_id" "日期格式错误，请使用 YYYY-MM-DD。"
                return
            fi
            if ptm_do_set_expiration "$port" "$expire_date" >/dev/null 2>&1; then
                ptm_send_telegram_to_chat "$chat_id" "$(ptm_build_port_plain_message "$port" "到期日已更新")"
                ptm_send_telegram_to_port "$port" "$(ptm_build_port_user_message "$port" "到期日已更新")" || true
            else
                ptm_send_telegram_to_chat "$chat_id" "设置失败，请回到脚本菜单检查端口状态。"
            fi
            ;;
    esac
}

ptm_telegram_set_report_enabled() {
    local chat_id="$1" enabled="$2"
    if ! ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_to_chat "$chat_id" "只有管理员可以修改概览推送。"
        return
    fi
    if [ "$enabled" = "true" ]; then
        ptm_update_config ".notify.telegram.report_enabled = true | .notify.telegram.daily_report_enabled = true" >/dev/null 2>&1
        ptm_send_telegram_to_chat "$chat_id" "周期概览推送已开启。"
    else
        ptm_update_config ".notify.telegram.report_enabled = false | .notify.telegram.daily_report_enabled = false" >/dev/null 2>&1
        ptm_send_telegram_to_chat "$chat_id" "周期概览推送已关闭。"
    fi
}

ptm_telegram_set_report_schedule() {
    local chat_id="$1" arg1="$2" arg2="$3"
    if ! ptm_telegram_is_admin "$chat_id"; then
        ptm_send_telegram_to_chat "$chat_id" "只有管理员可以设置推送周期。"
        return
    fi
    if [ -z "$arg1" ]; then
        ptm_send_telegram_to_chat "$chat_id" "用法：
/schedule daily
/schedule weekly
/schedule month_end
/schedule 端口 inherit|daily|weekly|month_end|off"
        return
    fi

    local schedule schedule_json
    if [ -z "$arg2" ]; then
        schedule=$(ptm_normalize_report_schedule "$arg1" false)
        if [ -z "$schedule" ]; then
            ptm_send_telegram_to_chat "$chat_id" "周期无效，可用：daily、weekly、month_end、off。"
            return
        fi
        schedule_json=$(ptm_json_string "$schedule")
        if [ "$schedule" = "off" ]; then
            ptm_update_config ".notify.telegram.report_schedule = $schedule_json | .notify.telegram.report_enabled = false | .notify.telegram.daily_report_enabled = false" >/dev/null 2>&1
        else
            ptm_update_config ".notify.telegram.report_schedule = $schedule_json | .notify.telegram.report_enabled = true | .notify.telegram.daily_report_enabled = true" >/dev/null 2>&1
        fi
        ptm_send_telegram_to_chat "$chat_id" "全局概览推送周期已设置为：$(ptm_report_schedule_label "$schedule")"
        return
    fi

    if ! ptm_port_exists "$arg1"; then
        ptm_send_telegram_to_chat "$chat_id" "未找到端口：$arg1"
        return
    fi
    schedule=$(ptm_normalize_report_schedule "$arg2" true)
    if [ -z "$schedule" ]; then
        ptm_send_telegram_to_chat "$chat_id" "周期无效，可用：inherit、daily、weekly、month_end、off。"
        return
    fi
    schedule_json=$(ptm_json_string "$schedule")
    if ptm_update_config ".ports.\"$arg1\".telegram_report_schedule = $schedule_json"; then
        ptm_send_telegram_to_chat "$chat_id" "端口 $arg1 的用户概览推送周期已设置为：$(ptm_report_schedule_label "$schedule")"
    else
        ptm_send_telegram_to_chat "$chat_id" "设置失败，请稍后重试。"
    fi
}

ptm_telegram_handle_message() {
    local chat_id="$1" text="$2"
    text="${text//$'\r'/}"
    text="${text%%$'\n'*}"
    local cmd arg1 arg2 arg3
    read -r cmd arg1 arg2 arg3 _ <<< "$text"
    cmd="${cmd%@*}"

    local role="user"
    ptm_telegram_is_admin "$chat_id" && role="admin"

    if [ "$cmd" = "/cancel" ]; then
        ptm_telegram_clear_session "$chat_id"
        ptm_send_telegram_to_chat "$chat_id" "已取消当前操作。"
        return
    fi

    if [ "$role" = "admin" ] && [ -n "$(ptm_telegram_session_step "$chat_id")" ] && [[ "$cmd" != /* ]]; then
        ptm_telegram_handle_adduser_step "$chat_id" "$text"
        return
    fi

    if [ -z "$cmd" ] || [[ "$cmd" != /* ]]; then
        ptm_send_telegram_to_chat "$chat_id" "$(ptm_telegram_help_text user)"
        return
    fi

    case "$cmd" in
        /start|/help)
            ptm_send_telegram_to_chat "$chat_id" "Chat ID：$chat_id

$(ptm_telegram_help_text "$role")"
            ;;
        /id)
            ptm_send_telegram_to_chat "$chat_id" "Chat ID：$chat_id"
            ;;
        /adduser)
            ptm_telegram_start_adduser "$chat_id"
            ;;
        /status|/my)
            if [ "$role" = "admin" ]; then
                ptm_telegram_send_ports_summary "$chat_id" "$(ptm_get_active_ports 2>/dev/null)" "端口使用概览"
            else
                ptm_telegram_send_ports_summary "$chat_id" "$(ptm_get_telegram_bound_ports "$chat_id")" "我的节点"
            fi
            ;;
        /ports)
            if [ "$role" = "admin" ]; then
                ptm_telegram_send_ports_summary "$chat_id" "$(ptm_get_active_ports 2>/dev/null)" "端口使用概览"
            else
                ptm_telegram_send_ports_summary "$chat_id" "$(ptm_get_telegram_bound_ports "$chat_id")" "我的节点"
            fi
            ;;
        /port)
            if [ -z "$arg1" ] && [ "$role" != "admin" ]; then
                ptm_telegram_send_ports_summary "$chat_id" "$(ptm_get_telegram_bound_ports "$chat_id")" "我的节点"
                return
            fi
            [ -n "$arg1" ] || { ptm_send_telegram_to_chat "$chat_id" "用法：/port 端口"; return; }
            ptm_telegram_send_port "$chat_id" "$arg1"
            ;;
        /users)
            if [ "$role" = "admin" ]; then
                ptm_telegram_send_users "$chat_id"
            else
                ptm_send_telegram_to_chat "$chat_id" "只有管理员可以查看绑定列表。"
            fi
            ;;
        /bind)
            [ -n "$arg1" ] && [ -n "$arg2" ] || { ptm_send_telegram_to_chat "$chat_id" "用法：/bind 端口 ChatID"; return; }
            ptm_telegram_bind_port "$chat_id" "$arg1" "$arg2"
            ;;
        /unbind)
            [ -n "$arg1" ] || { ptm_send_telegram_to_chat "$chat_id" "用法：/unbind 端口"; return; }
            ptm_telegram_unbind_port "$chat_id" "$arg1"
            ;;
        /renew)
            [ -n "$arg1" ] && [ -n "$arg2" ] || { ptm_send_telegram_to_chat "$chat_id" "用法：/renew 端口 月数"; return; }
            ptm_telegram_renew_port "$chat_id" "$arg1" "$arg2"
            ;;
        /expire)
            [ -n "$arg1" ] && [ -n "$arg2" ] || { ptm_send_telegram_to_chat "$chat_id" "用法：/expire 端口 YYYY-MM-DD 或 /expire 端口 permanent"; return; }
            ptm_telegram_set_expire_port "$chat_id" "$arg1" "$arg2"
            ;;
        /report)
            if [ "$role" = "admin" ]; then
                ptm_send_daily_telegram_reports force
                ptm_send_telegram_to_chat "$chat_id" "已触发一次用量概览。"
            else
                ptm_send_telegram_to_chat "$chat_id" "只有管理员可以触发报告。"
            fi
            ;;
        /reporton)
            ptm_telegram_set_report_enabled "$chat_id" true
            ;;
        /reportoff)
            ptm_telegram_set_report_enabled "$chat_id" false
            ;;
        /schedule)
            ptm_telegram_set_report_schedule "$chat_id" "$arg1" "$arg2"
            ;;
        *)
            ptm_send_telegram_to_chat "$chat_id" "$(ptm_telegram_help_text "$role")"
            ;;
    esac
}

ptm_telegram_bot_loop() {
    ptm_init_config
    ptm_setup_telegram_commands || true
    while true; do
        local enabled bot_token offset response
        enabled=$(jq -r '.notify.telegram.enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
        bot_token=$(jq -r '.notify.telegram.bot_token // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
        if [ "$enabled" != "true" ] || [ -z "$bot_token" ] || [ "$bot_token" = "null" ]; then
            sleep 15
            continue
        fi
        offset=$(jq -r '.notify.telegram.update_offset // 0' "$PTM_CONFIG_FILE" 2>/dev/null)
        [[ "$offset" =~ ^[0-9]+$ ]] || offset=0
        response=$(curl -s --connect-timeout 10 --max-time 70 -G \
            "https://api.telegram.org/bot${bot_token}/getUpdates" \
            --data-urlencode "timeout=50" \
            --data-urlencode "offset=${offset}" \
            --data-urlencode 'allowed_updates=["message","callback_query"]' 2>/dev/null)
        if ! echo "$response" | jq -e '.ok == true' >/dev/null 2>&1; then
            ptm_log_notification "[TG Bot] getUpdates 失败"
            sleep 5
            continue
        fi

        local update
        while IFS= read -r update; do
            local update_id chat_id text callback_id callback_chat_id callback_data next_offset
            update_id=$(echo "$update" | jq -r '.update_id // empty')
            chat_id=$(echo "$update" | jq -r '.message.chat.id // empty | tostring')
            text=$(echo "$update" | jq -r '.message.text // empty')
            [ -n "$chat_id" ] && [ -n "$text" ] && ptm_telegram_handle_message "$chat_id" "$text"
            callback_id=$(echo "$update" | jq -r '.callback_query.id // empty')
            callback_chat_id=$(echo "$update" | jq -r '.callback_query.message.chat.id // empty | tostring')
            callback_data=$(echo "$update" | jq -r '.callback_query.data // empty')
            [ -n "$callback_id" ] && [ -n "$callback_chat_id" ] && [ -n "$callback_data" ] && \
                ptm_telegram_handle_callback "$callback_id" "$callback_chat_id" "$callback_data"
            if [[ "$update_id" =~ ^[0-9]+$ ]]; then
                next_offset=$((update_id + 1))
                ptm_update_config ".notify.telegram.update_offset = $next_offset" >/dev/null 2>&1 || true
            fi
        done < <(echo "$response" | jq -c '.result[]?')
    done
}

ptm_install_telegram_bot_service() {
    if ! pm_service_supported; then
        echo -e "${gl_huang}⚠ 当前系统未检测到 systemd/OpenRC，无法安装 Telegram Bot 常驻服务${gl_bai}"
        return 1
    fi
    local runner="$SCRIPT_PATH"
    [ -f "$runner" ] || runner="$SHORTCUT"
    if [ ! -f "$runner" ]; then
        echo -e "${gl_hong}未找到脚本路径，无法安装 Telegram Bot 服务${gl_bai}"
        return 1
    fi

    ptm_setup_telegram_commands || true

    cat > "$PTM_TG_BOT_SCRIPT" <<EOF
#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
exec "$runner" --ptm-telegram-bot
EOF
    chmod +x "$PTM_TG_BOT_SCRIPT"

    if pm_has_systemd; then
        mkdir -p "$(dirname "$PTM_TG_SERVICE_FILE")"
        cat > "$PTM_TG_SERVICE_FILE" <<EOF
[Unit]
Description=PTM Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PTM_TG_BOT_SCRIPT
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    fi
    pm_write_openrc_service "$PTM_TG_SERVICE" "PTM Telegram Bot" "$PTM_TG_BOT_SCRIPT"

    systemctl daemon-reload
    systemctl enable --now "$PTM_TG_SERVICE" >/dev/null 2>&1
    if systemctl is-active --quiet "$PTM_TG_SERVICE" 2>/dev/null; then
        echo -e "${gl_lv}✓ Telegram Bot 服务已启动${gl_bai}"
        return 0
    fi
    echo -e "${gl_hong}Telegram Bot 服务启动失败，请查看：systemctl status ${PTM_TG_SERVICE}${gl_bai}"
    return 1
}

ptm_remove_telegram_bot_service() {
    if pm_service_supported; then
        systemctl stop "$PTM_TG_SERVICE" 2>/dev/null || true
        systemctl disable "$PTM_TG_SERVICE" 2>/dev/null || true
        rm -f "$PTM_TG_SERVICE_FILE"
        pm_remove_openrc_service "$PTM_TG_SERVICE"
        systemctl daemon-reload 2>/dev/null || true
    fi
    rm -f "$PTM_TG_BOT_SCRIPT"
}

# ---- cron 自动化：通过主脚本非交互子命令执行，避免复制两套 PTM 通知逻辑 ----

ptm_install_cron() {
    if ! command -v crontab >/dev/null 2>&1; then
        echo -e "${gl_huang}⚠ 未安装 crontab，跳过每日自动检查/重置的定时任务${gl_bai}"
        return 0
    fi

    local runner="$SCRIPT_PATH"
    [ -f "$runner" ] || runner="$SHORTCUT"

    cat > "$PTM_DAILY_SCRIPT" <<PTMDAILYEOF
#!/bin/bash
# ptm 每日到期/配额检查 wrapper（由 proxy-manager 自动生成，请勿手动修改）
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SCRIPT_RUNNER="${runner}"
if [ -x "\$SCRIPT_RUNNER" ] || [ -f "\$SCRIPT_RUNNER" ]; then
    exec "\$SCRIPT_RUNNER" --ptm-daily-check
fi
CONFIG_FILE="${PTM_CONFIG_FILE}"
TABLE_NAME="${PTM_TABLE_NAME}"
FAMILY="${PTM_TABLE_FAMILY}"
LOG_FILE="${PTM_NOTIFICATION_LOG}"
LOCK_FILE="/tmp/proxy-manager-ptm-daily.lock"

log() { mkdir -p "\$(dirname "\$LOG_FILE")"; echo "[\$(TZ='Asia/Shanghai' date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"; }

send_email() {
    local title="\$1" html="\$2" to="\$3"
    local key from
    key=\$(jq -r '.notify.resend_api_key // ""' "\$CONFIG_FILE" 2>/dev/null)
    from=\$(jq -r '.notify.email_from // ""' "\$CONFIG_FILE" 2>/dev/null)
    [ -z "\$key" ] || [ -z "\$from" ] || [ -z "\$to" ] && return 1
    local body
    body=\$(jq -n --arg f "\$from" --arg t "\$to" --arg s "\$title" --arg h "\$html" '{from:\$f,to:\$t,subject:\$s,html:\$h}')
    curl -s --max-time 20 -X POST "https://api.resend.com/emails" -H "Authorization: Bearer \$key" -H "Content-Type: application/json" -d "\$body" | grep -q '"id"'
}

check_all() {
    [ -f "\$CONFIG_FILE" ] || return 0
    local today today_epoch admin
    today=\$(TZ='Asia/Shanghai' date +%Y-%m-%d)
    today_epoch=\$(date -d "\$today" +%s 2>/dev/null || echo 0)
    admin=\$(jq -r '.notify.admin_email // ""' "\$CONFIG_FILE" 2>/dev/null)
    for port in \$(jq -r '.ports | keys[]' "\$CONFIG_FILE" 2>/dev/null); do
        local expire user_email expire_epoch
        expire=\$(jq -r ".ports.\\"\$port\\".expiration_date // \\"\\"" "\$CONFIG_FILE")
        if [ -n "\$expire" ] && [ "\$expire" != "null" ]; then
            user_email=\$(jq -r ".ports.\\"\$port\\".email // \\"\\"" "\$CONFIG_FILE")
            expire_epoch=\$(date -d "\$expire" +%s 2>/dev/null || echo 0)
            if [ "\$expire_epoch" -gt 0 ] && [ "\$today_epoch" -gt "\$expire_epoch" ]; then
                local days=\$(( (today_epoch - expire_epoch) / 86400 ))
                if [ "\$days" -ge 3 ]; then
                    log "[自动清理] 端口 \$port 过期超3天，跳过（请通过 proxy-manager 端口流量菜单手动清理确认）"
                    continue
                fi
                log "[租期管理] 端口 \$port 已到期 (\$expire)，执行停机"
                [ -n "\$user_email" ] && [ "\$user_email" != "null" ] && send_email "【服务暂停】端口 \$port 已到期停机" "<p>端口 \$port 已到期停机</p>" "\$user_email"
                [ -n "\$admin" ] && [ "\$admin" != "null" ] && send_email "[到期封锁] 端口 \$port" "<p>端口 \$port 到期日 \$expire 已停机</p>" "\$admin"
                nft delete quota \$FAMILY \$TABLE_NAME "port_\$(echo "\$port" | tr ',-' '__')_block_quota" 2>/dev/null || true
                nft add quota \$FAMILY \$TABLE_NAME "port_\$(echo "\$port" | tr ',-' '__')_block_quota" { over 0 bytes\; } 2>/dev/null || true
                local psafe=\$(echo "\$port" | tr ',-' '__')
                nft insert rule \$FAMILY \$TABLE_NAME input tcp dport \$port quota name "port_\${psafe}_block_quota" drop 2>/dev/null || true
                nft insert rule \$FAMILY \$TABLE_NAME input udp dport \$port quota name "port_\${psafe}_block_quota" drop 2>/dev/null || true
                nft insert rule \$FAMILY \$TABLE_NAME output tcp sport \$port quota name "port_\${psafe}_block_quota" drop 2>/dev/null || true
                nft insert rule \$FAMILY \$TABLE_NAME output udp sport \$port quota name "port_\${psafe}_block_quota" drop 2>/dev/null || true
            fi
        fi
    done
}

if command -v flock >/dev/null 2>&1; then
    ( flock -n 9 || exit 0; check_all ) 9>"\$LOCK_FILE"
else
    check_all
fi
PTMDAILYEOF
    chmod +x "$PTM_DAILY_SCRIPT"

    cat > "$PTM_RESET_SCRIPT" <<PTMRESETEOF
#!/bin/bash
# ptm 每日计费周期重置 wrapper（由 proxy-manager 自动生成，请勿手动修改）
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SCRIPT_RUNNER="${runner}"
if [ -x "\$SCRIPT_RUNNER" ] || [ -f "\$SCRIPT_RUNNER" ]; then
    exec "\$SCRIPT_RUNNER" --ptm-reset-check
fi
CONFIG_FILE="${PTM_CONFIG_FILE}"
TABLE_NAME="${PTM_TABLE_NAME}"
FAMILY="${PTM_TABLE_FAMILY}"
LOG_FILE="${PTM_NOTIFICATION_LOG}"
LOCK_FILE="/tmp/proxy-manager-ptm-reset.lock"

log() { mkdir -p "\$(dirname "\$LOG_FILE")"; echo "[\$(TZ='Asia/Shanghai' date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"; }

cycle_start() {
    local reset_day=\$1
    local today_day year month cur_last cur_eff
    today_day=\$(TZ='Asia/Shanghai' date +%d | sed 's/^0//')
    year=\$(TZ='Asia/Shanghai' date +%Y)
    month=\$(TZ='Asia/Shanghai' date +%m)
    cur_last=\$(date -d "\$year-\$month-01 +1 month -1 day" +%-d 2>/dev/null || echo 28)
    cur_eff=\$reset_day
    [ "\$reset_day" -gt "\$cur_last" ] && cur_eff=\$cur_last
    if [ "\$today_day" -ge "\$cur_eff" ]; then
        printf "%s-%s-%02d" "\$year" "\$month" "\$cur_eff"
    else
        if [ "\$month" = "01" ]; then month="12"; year=\$((year - 1)); else month=\$(printf "%02d" \$((10#\$month - 1))); fi
        local prev_last=\$(date -d "\$year-\$month-01 +1 month -1 day" +%-d 2>/dev/null || echo 28)
        local prev_eff=\$reset_day
        [ "\$reset_day" -gt "\$prev_last" ] && prev_eff=\$prev_last
        printf "%s-%s-%02d" "\$year" "\$month" "\$prev_eff"
    fi
}

reset_all() {
    [ -f "\$CONFIG_FILE" ] || return 0
    local tmp="\${CONFIG_FILE}.tmp"
    for port in \$(jq -r '.ports | keys[]' "\$CONFIG_FILE" 2>/dev/null); do
        local reset_day
        reset_day=\$(jq -r ".ports.\\"\$port\\".quota.reset_day" "\$CONFIG_FILE" 2>/dev/null)
        [ "\$reset_day" = "null" ] || [ -z "\$reset_day" ] && continue
        local cur last
        cur=\$(cycle_start "\$reset_day")
        last=\$(jq -r ".ports.\\"\$port\\".quota.last_reset_cycle // \\"\\"" "\$CONFIG_FILE" 2>/dev/null)
        if [ -z "\$last" ] || [ "\$last" = "null" ]; then
            jq ".ports.\\"\$port\\".quota.last_reset_cycle = \\"\$cur\\"" "\$CONFIG_FILE" > "\$tmp" && mv "\$tmp" "\$CONFIG_FILE"
            continue
        fi
        if [ "\$last" != "\$cur" ]; then
            local psafe=\$(echo "\$port" | tr ',-' '__')
            nft reset counter \$FAMILY \$TABLE_NAME "port_\${psafe}_in" >/dev/null 2>&1 || true
            nft reset counter \$FAMILY \$TABLE_NAME "port_\${psafe}_out" >/dev/null 2>&1 || true
            nft reset quota \$FAMILY \$TABLE_NAME "port_\${psafe}_quota" >/dev/null 2>&1 || true
            jq ".ports.\\"\$port\\".quota.last_reset_cycle = \\"\$cur\\"" "\$CONFIG_FILE" > "\$tmp" && mv "\$tmp" "\$CONFIG_FILE"
            log "端口 \$port 计费周期重置完成 (周期起点: \$cur)"
        fi
    done
}

if command -v flock >/dev/null 2>&1; then
    ( flock -n 9 || exit 0; reset_all ) 9>"\$LOCK_FILE"
else
    reset_all
fi
PTMRESETEOF
    chmod +x "$PTM_RESET_SCRIPT"

    local daily_h daily_m reset_h reset_m tmp_cron
    read -r daily_h daily_m < <(snell_bj_to_local_time 00 10)
    read -r reset_h reset_m < <(snell_bj_to_local_time 00 20)
    tmp_cron=$(mktemp) || return 1
    crontab -l 2>/dev/null | grep -v "# ptm每日检查" | grep -v "# ptm每日重置" > "$tmp_cron" || true
    echo "${daily_m} ${daily_h} * * * ${PTM_DAILY_SCRIPT} >/dev/null 2>&1  # ptm每日检查" >> "$tmp_cron"
    echo "${reset_m} ${reset_h} * * * ${PTM_RESET_SCRIPT} >/dev/null 2>&1  # ptm每日重置" >> "$tmp_cron"
    crontab "$tmp_cron" 2>/dev/null && rm -f "$tmp_cron"
    echo -e "${gl_lv}✓ 已注册每日北京时间 00:10(到期/配额/通知检查) 与 00:20(计费周期重置) 定时任务${gl_bai}"
}

ptm_remove_cron() {
    if command -v crontab >/dev/null 2>&1; then
        local tmp_cron
        tmp_cron=$(mktemp) || return 1
        crontab -l 2>/dev/null | grep -v "# ptm每日检查" | grep -v "# ptm每日重置" > "$tmp_cron" || true
        crontab "$tmp_cron" 2>/dev/null && rm -f "$tmp_cron"
    fi
    rm -f "$PTM_DAILY_SCRIPT" "$PTM_RESET_SCRIPT"
}

# ---- 交互菜单 ----

# 快速开通端口（对应dog原版 quick_setup_port 完整流程：添加端口 → 设置重置日期 → 设置租期 → 设置邮箱）
# 注意：带宽限速不在此流程内，和dog原版一致——限速走独立的"端口限制设置管理"菜单
ptm_menu_add_port() {
    ptm_init_config
    ptm_check_dependencies
    echo -e "\n${BLUE}${BOLD}=== 快速开通端口 ===${NC}"
    echo "此功能将依次引导您完成: 添加端口 → 设置重置日期 → 设置租期 → 设置邮箱/TG"
    echo ""

    echo -e "\n${BLUE}${BOLD}=== 添加端口监控 ===${NC}"
    echo "格式：单端口(如 40001) / 端口段(如 8000-8100) / 端口组(如 101,102,105，将共享流量统计)"
    ptm_prompt_monitor_port
    port="$PTM_SELECTED_MONITOR_PORT"
    if [ -z "$port" ]; then echo -e "${gl_hong}端口不能为空${gl_bai}"; break_end; return; fi
    if ! [[ "$port" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+)*$ ]]; then
        echo -e "${gl_hong}端口格式不合法，只能是数字/端口段(100-200)/端口组(101,102,105)${gl_bai}"; break_end; return
    fi
    if jq -e ".ports | has(\"$port\")" "$PTM_CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${gl_hong}端口 $port 已在监控列表中${gl_bai}"; break_end; return
    fi

    echo ""
    echo "请选择统计模式:"
    echo "1. 双向流量统计（推荐）：总流量 = (入站 + 出站) × 2"
    echo "2. 仅出站统计：总流量 = 出站 × 2"
    echo "3. CN Premium 内网中转：总流量 = (入站 + 出站) × 1"
    read -e -p "请选择(回车默认1) [1-3]: " billing_choice
    local billing_mode="double"
    case "$billing_choice" in 2) billing_mode="single" ;; 3) billing_mode="premium" ;; esac

    echo ""
    local quota_input
    while true; do
        echo "请输入配额值（0为无限制）（要带单位MB/GB/T）:"
        read -e -p "流量配额(回车默认0): " quota_input
        [ -z "$quota_input" ] && quota_input="0"
        ptm_validate_quota "$quota_input" && break
        echo -e "${gl_hong}配额格式错误: $quota_input，请使用如：100MB, 1GB, 2T${gl_bai}"
    done
    local monthly_limit="unlimited"
    [ "$quota_input" != "0" ] && monthly_limit="$quota_input"

    echo ""
    read -e -p "请输入当前规则备注(可选，直接回车跳过): " remark

    local created_at
    created_at=$(ptm_beijing_time -Iseconds)
    # 用 jq -n --arg 安全构造 JSON（避免备注含引号/反斜杠等特殊字符破坏 JSON 结构）
    local port_json
    port_json=$(jq -n \
        --arg remark "$remark" --arg mode "$billing_mode" \
        --arg created "$created_at" --arg quota "$monthly_limit" \
        '{remark: $remark, billing_mode: $mode, email: "", telegram_chat_id: "", telegram_report_schedule: "inherit", created_at: $created,
          expiration_date: "",
          bandwidth_limit: {enabled: false, rate: "unlimited"},
          quota: {enabled: true, monthly_limit: $quota}}')
    ptm_update_config ".ports.\"$port\" = $port_json"
    ptm_add_nftables_rules "$port"
    [ "$monthly_limit" != "unlimited" ] && ptm_apply_quota "$port" "$monthly_limit"
    ptm_install_cron
    echo -e "${gl_lv}端口 $port 监控添加成功${gl_bai}"
    echo ""
    echo -e "${gl_lv}成功添加 1 个端口监控${gl_bai}"

    # ==================== 第二步：设置重置日期 ====================
    echo ""
    echo -e "${CYAN}>>> 按回车进入【月重置日设置】...${NC}"
    read -r _
    echo -e "\n${BLUE}${BOLD}=== 设置月重置日 ===${NC}"
    echo "为端口 $port 设置月重置日期:"
    echo "(0代表不重置，1-31 为每月重置日)"
    read -e -p "月重置日 [0-31]: " reset_day_input
    if [ -n "$reset_day_input" ] && [ "$reset_day_input" != "0" ]; then
        if [[ "$reset_day_input" =~ ^[0-9]+$ ]] && [ "$reset_day_input" -ge 1 ] && [ "$reset_day_input" -le 31 ]; then
            ptm_update_config ".ports.\"$port\".quota.reset_day = $reset_day_input"
            echo -e "${gl_lv}端口 $port 月重置日设置成功: 每月${reset_day_input}日${gl_bai}"
        else
            echo -e "${gl_hong}重置日期无效: $reset_day_input，已跳过${gl_bai}"
        fi
    else
        echo -e "${gl_huang}跳过重置日期设置${gl_bai}"
    fi

    # ==================== 第三步：设置租期 ====================
    echo ""
    echo -e "${CYAN}>>> 按回车进入【租期设置】...${NC}"
    read -r _
    echo -e "\n${BLUE}${BOLD}=== 续费/设置租期: $port ===${NC}"
    ptm_lease_prompt_and_apply "$port"

    # ==================== 第四步：设置用户邮箱 / Telegram ====================
    echo ""
    echo -e "${CYAN}>>> 按回车进入【联系方式设置】...${NC}"
    read -r _
    read -e -p "是否设置用户邮箱？[y/n] (默认n，可后续补充): " email_choice
    if [[ "$email_choice" == "y" || "$email_choice" == "Y" ]]; then
        read -e -p "请输入接收邮箱 (输入 d 可留空跳过): " new_email
        if [ "$new_email" != "d" ] && [ -n "$new_email" ]; then
            if [[ "$new_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
                ptm_update_config ".ports.\"$port\".email = \"$new_email\""
                echo -e "${gl_lv}端口 $port 邮箱已设置为: $new_email${gl_bai}"
            else
                echo -e "${gl_hong}邮箱格式错误，未保存${gl_bai}"
            fi
        fi
    fi

    echo ""
    read -e -p "是否设置用户 Telegram Chat ID？[y/n] (默认n，可后续补充): " tg_choice
    if [[ "$tg_choice" == "y" || "$tg_choice" == "Y" ]]; then
        read -e -p "请输入用户 Telegram Chat ID (输入 d 可留空跳过): " new_tg_chat
        if [ "$new_tg_chat" != "d" ] && [ -n "$new_tg_chat" ]; then
            if [[ "$new_tg_chat" =~ ^-?[0-9]+$ ]]; then
                local new_tg_json
                new_tg_json=$(ptm_json_string "$new_tg_chat")
                ptm_update_config ".ports.\"$port\".telegram_chat_id = $new_tg_json"
                echo -e "${gl_lv}端口 $port Telegram Chat ID 已设置为: $new_tg_chat${gl_bai}"
            else
                echo -e "${gl_hong}Telegram Chat ID 格式错误，未保存${gl_bai}"
            fi
        fi
    fi

    echo ""
    echo -e "${gl_lv}========================================${gl_bai}"
    echo -e "${gl_lv}       快速开通流程完成！${gl_bai}"
    echo -e "${gl_lv}========================================${gl_bai}"
    break_end
}

ptm_get_daily_total_traffic() {
    local total=0 port
    for port in $(ptm_get_active_ports 2>/dev/null); do
        total=$((total + $(ptm_get_port_monthly_usage "$port" 2>/dev/null || echo 0)))
    done
    echo "$total"
}

# 渲染端口状态表格（主菜单头部实时展示 + 独立"查看状态"菜单项共用）
ptm_render_port_table() {
    local ports
    ports=$(ptm_get_active_ports)
    if [ -z "$ports" ]; then
        echo -e "${gl_huang}暂无监控端口${gl_bai}"
        return
    fi
    printf "%-20s %-10s %-10s %-16s %-18s %s\n" "端口" "计费模式" "状态" "已用流量" "配额" "到期日"
    local port
    for port in $ports; do
        local billing_mode quota_limit expire_date status usage
        billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE")
        billing_mode=$(ptm_format_billing_mode "$billing_mode")
        quota_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE")
        expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"永久\"" "$PTM_CONFIG_FILE")
        status=$(ptm_format_running_status "$(ptm_get_port_running_status "$port")")
        usage=$(ptm_format_bytes "$(ptm_get_port_monthly_usage "$port")")
        printf "%-20s %-10s %-10s %-16s %-18s %s\n" "$port" "$billing_mode" "$status" "$usage" "$quota_limit" "$expire_date"
    done
}

ptm_menu_list_ports() {
    ptm_init_config
    ptm_render_port_table
    break_end
}

ptm_do_renew_months() {
    local port=$1 months=$2
    local current_expire today reset_day base_date
    current_expire=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$PTM_CONFIG_FILE")
    reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // 1" "$PTM_CONFIG_FILE")
    today=$(ptm_beijing_time +%Y-%m-%d)
    local today_epoch expire_epoch
    today_epoch=$(ptm_date_epoch "$today" 2>/dev/null || echo 0)
    expire_epoch=$(ptm_date_epoch "$current_expire" 2>/dev/null || echo 0)
    if [ -n "$current_expire" ] && [ "$current_expire" != "null" ] && [ "$expire_epoch" -gt "$today_epoch" ]; then
        base_date="$current_expire"
    else
        base_date="$today"
    fi
    local new_date
    new_date=$(ptm_calculate_next_expiration "$base_date" "$months" "${reset_day:-1}")
    ptm_do_set_expiration "$port" "$new_date"
}

ptm_do_set_expiration() {
    local port=$1 new_date=$2
    if [ -z "$new_date" ]; then
        echo -e "${gl_hong}日期计算失败${gl_bai}"; return 1
    fi
    if ! ptm_update_config ".ports.\"$port\".expiration_date = \"$new_date\""; then
        echo -e "${gl_hong}写入失败，请重试${gl_bai}"; return 1
    fi
    local saved_date
    saved_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$PTM_CONFIG_FILE")
    if [ "$saved_date" != "$new_date" ]; then
        echo -e "${gl_hong}验证失败：期望 $new_date，实际 $saved_date${gl_bai}"; return 1
    fi
    # 到期日延后/清除，若端口此前处于到期封锁状态需要解封
    if [ "$(ptm_get_port_running_status "$port")" = "blocked_expired" ]; then
        ptm_unblock_port "$port"
    fi
    echo -e "${gl_lv}✓ 到期日已更新: $new_date${gl_bai}"
}

# 管理端口租期：续费预设月数 / 手动输入到期日 / 清除租期(设为永久)，对应 dog 原版"管理端口租期"子菜单
# 租期管理核心动作(对应dog原版"续费/设置租期"1-6选项)，供独立菜单与"快速开通"向导共用
ptm_lease_prompt_and_apply() {
    local port="$1"
    local current_expire
    current_expire=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$PTM_CONFIG_FILE")
    [ -z "$current_expire" ] || [ "$current_expire" = "null" ] && current_expire="未设置 (永久)"
    echo -e "当前到期日: ${gl_lv}$current_expire${gl_bai}"
    echo "------------------------"
    echo "1. 增加 1 个月"
    echo "2. 增加 3 个月 (季付)"
    echo "3. 增加 6 个月 (半年)"
    echo "4. 增加 1 年"
    echo "5. 手动输入到期日期"
    echo "6. 清除租期 (设置为永久)"
    echo "0. 跳过"
    read -e -p "请选择续费时长 [0-6]: " duration_choice
    case "$duration_choice" in
        1) ptm_do_renew_months "$port" 1 ;;
        2) ptm_do_renew_months "$port" 3 ;;
        3) ptm_do_renew_months "$port" 6 ;;
        4) ptm_do_renew_months "$port" 12 ;;
        5)
            read -e -p "请输入到期日期 (格式 YYYY-MM-DD): " manual_date
            if ! ptm_date_valid "$manual_date"; then
                echo -e "${gl_hong}日期格式错误${gl_bai}"
            else
                ptm_do_set_expiration "$port" "$manual_date"
            fi
            ;;
        6)
            if ptm_update_config ".ports.\"$port\".expiration_date = \"\""; then
                [ "$(ptm_get_port_running_status "$port")" = "blocked_expired" ] && ptm_unblock_port "$port"
                echo -e "${gl_lv}✓ 已清除租期，端口恢复永久有效${gl_bai}"
            fi
            ;;
        0) echo -e "${gl_huang}跳过租期设置${gl_bai}" ;;
        *) echo -e "${gl_hong}无效选择${gl_bai}" ;;
    esac
}

# 3. 管理端口租期（对应dog原版 manage_port_expiration）
ptm_menu_manage_lease() {
    ptm_init_config
    ptm_pick_ports "请选择要管理租期的端口 [序号]: " || { echo -e "${gl_huang}未选择有效端口${gl_bai}"; break_end; return; }
    local port="${PTM_PICKED_PORTS[0]}"
    echo -e "\n${BLUE}${BOLD}=== 管理端口租期: $port ===${NC}"
    ptm_lease_prompt_and_apply "$port"
    break_end
}

# 2-1. 设置端口带宽限制（对应dog原版 set_port_bandwidth_limit：多选端口、0=无限制、单位Kbps/Mbps/Gbps）
ptm_menu_set_bandwidth() {
    ptm_init_config
    ptm_pick_ports "请选择要限制的端口（多端口用逗号,分隔） [序号]: " || { echo -e "${gl_huang}未选择有效端口${gl_bai}"; break_end; return; }
    echo ""
    echo "为端口 $(IFS=,; echo "${PTM_PICKED_PORTS[*]}") 设置带宽限制（速率控制）:"
    echo "请输入限制值（0为无限制）（要带单位Kbps/Mbps/Gbps）:"
    read -e -p "带宽限制: " limit_input
    if [ -z "$limit_input" ] || [ "$limit_input" = "0" ]; then
        local port
        for port in "${PTM_PICKED_PORTS[@]}"; do
            ptm_remove_tc_limit "$port"
            ptm_update_config ".ports.\"$port\".bandwidth_limit.enabled = false | .ports.\"$port\".bandwidth_limit.rate = \"unlimited\""
            echo -e "${gl_lv}端口 $port 带宽限制已移除${gl_bai}"
        done
        break_end
        return
    fi
    if ! ptm_validate_rate "$limit_input"; then
        echo -e "${gl_hong}格式错误，请使用如：500Kbps, 100Mbps, 1Gbps${gl_bai}"
        break_end
        return
    fi
    local tc_limit
    tc_limit=$(ptm_rate_to_tc "$limit_input")
    local success_count=0 port
    for port in "${PTM_PICKED_PORTS[@]}"; do
        ptm_remove_tc_limit "$port"
        if ! ptm_apply_tc_limit "$port" "$tc_limit"; then
            echo -e "${gl_hong}端口 $port 带宽限制设置失败${gl_bai}"
            continue
        fi
        ptm_update_config ".ports.\"$port\".bandwidth_limit.enabled = true | .ports.\"$port\".bandwidth_limit.rate = \"$limit_input\""
        echo -e "${gl_lv}端口 $port 带宽限制设置成功: $limit_input${gl_bai}"
        success_count=$((success_count + 1))
    done
    echo -e "${gl_lv}成功设置 $success_count 个端口的带宽限制${gl_bai}"
    break_end
}

# 2-2. 设置端口流量配额（对应dog原版 set_port_quota_limit：多选端口、0=无限制、单位MB/GB/TB）
ptm_menu_set_quota() {
    ptm_init_config
    ptm_pick_ports "请选择要设置配额的端口（多端口用逗号,分隔） [序号]: " || { echo -e "${gl_huang}未选择有效端口${gl_bai}"; break_end; return; }
    echo ""
    while true; do
        echo "为端口 $(IFS=,; echo "${PTM_PICKED_PORTS[*]}") 设置流量配额（总量控制）:"
        echo "请输入配额值（0为无限制）（要带单位MB/GB/T）:"
        read -e -p "流量配额(回车默认0): " quota_input
        [ -z "$quota_input" ] && quota_input="0"
        ptm_validate_quota "$quota_input" && break
        echo -e "${gl_hong}配额格式错误: $quota_input，请使用如：100MB, 1GB, 2T${gl_bai}"
    done
    local monthly_limit="unlimited"
    [ "$quota_input" != "0" ] && monthly_limit="$quota_input"
    local port
    for port in "${PTM_PICKED_PORTS[@]}"; do
        ptm_update_config ".ports.\"$port\".quota.monthly_limit = \"$monthly_limit\""
        if [ "$monthly_limit" = "unlimited" ]; then
            ptm_remove_quota "$port"
        else
            ptm_apply_quota "$port" "$monthly_limit"
        fi
        echo -e "${gl_lv}端口 $port 流量配额已更新: $monthly_limit${gl_bai}"
    done
    break_end
}

ptm_menu_set_reset_day() {
    ptm_init_config
    ptm_render_port_table
    echo ""
    read -e -p "请输入要设置重置日的端口: " port
    if ! jq -e ".ports | has(\"$port\")" "$PTM_CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${gl_hong}端口不存在${gl_bai}"; break_end; return
    fi
    read -e -p "每月流量重置日 (1-28，留空则清除自动重置设置): " reset_day_input
    if [ -z "$reset_day_input" ]; then
        ptm_update_config "del(.ports.\"$port\".quota.reset_day) | del(.ports.\"$port\".quota.last_reset_cycle)"
        echo -e "${gl_lv}✓ 已清除自动重置设置${gl_bai}"
    elif ! [[ "$reset_day_input" =~ ^[0-9]+$ ]] || [ "$reset_day_input" -lt 1 ] || [ "$reset_day_input" -gt 28 ]; then
        echo -e "${gl_hong}请输入 1-28 之间的整数${gl_bai}"
    else
        ptm_update_config ".ports.\"$port\".quota.reset_day = $reset_day_input"
        echo -e "${gl_lv}✓ 重置日已设置为每月 $reset_day_input 号${gl_bai}"
    fi
    break_end
}

ptm_menu_reset_now() {
    ptm_init_config
    read -e -p "请输入要立即重置流量的端口 (留空重置全部到期端口): " port
    if [ -z "$port" ]; then
        ptm_reset_all_due_ports
        echo -e "${gl_lv}✓ 已按计费周期重置全部到期端口${gl_bai}"
    else
        if ! jq -e ".ports | has(\"$port\")" "$PTM_CONFIG_FILE" >/dev/null 2>&1; then
            echo -e "${gl_hong}端口不存在${gl_bai}"; break_end; return
        fi
        ptm_auto_reset_port "$port"
        local reset_day
        reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // 1" "$PTM_CONFIG_FILE")
        ptm_update_config ".ports.\"$port\".quota.last_reset_cycle = \"$(ptm_get_billing_cycle_start "$reset_day")\""
        echo -e "${gl_lv}✓ 端口 $port 流量已重置${gl_bai}"
    fi
    break_end
}

# 删除端口监控（对应dog原版 remove_port_monitoring：多选+确认+清理日志与conntrack）
ptm_menu_remove_port() {
    ptm_init_config
    echo -e "\n${BLUE}${BOLD}=== 删除端口监控 ===${NC}"
    ptm_pick_ports "请选择要删除的端口（多端口用逗号,分隔） [序号]: " || { echo -e "${gl_huang}未选择有效端口${gl_bai}"; break_end; return; }

    echo ""
    echo "将删除以下端口的监控:"
    local port
    for port in "${PTM_PICKED_PORTS[@]}"; do
        echo "  端口 $port"
    done
    echo ""
    read -e -p "确认删除这些端口的监控? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "取消删除"; break_end; return
    fi

    local deleted_count=0
    for port in "${PTM_PICKED_PORTS[@]}"; do
        ptm_remove_nftables_rules "$port"
        ptm_remove_quota "$port"
        ptm_remove_tc_limit "$port"
        ptm_update_config "del(.ports.\"$port\")"

        if [ -f "$PTM_RESET_HISTORY_LOG" ]; then
            grep -v "|${port}|" "$PTM_RESET_HISTORY_LOG" > "${PTM_RESET_HISTORY_LOG}.tmp" 2>/dev/null || true
            mv "${PTM_RESET_HISTORY_LOG}.tmp" "$PTM_RESET_HISTORY_LOG" 2>/dev/null || true
        fi
        if [ -f "$PTM_NOTIFICATION_LOG" ]; then
            grep -vE "端口 ${port} " "$PTM_NOTIFICATION_LOG" > "${PTM_NOTIFICATION_LOG}.tmp" 2>/dev/null || true
            mv "${PTM_NOTIFICATION_LOG}.tmp" "$PTM_NOTIFICATION_LOG" 2>/dev/null || true
        fi

        if command -v conntrack >/dev/null 2>&1; then
            local p
            for p in $(ptm_get_group_ports "$port"); do
                conntrack -D -p tcp --dport "$p" 2>/dev/null || true
                conntrack -D -p udp --dport "$p" 2>/dev/null || true
            done
        fi

        echo -e "${gl_lv}端口 $port 监控及相关数据删除成功${gl_bai}"
        deleted_count=$((deleted_count + 1))
    done
    echo ""
    echo -e "${gl_lv}成功删除 $deleted_count 个端口监控${gl_bai}"
    break_end
}

# 合并端口为组（对应dog原版 merge_ports_to_group）
ptm_menu_merge_ports() {
    ptm_init_config
    echo -e "\n${BLUE}${BOLD}=== 合并端口为组 ===${NC}"
    echo "此功能可将多个单独的端口合并为一个端口组，实现流量共享统计。"
    echo ""
    ptm_pick_ports "请选择要合并的端口（用逗号分隔，如1,2,3） [序号]: " "single_only" || {
        echo -e "${gl_huang}需要至少2个单独端口才能合并为组${gl_bai}"; break_end; return
    }
    if [ "${#PTM_PICKED_PORTS[@]}" -lt 2 ]; then
        echo -e "${gl_hong}至少需要选择2个端口才能合并${gl_bai}"; break_end; return
    fi

    # 检查计费模式是否一致
    local first_port="${PTM_PICKED_PORTS[0]}"
    local first_billing_mode
    first_billing_mode=$(jq -r ".ports.\"$first_port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE")
    local mismatched_info="" port
    for port in "${PTM_PICKED_PORTS[@]}"; do
        local pb
        pb=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$PTM_CONFIG_FILE")
        [ "$pb" != "$first_billing_mode" ] && mismatched_info="$mismatched_info $port:$(ptm_format_billing_mode "$pb")"
    done
    if [ -n "$mismatched_info" ]; then
        echo -e "${gl_hong}❌ 无法合并：端口计费模式不同${gl_bai}"
        echo "第一个端口 $first_port 的计费模式: $(ptm_format_billing_mode "$first_billing_mode")"
        echo "计费模式不匹配的端口:$mismatched_info"
        echo "请确保所有端口使用相同的计费模式后再合并"
        break_end
        return
    fi

    local group_key
    group_key=$(IFS=','; echo "${PTM_PICKED_PORTS[*]}")

    local total_input=0 total_output=0
    for port in "${PTM_PICKED_PORTS[@]}"; do
        local traffic=($(ptm_get_port_traffic "$port"))
        total_input=$((total_input + ${traffic[0]:-0}))
        total_output=$((total_output + ${traffic[1]:-0}))
    done

    # 继承第一个端口的配置作为模板
    local quota_config bandwidth_config remark expiration_date email telegram_chat_id telegram_report_schedule
    quota_config=$(jq -c ".ports.\"$first_port\".quota // {\"enabled\":true,\"monthly_limit\":\"unlimited\"}" "$PTM_CONFIG_FILE")
    bandwidth_config=$(jq -c ".ports.\"$first_port\".bandwidth_limit // {\"enabled\":false,\"rate\":\"unlimited\"}" "$PTM_CONFIG_FILE")
    remark=$(jq -r ".ports.\"$first_port\".remark // \"\"" "$PTM_CONFIG_FILE")
    expiration_date=$(jq -r ".ports.\"$first_port\".expiration_date // \"\"" "$PTM_CONFIG_FILE")
    email=$(jq -r ".ports.\"$first_port\".email // \"\"" "$PTM_CONFIG_FILE")
    telegram_chat_id=$(jq -r ".ports.\"$first_port\".telegram_chat_id // \"\"" "$PTM_CONFIG_FILE")
    telegram_report_schedule=$(jq -r ".ports.\"$first_port\".telegram_report_schedule // \"inherit\"" "$PTM_CONFIG_FILE")

    local total_traffic
    total_traffic=$(ptm_calculate_total_traffic "$total_input" "$total_output" "$first_billing_mode")
    echo ""
    echo "将合并以下端口为组: $group_key"
    echo "合并后总流量: $(ptm_format_bytes "$total_traffic")"
    echo "将继承端口 $first_port 的配置: 计费模式、配额、带宽限制、备注、租期、邮箱、Telegram 绑定"
    read -e -p "确认合并? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "取消合并"; break_end; return
    fi

    # 先清理各成员端口的 nft/tc（config 暂不删除，等端口组配置确认写入成功后再删，避免中途失败丢配置）
    for port in "${PTM_PICKED_PORTS[@]}"; do
        ptm_remove_nftables_rules "$port" >/dev/null 2>&1
        ptm_remove_quota "$port" >/dev/null 2>&1
        ptm_remove_tc_limit "$port" >/dev/null 2>&1
    done

    local port_json
    port_json=$(jq -n \
        --arg remark "$remark" --arg mode "$first_billing_mode" \
        --arg created "$(ptm_beijing_time -Iseconds)" \
        --argjson bandwidth "$bandwidth_config" --argjson quota "$quota_config" \
        '{remark: $remark, billing_mode: $mode, email: "", telegram_chat_id: "", telegram_report_schedule: "inherit", created_at: $created,
          expiration_date: "", bandwidth_limit: $bandwidth, quota: $quota}')

    if [ -z "$port_json" ] || ! ptm_update_config ".ports.\"$group_key\" = $port_json"; then
        echo -e "${gl_hong}端口组配置写入失败，正在回滚（成员端口配置保留，恢复其监控）...${gl_bai}"
        for port in "${PTM_PICKED_PORTS[@]}"; do
            ptm_add_nftables_rules "$port" >/dev/null 2>&1
            local rb_limit
            rb_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE" 2>/dev/null)
            [ -n "$rb_limit" ] && [ "$rb_limit" != "unlimited" ] && [ "$rb_limit" != "null" ] && ptm_apply_quota "$port" "$rb_limit" >/dev/null 2>&1
        done
        break_end
        return
    fi

    # 端口组配置已写入成功，安全删除各成员端口的 config
    for port in "${PTM_PICKED_PORTS[@]}"; do
        ptm_update_config "del(.ports.\"$port\")"
    done
    [ -n "$expiration_date" ] && [ "$expiration_date" != "null" ] && ptm_update_config ".ports.\"$group_key\".expiration_date = \"$expiration_date\""
    [ -n "$email" ] && [ "$email" != "null" ] && ptm_update_config ".ports.\"$group_key\".email = \"$email\""
    if [ -n "$telegram_chat_id" ] && [ "$telegram_chat_id" != "null" ]; then
        local telegram_chat_json
        telegram_chat_json=$(ptm_json_string "$telegram_chat_id")
        ptm_update_config ".ports.\"$group_key\".telegram_chat_id = $telegram_chat_json"
    fi
    if [ -n "$telegram_report_schedule" ] && [ "$telegram_report_schedule" != "null" ]; then
        local telegram_schedule_json
        telegram_schedule_json=$(ptm_json_string "$telegram_report_schedule")
        ptm_update_config ".ports.\"$group_key\".telegram_report_schedule = $telegram_schedule_json"
    fi

    ptm_restore_counter_value "$group_key" "$total_input" "$total_output"
    ptm_add_nftables_rules "$group_key"
    local monthly_limit
    monthly_limit=$(echo "$quota_config" | jq -r '.monthly_limit // "unlimited"')
    [ "$monthly_limit" != "unlimited" ] && ptm_apply_quota "$group_key" "$monthly_limit"
    local rate_limit rate_enabled
    rate_limit=$(echo "$bandwidth_config" | jq -r '.rate // "unlimited"')
    rate_enabled=$(echo "$bandwidth_config" | jq -r '.enabled // false')
    if [ "$rate_enabled" = "true" ] && [ "$rate_limit" != "unlimited" ]; then
        ptm_apply_tc_limit "$group_key" "$(ptm_rate_to_tc "$rate_limit")"
    fi

    echo -e "${gl_lv}✓ 端口组 $group_key 合并完成${gl_bai}"
    break_end
}

ptm_menu_configure_email() {
    ptm_init_config
    echo -e "\n${BLUE}${BOLD}=== 邮件通知设置 (Resend API) ===${NC}"
    echo "未配置 Resend API Key 时，到期/配额提醒邮件会静默跳过（不影响封锁/重置等核心功能）"
    read -e -p "Resend API Key (留空不改): " api_key
    read -e -p "发件邮箱地址 (留空不改): " email_from
    read -e -p "发件人显示名称 (留空不改): " email_from_name
    read -e -p "管理员邮箱 (接收系统级通知，留空不改): " admin_email

    [ -n "$api_key" ] && ptm_update_config ".notify.resend_api_key = \"$api_key\" | .notify.enabled = true"
    [ -n "$email_from" ] && ptm_update_config ".notify.email_from = \"$email_from\""
    [ -n "$email_from_name" ] && ptm_update_config ".notify.email_from_name = \"$email_from_name\""
    [ -n "$admin_email" ] && ptm_update_config ".notify.admin_email = \"$admin_email\""
    echo -e "${gl_lv}✓ 通知设置已保存${gl_bai}"
    break_end
}

ptm_menu_configure_telegram() {
    ptm_init_config
    echo -e "\n${BLUE}${BOLD}=== Telegram Bot 通知设置 ===${NC}"
    echo "先向 @BotFather 创建 Bot 获取 Token；配置 Token 后，给 Bot 发送 /id 获取 Chat ID。"
    echo "管理员 Chat ID 用于车主命令；用户 Chat ID 可在菜单 3 绑定到端口。"
    echo ""
    local current_enabled current_schedule
    current_enabled=$(jq -r '.notify.telegram.report_enabled // .notify.telegram.daily_report_enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
    current_schedule=$(jq -r '.notify.telegram.report_schedule // "daily"' "$PTM_CONFIG_FILE" 2>/dev/null)
    read -e -p "Telegram Bot Token (留空不改): " bot_token
    read -e -p "管理员 Chat ID (留空不改): " admin_chat_id
    read -e -p "到期提前提醒天数 [0-30] (留空不改，默认3): " warning_days
    read -e -p "是否开启 Telegram 周期概览推送？[y/n] (当前: ${current_enabled}, 留空不改): " report_choice
    ptm_prompt_report_schedule "默认推送周期（车主概览 + 未单独设置的用户）" "$current_schedule" false
    local report_schedule_choice="$REPLY_VALUE"

    if [ -n "$bot_token" ]; then
        local token_json
        token_json=$(ptm_json_string "$bot_token")
        ptm_update_config ".notify.telegram.bot_token = $token_json | .notify.telegram.enabled = true"
    fi
    if [ -n "$admin_chat_id" ]; then
        if [[ "$admin_chat_id" =~ ^-?[0-9]+$ ]]; then
            local admin_json
            admin_json=$(ptm_json_string "$admin_chat_id")
            ptm_update_config ".notify.telegram.admin_chat_id = $admin_json | .notify.telegram.enabled = true"
        else
            echo -e "${gl_hong}管理员 Chat ID 格式错误，已跳过${gl_bai}"
        fi
    fi
    if [ -n "$warning_days" ]; then
        if [[ "$warning_days" =~ ^[0-9]+$ ]] && [ "$warning_days" -le 30 ]; then
            ptm_update_config ".notify.telegram.expire_warning_days = $warning_days"
        else
            echo -e "${gl_hong}提醒天数无效，需为 0-30 的整数，已跳过${gl_bai}"
        fi
    fi
    case "$report_choice" in
        y|Y) ptm_update_config ".notify.telegram.report_enabled = true | .notify.telegram.daily_report_enabled = true" ;;
        n|N) ptm_update_config ".notify.telegram.report_enabled = false | .notify.telegram.daily_report_enabled = false" ;;
    esac
    if [ -n "$report_schedule_choice" ]; then
        local schedule_json
        schedule_json=$(ptm_json_string "$report_schedule_choice")
        if [ "$report_schedule_choice" = "off" ]; then
            ptm_update_config ".notify.telegram.report_schedule = $schedule_json | .notify.telegram.report_enabled = false | .notify.telegram.daily_report_enabled = false"
        else
            ptm_update_config ".notify.telegram.report_schedule = $schedule_json"
        fi
    fi

    local saved_token
    saved_token=$(jq -r '.notify.telegram.bot_token // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    if [ -n "$saved_token" ] && [ "$saved_token" != "null" ]; then
        ptm_setup_telegram_commands || true
        ptm_install_telegram_bot_service || true
    else
        echo -e "${gl_huang}未配置 Bot Token，Telegram Bot 服务未启动${gl_bai}"
    fi
    echo -e "${gl_lv}✓ Telegram 通知设置已保存${gl_bai}"
    break_end
}

ptm_menu_bind_telegram_chat() {
    ptm_init_config
    echo -e "\n${BLUE}${BOLD}=== 绑定端口 Telegram 用户 ===${NC}"
    echo "让用户先给 Bot 发送 /id，将返回的 Chat ID 填到这里。"
    ptm_pick_ports "请选择要绑定 Telegram 的端口 [序号]: " || { echo -e "${gl_huang}未选择有效端口${gl_bai}"; break_end; return; }
    local port="${PTM_PICKED_PORTS[0]}" user_chat
    read -e -p "用户 Telegram Chat ID (输入 d 清除绑定): " user_chat
    if [ "$user_chat" = "d" ]; then
        ptm_update_config ".ports.\"$port\".telegram_chat_id = \"\" | .ports.\"$port\".telegram_report_schedule = \"inherit\""
        echo -e "${gl_lv}✓ 已清除端口 $port 的 Telegram 绑定${gl_bai}"
        break_end
        return
    fi
    if ! [[ "$user_chat" =~ ^-?[0-9]+$ ]]; then
        echo -e "${gl_hong}Chat ID 格式错误${gl_bai}"
        break_end
        return
    fi
    local chat_json
    chat_json=$(ptm_json_string "$user_chat")
    if ptm_update_config ".ports.\"$port\".telegram_chat_id = $chat_json"; then
        echo -e "${gl_lv}✓ 端口 $port 已绑定 Telegram Chat ID: $user_chat${gl_bai}"
        local current_schedule schedule_choice schedule_json
        current_schedule=$(jq -r ".ports.\"$port\".telegram_report_schedule // \"inherit\"" "$PTM_CONFIG_FILE" 2>/dev/null)
        ptm_prompt_report_schedule "该用户的概览推送周期" "$current_schedule" true
        schedule_choice="$REPLY_VALUE"
        if [ -n "$schedule_choice" ]; then
            schedule_json=$(ptm_json_string "$schedule_choice")
            ptm_update_config ".ports.\"$port\".telegram_report_schedule = $schedule_json"
        fi
        ptm_send_telegram_to_chat "$user_chat" "$(ptm_build_port_user_message "$port" "绑定成功")" || true
    else
        echo -e "${gl_hong}绑定失败，请稍后重试${gl_bai}"
    fi
    break_end
}

ptm_menu_set_user_report_schedule() {
    ptm_init_config
    echo -e "\n${BLUE}${BOLD}=== 设置用户概览推送周期 ===${NC}"
    ptm_pick_ports "请选择要设置推送周期的端口 [序号]: " || { echo -e "${gl_huang}未选择有效端口${gl_bai}"; break_end; return; }
    local port="${PTM_PICKED_PORTS[0]}" chat current schedule_choice schedule_json
    chat=$(ptm_get_telegram_chat_for_port "$port")
    if [ -z "$chat" ] || [ "$chat" = "null" ]; then
        echo -e "${gl_huang}端口 $port 尚未绑定 Telegram 用户，请先绑定 Chat ID${gl_bai}"
        break_end
        return
    fi
    current=$(jq -r ".ports.\"$port\".telegram_report_schedule // \"inherit\"" "$PTM_CONFIG_FILE" 2>/dev/null)
    ptm_prompt_report_schedule "端口 $port 用户概览推送周期" "$current" true
    schedule_choice="$REPLY_VALUE"
    if [ -z "$schedule_choice" ]; then
        echo -e "${gl_huang}未修改${gl_bai}"
        break_end
        return
    fi
    schedule_json=$(ptm_json_string "$schedule_choice")
    ptm_update_config ".ports.\"$port\".telegram_report_schedule = $schedule_json"
    echo -e "${gl_lv}✓ 端口 $port 用户推送周期已设置为: $(ptm_report_schedule_label "$schedule_choice")${gl_bai}"
    break_end
}

ptm_menu_test_telegram() {
    ptm_init_config
    local target_chat
    target_chat=$(jq -r '.notify.telegram.admin_chat_id // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
    if [ -z "$target_chat" ] || [ "$target_chat" = "null" ]; then
        read -e -p "请输入接收测试消息的 Chat ID: " target_chat
    fi
    if [ -z "$target_chat" ]; then
        echo -e "${gl_hong}Chat ID 不能为空${gl_bai}"
        break_end
        return
    fi
    if ptm_send_telegram_to_chat "$target_chat" "测试通知
Telegram Bot 通知已连通。
发送 /help 可查看可用命令。"; then
        echo -e "${gl_lv}✓ Telegram 测试通知发送成功${gl_bai}"
    else
        echo -e "${gl_hong}Telegram 测试通知发送失败，请检查 Bot Token、Chat ID 和网络${gl_bai}"
    fi
    break_end
}

ptm_menu_configure_notify() {
    ptm_init_config
    while true; do
        clear
        echo -e "\n${BLUE}${BOLD}=== 通知管理 ===${NC}"
        local email_enabled tg_enabled tg_admin tg_report tg_schedule tg_service
        email_enabled=$(jq -r '.notify.enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
        tg_enabled=$(jq -r '.notify.telegram.enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
        tg_admin=$(jq -r '.notify.telegram.admin_chat_id // ""' "$PTM_CONFIG_FILE" 2>/dev/null)
        tg_report=$(jq -r '.notify.telegram.report_enabled // .notify.telegram.daily_report_enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
        tg_schedule=$(jq -r '.notify.telegram.report_schedule // "daily"' "$PTM_CONFIG_FILE" 2>/dev/null)
        if pm_service_supported && systemctl is-active --quiet "$PTM_TG_SERVICE" 2>/dev/null; then
            tg_service="运行中"
        else
            tg_service="未运行"
        fi
        echo "邮箱通知：$email_enabled"
        echo "Telegram：$tg_enabled | 管理员: ${tg_admin:-未设置} | 概览推送: $tg_report/$(ptm_report_schedule_label "$tg_schedule") | 服务: $tg_service"
        echo ""
        echo -e "  ${GREEN}1.${NC} 邮件通知设置"
        echo -e "  ${GREEN}2.${NC} Telegram Bot 设置"
        echo -e "  ${GREEN}3.${NC} 绑定端口 Telegram 用户"
        echo -e "  ${GREEN}4.${NC} 设置用户概览推送周期"
        echo -e "  ${GREEN}5.${NC} 发送 Telegram 测试通知"
        echo -e "  ${GREEN}6.${NC} 启动/重启 Telegram Bot 服务"
        echo -e "  ${GREEN}7.${NC} 停止 Telegram Bot 服务"
        echo -e "  ${GREEN}0.${NC} 返回"
        local choice
        read -e -p "$(echo -e "${CYAN}请选择 [0-7]: ${NC}")" choice
        case "$choice" in
            1) ptm_menu_configure_email ;;
            2) ptm_menu_configure_telegram ;;
            3) ptm_menu_bind_telegram_chat ;;
            4) ptm_menu_set_user_report_schedule ;;
            5) ptm_menu_test_telegram ;;
            6) ptm_install_telegram_bot_service; break_end ;;
            7) ptm_remove_telegram_bot_service; echo -e "${gl_lv}✓ Telegram Bot 服务已停止${gl_bai}"; break_end ;;
            0) return ;;
            *) err "无效选项。"; sleep 1 ;;
        esac
    done
}

ptm_menu_diagnose() {
    ptm_init_config
    echo -e "\n${BLUE}${BOLD}=== 配置诊断 ===${NC}"
    local ports
    ports=$(ptm_get_active_ports)
    if [ -z "$ports" ]; then
        echo -e "${gl_huang}暂无监控端口${gl_bai}"; break_end; return
    fi
    local port
    for port in $ports; do
        echo -n "端口 $port: "
        local ok=true
        if ! ptm_is_port_rules_exist "$port"; then
            echo -n "❌流量规则缺失 "
            ok=false
        fi
        local quota_limit
        quota_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$PTM_CONFIG_FILE")
        if [ "$quota_limit" != "unlimited" ]; then
            local port_safe
            port_safe=$(ptm_safe_name "$port")
            if ! nft list quota $PTM_TABLE_FAMILY $PTM_TABLE_NAME "port_${port_safe}_quota" &>/dev/null; then
                echo -n "❌配额对象缺失 "
                ok=false
            fi
        fi
        local email
        email=$(jq -r ".ports.\"$port\".email // \"\"" "$PTM_CONFIG_FILE")
        [ -z "$email" ] || [ "$email" = "null" ] && echo -n "⚠️未配置客户邮箱 "
        local tg_chat
        tg_chat=$(ptm_get_telegram_chat_for_port "$port")
        [ -z "$tg_chat" ] || [ "$tg_chat" = "null" ] && echo -n "⚠️未绑定TG "
        [ "$ok" = true ] && echo -n "✅正常"
        echo ""
    done
    echo ""
    if crontab -l 2>/dev/null | grep -q "# ptm每日检查"; then
        echo -e "${gl_lv}✅ 每日检查定时任务已注册${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ 每日检查定时任务未注册（新增一个端口即可自动注册）${gl_bai}"
    fi
    if crontab -l 2>/dev/null | grep -q "# ptm每日重置"; then
        echo -e "${gl_lv}✅ 每日重置定时任务已注册${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ 每日重置定时任务未注册（新增一个端口即可自动注册）${gl_bai}"
    fi
    local notify_enabled
    notify_enabled=$(jq -r '.notify.enabled // false' "$PTM_CONFIG_FILE")
    if [ "$notify_enabled" = "true" ]; then
        echo -e "${gl_lv}✅ 邮件通知已配置${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ 邮件通知未配置（菜单 4 可配置，不配置则仅静默跳过通知）${gl_bai}"
    fi
    local tg_enabled
    tg_enabled=$(jq -r '.notify.telegram.enabled // false' "$PTM_CONFIG_FILE" 2>/dev/null)
    if [ "$tg_enabled" = "true" ]; then
        echo -e "${gl_lv}✅ Telegram 通知已配置${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ Telegram 通知未配置（菜单 4 可配置）${gl_bai}"
    fi
    if pm_service_supported && systemctl is-active --quiet "$PTM_TG_SERVICE" 2>/dev/null; then
        echo -e "${gl_lv}✅ Telegram Bot 服务运行中${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ Telegram Bot 服务未运行${gl_bai}"
    fi
    break_end
}

uninstall_ptm() {
    if [[ "$1" != "quiet" ]]; then
        if [[ ! -d "$PTM_CONFIG_DIR" ]] && ! nft list table $PTM_TABLE_FAMILY $PTM_TABLE_NAME >/dev/null 2>&1; then
            warn "端口流量计费管理未安装。"
            return 0
        fi
        confirm "确认卸载端口流量计费管理? 这会删除所有端口监控、nftables 规则、tc 限速、定时任务及 ${PTM_CONFIG_DIR} 配置目录。" "n" || return 0
    fi

    local port
    for port in $(ptm_get_active_ports 2>/dev/null); do
        ptm_remove_nftables_rules "$port"
        ptm_remove_quota "$port"
        ptm_remove_tc_limit "$port"
    done
    nft delete table $PTM_TABLE_FAMILY $PTM_TABLE_NAME 2>/dev/null || true
    ptm_remove_cron
    ptm_remove_telegram_bot_service
    rm -f "$PTM_CONFIG_LOCK_FILE" /tmp/proxy-manager-ptm-daily.lock /tmp/proxy-manager-ptm-reset.lock
    rm -rf "$PTM_CONFIG_DIR"
    [[ "$1" == "quiet" ]] || ok "已完全卸载端口流量计费管理。"
}

# 1. 添加/删除端口监控（对应 dog 原版 manage_port_monitoring）
ptm_menu_port_monitoring() {
    while true; do
        clear
        echo -e "\n${BLUE}${BOLD}=== 端口监控管理 ===${NC}"
        echo -e "  ${GREEN}1.${NC} 快速开通端口"
        echo -e "  ${GREEN}2.${NC} 删除端口监控"
        echo -e "  ${GREEN}3.${NC} 合并端口为组"
        echo -e "  ${GREEN}0.${NC} 返回"
        local choice
        read -e -p "$(echo -e "${CYAN}请选择 [0-3]: ${NC}")" choice
        case "$choice" in
            1) ptm_menu_add_port ;;
            2) ptm_menu_remove_port ;;
            3) ptm_menu_merge_ports ;;
            0) return ;;
            *) err "无效选项。"; sleep 1 ;;
        esac
    done
}

# 2. 端口限制设置管理（对应 dog 原版 manage_traffic_limits）
ptm_menu_limits() {
    while true; do
        clear
        echo -e "\n${BLUE}${BOLD}=== 端口限制设置管理 ===${NC}"
        echo -e "  ${GREEN}1.${NC} 设置端口带宽限制（速率控制）"
        echo -e "  ${GREEN}2.${NC} 设置端口流量配额（总量控制）"
        echo -e "  ${GREEN}3.${NC} 管理端口租期（自动到期停机）"
        echo -e "  ${GREEN}0.${NC} 返回"
        local choice
        read -e -p "$(echo -e "${CYAN}请选择 [0-3]: ${NC}")" choice
        case "$choice" in
            1) ptm_menu_set_bandwidth ;;
            2) ptm_menu_set_quota ;;
            3) ptm_menu_manage_lease ;;
            0) return ;;
            *) err "无效选项。"; sleep 1 ;;
        esac
    done
}

# 3. 流量重置管理（对应 dog 原版 manage_traffic_reset）
ptm_menu_reset_mgmt() {
    while true; do
        clear
        echo -e "\n${BLUE}${BOLD}=== 流量重置管理 ===${NC}"
        echo -e "  ${GREEN}1.${NC} 重置流量月重置日设置"
        echo -e "  ${GREEN}2.${NC} 立即重置"
        echo -e "  ${GREEN}0.${NC} 返回"
        local choice
        read -e -p "$(echo -e "${CYAN}请选择 [0-2]: ${NC}")" choice
        case "$choice" in
            1) ptm_menu_set_reset_day ;;
            2) ptm_menu_reset_now ;;
            0) return ;;
            *) err "无效选项。"; sleep 1 ;;
        esac
    done
}

# 主菜单：结构对应 dog 原版 show_main_menu（银行1添加/删除、2限制设置、3重置管理、
# 4通知管理、5配置检测），去掉了 dog 原版里超出本次移植范围的
# "4.一键导出/导入配置"(GitHub备份) 与 "7.扩展工具"(与流量计费无关的个人工具)
ptm_menu() {
    ptm_init_config
    while true; do
        clear
        local port_count daily_total
        port_count=$(ptm_get_active_ports 2>/dev/null | grep -c .)
        daily_total=$(ptm_format_bytes "$(ptm_get_daily_total_traffic)")
        echo -e "\n${BLUE}${BOLD}=== 端口流量计费与到期管理 ===${NC}"
        echo -e " ${DIM}监控端口: ${port_count} 个 | 端口总流量: ${daily_total}${NC}"
        echo
        ptm_render_port_table
        echo
        echo -e "${YELLOW}${BOLD}╭─ 管理操作${NC}"
        echo -e "  ${GREEN}1.${NC} 添加/删除端口监控"
        echo -e "  ${GREEN}2.${NC} 端口限制设置管理"
        echo -e "  ${GREEN}3.${NC} 流量重置管理"
        echo -e "  ${GREEN}4.${NC} 通知管理"
        echo -e "  ${GREEN}5.${NC} 配置诊断"
        echo -e "  ${GREEN}0.${NC} 返回主菜单"
        hr
        local choice
        read -e -p "$(echo -e "${CYAN}请选择 [0-5]: ${NC}")" choice
        case $choice in
            1) ptm_menu_port_monitoring ;;
            2) ptm_menu_limits ;;
            3) ptm_menu_reset_mgmt ;;
            4) ptm_menu_configure_notify ;;
            5) ptm_menu_diagnose ;;
            0) return ;;
            *) err "无效选项。"; sleep 1 ;;
        esac
    done
}

# ===========================================================================
#  十四、状态面板 / 主菜单
# ===========================================================================
show_status() {
    echo -e "${CYAN}╭──────────────────── 服务状态 ────────────────────╮${NC}"
    if sb_installed; then
        if sb_running; then echo -e "${CYAN}│${NC} sing-box : ${GREEN}● 运行中${NC}  $(sb_version)"
        else echo -e "${CYAN}│${NC} sing-box : ${RED}● 已停止${NC}  $(sb_version)"; fi
    else echo -e "${CYAN}│${NC} sing-box : ${YELLOW}○ 未安装${NC}"; fi
    if xray_installed; then
        if xray_running; then echo -e "${CYAN}│${NC} Xray     : ${GREEN}● 运行中${NC}  $(xray_version)"
        else echo -e "${CYAN}│${NC} Xray     : ${RED}● 已停止${NC}  $(xray_version)"; fi
    else echo -e "${CYAN}│${NC} Xray     : ${YELLOW}○ 未安装${NC}"; fi
    if snell_installed; then
        local snell_ver=""; snell_load_state && snell_ver=" v${SNELL_VERSION}"
        if snell_running; then echo -e "${CYAN}│${NC} Snell    : ${GREEN}● 运行中${NC}${snell_ver}"
        else echo -e "${CYAN}│${NC} Snell    : ${RED}● 已停止${NC}${snell_ver}"; fi
    fi
    if [[ -f "$STATE" ]]; then
        local snell_ports stls_ports mieru_ports wg_peers
        snell_ports="$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-managed") | .key | sub("^snell-"; "")' "$STATE" 2>/dev/null | paste -sd, -)"
        [[ -n "$snell_ports" ]] && echo -e "${CYAN}│${NC} Snell节点: ${GREEN}● 已配置${NC}  ${snell_ports}"
        stls_ports="$(jq -r '.nodes | to_entries[] | select(.value.core == "snell-shadowtls") | .key | sub("^snell-shadowtls-"; "")' "$STATE" 2>/dev/null | paste -sd, -)"
        [[ -n "$stls_ports" ]] && echo -e "${CYAN}│${NC} Snell+STLS: ${GREEN}● 已配置${NC}  ${stls_ports}"
        mieru_ports="$(jq -r '.nodes | to_entries[] | select(.value.core == "mieru-managed") | .key | sub("^mieru-"; "")' "$STATE" 2>/dev/null | paste -sd, -)"
        [[ -n "$mieru_ports" ]] && echo -e "${CYAN}│${NC} Mieru节点: ${GREEN}● 已配置${NC}  ${mieru_ports}"
        wg_peers="$(jq -r '[.nodes | to_entries[] | select(.value.core == "wireguard-managed")] | length' "$STATE" 2>/dev/null)"
        [[ -n "$wg_peers" && "$wg_peers" != "0" ]] && echo -e "${CYAN}│${NC} WG Peers : ${GREEN}● 已配置${NC}  ${wg_peers}"
    fi
    if mieru_installed; then
        local mieru_ver; mieru_ver="$(mieru_version)"
        if mieru_running; then echo -e "${CYAN}│${NC} Mieru    : ${GREEN}● 运行中${NC}  ${mieru_ver}"
        else echo -e "${CYAN}│${NC} Mieru    : ${RED}● 已停止${NC}  ${mieru_ver}"; fi
    fi
    if wg_installed; then
        local wg_ver; wg_ver="$(wg_version)"
        if wg_running; then echo -e "${CYAN}│${NC} WireGuard: ${GREEN}● 运行中${NC}  ${wg_ver}"
        else echo -e "${CYAN}│${NC} WireGuard: ${RED}● 已停止${NC}  ${wg_ver}"; fi
    fi
    echo -e "${CYAN}│${NC} 节点数量 : ${GREEN}$(node_count)${NC}"
    echo -e "${CYAN}╰──────────────────────────────────────────────────╯${NC}"
}

show_menu() {
    clear 2>/dev/null || true
    echo -e "${MAGENTA}${BOLD}╭──────────────────────────────────────────────────╮${NC}"
    echo -e "${MAGENTA}${BOLD}│              Proxy Node Manager                  │${NC}"
    echo -e "${MAGENTA}${BOLD}│          Sing-box / Xray 多协议节点管理          │${NC}"
    echo -e "${MAGENTA}${BOLD}╰──────────────────────────────────────────────────╯${NC}"
    echo -e " ${DIM}v${SCRIPT_VERSION} | ${OS_ID:-?}/${ARCH} | 快捷命令: pm${NC}"
    echo
    show_status
    echo
    echo -e "${BLUE}${BOLD}╭─ 安装协议${NC}"
    echo -e "  ${GREEN}1.${NC} VLESS 协议"
    echo -e "  ${GREEN}2.${NC} FinalMask 抗审查"
    echo -e "  ${GREEN}3.${NC} VMess 协议"
    echo -e "  ${GREEN}4.${NC} Trojan 协议"
    echo -e "  ${GREEN}5.${NC} Shadowsocks"
    echo -e "  ${GREEN}6.${NC} SOCKS5 / HTTP"
    echo -e "  ${GREEN}7.${NC} Hysteria2"
    echo -e "  ${GREEN}8.${NC} TUIC v5"
    echo -e "  ${GREEN}9.${NC} AnyTLS"
    echo -e " ${GREEN}10.${NC} ShadowTLS v3"
    echo -e " ${GREEN}11.${NC} NaïveProxy"
    echo -e " ${GREEN}12.${NC} Snell"
    echo -e " ${GREEN}13.${NC} Mieru"
    echo -e " ${GREEN}14.${NC} WireGuard"
    echo -e "${YELLOW}${BOLD}╰─ 节点与系统管理${NC}"
    echo -e " ${GREEN}15.${NC} 查看全部节点"
    echo -e " ${GREEN}16.${NC} 编辑节点配置"
    echo -e " ${GREEN}17.${NC} 删除指定节点"
    echo -e " ${GREEN}18.${NC} 端口流量计费与到期管理"
    echo -e " ${GREEN}19.${NC} 内核与服务管理"
    echo -e " ${GREEN}20.${NC} 更新脚本"
    echo -e " ${RED}21.${NC} 卸载"
    echo -e "  ${GREEN}0.${NC} 退出"
    hr
}

main_loop() {
    while true; do
        show_menu
        read -rp "$(echo -e "${CYAN}请输入选项 [0-21]: ${NC}")" choice
        echo
        case "$choice" in
            1)  vless_menu ;;
            2)  finalmask_menu ;;
            3)  vmess_menu ;;
            4)  trojan_menu ;;
            5)  shadowsocks_menu ;;
            6)  proxy_menu ;;
            7)  add_hysteria2 ;;
            8)  add_tuic ;;
            9)  add_anytls ;;
            10) add_shadowtls ;;
            11) add_naive ;;
            12) install_snell ;;
            13) install_mieru ;;
            14) install_wireguard ;;
            15) view_all_nodes ;;
            16) edit_node_menu ;;
            17) manage_nodes ;;
            18) ptm_menu ;;
            19) core_manage_menu ;;
            20) script_update_menu ;;
            21) uninstall_menu ;;
            0)  ok "感谢使用, 再见!"; exit 0 ;;
            *)  err "无效选项, 请输入 0-21。" ;;
        esac
        pause
    done
}

# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
main() {
    case "${1:-}" in
        --ptm-daily-check)
            check_root
            ptm_init_config
            ptm_restore_monitoring_if_needed
            ptm_check_all_expiration
            ptm_check_all_quota
            ptm_send_daily_telegram_reports
            exit 0
            ;;
        --ptm-reset-check)
            check_root
            ptm_init_config
            ptm_reset_all_due_ports
            exit 0
            ;;
        --ptm-telegram-bot)
            check_root
            ptm_telegram_bot_loop
            exit 0
            ;;
    esac

    check_root
    detect_system
    [[ -n "$PKG" ]] || warn "未识别到受支持的包管理器 apt/dnf/yum/apk, 依赖需手动安装。"
    check_dependencies
    init_state
    prompt_auto_update_setting
    auto_update_on_pm_start "$@"
    install_shortcut
    main_loop
}

main "$@"
