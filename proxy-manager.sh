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

# ---------------------------------------------------------------------------
# 二、全局常量
# ---------------------------------------------------------------------------
SCRIPT_VERSION="1.6.5"
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

# Reality 伪装域名候选 (需真实可达、支持 TLS1.3)
REALITY_SNIS=(
    "www.microsoft.com" "www.apple.com" "www.amazon.com"
    "www.cloudflare.com" "dl.google.com" "www.icloud.com"
    "addons.mozilla.org" "www.tesla.com" "www.samsung.com"
)

PUBLIC_IPV4=""; PUBLIC_IPV6=""

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
ask_port() {
    local prompt="${1:-监听端口}" p
    while true; do
        read -rp "$(echo -e "${CYAN}${prompt}, 回车随机 10000-60000: ${NC}")" p
        if [[ -z "$p" ]]; then
            p="$(random_port)"; while port_used "$p"; do p="$(random_port)"; done
            ok "  已随机分配端口: $p"
        fi
        if ! [[ "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then err "  端口无效, 请输入 1-65535。"; continue; fi
        if port_used "$p"; then err "  端口 $p 已被占用, 请换一个。"; continue; fi
        REPLY_PORT="$p"; return 0
    done
}

REPLY_SNI=""
ask_sni() {
    local s
    read -rp "$(echo -e "${CYAN}Reality 伪装域名 SNI, 回车随机: ${NC}")" s
    [[ -z "$s" ]] && s="${REALITY_SNIS[$((RANDOM % ${#REALITY_SNIS[@]}))]}"
    REPLY_SNI="$s"; ok "  使用伪装域名: $REPLY_SNI"
}

ask_tls_sni() {
    local s
    read -rp "$(echo -e "${CYAN}TLS SNI, 回车默认 www.bing.com: ${NC}")" s
    REPLY_SNI="${s:-www.bing.com}"
    ok "  使用 TLS SNI: $REPLY_SNI"
}

REPLY_NAME=""
ask_name() {
    local def="$1" n
    read -rp "$(echo -e "${CYAN}节点备注名, 回车默认 ${def}: ${NC}")" n
    REPLY_NAME="${n:-$def}"
}

REPLY_VALUE=""
ask_value_default() {
    local prompt="$1" def="$2" v
    read -rp "$(echo -e "${CYAN}${prompt}, 回车自动生成 [${def}]: ${NC}")" v
    REPLY_VALUE="${v:-$def}"
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
    read -rp "$(echo -e "${CYAN}${prompt}, 回车自动生成 [${def}]: ${NC}")" v
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

# save_node <core> <tag> <type> <name> <link> <detail> [extra_tag]
save_node() {
    LAST_NODE_TYPE="$3"
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
    read -rp "$(echo -e "${CYAN}Reality PrivateKey, 回车自动生成: ${NC}")" priv
    if [[ -z "$priv" ]]; then
        gen_xray_reality_keys || return 1
        ok "  Reality key 已自动生成。"
        return 0
    fi
    read -rp "$(echo -e "${CYAN}Reality PublicKey, 手动 PrivateKey 时必填: ${NC}")" pub
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
    read -rp "$(echo -e "${CYAN}VLESS decryption, 回车自动生成: ${NC}")" dec
    if [[ -z "$dec" ]]; then
        gen_xray_vless_enc || return 1
        ok "  VLESS 加密参数已自动生成。"
        return 0
    fi
    read -rp "$(echo -e "${CYAN}VLESS encryption, 手动 decryption 时必填: ${NC}")" enc
    [[ -z "$enc" ]] && { err "手动 VLESS decryption 时必须填写 encryption。"; return 1; }
    XRAY_VLESS_DEC="$dec"; XRAY_VLESS_ENC="$enc"
}

# ---------------------------------------------------------------------------
# 八、结果展示
# ---------------------------------------------------------------------------
show_result() {
    local name="$1" link="$2" detail="$3"
    echo; hr; ok "  ✅ ${name} 部署成功!"; hr
    echo -e "${BOLD}分享链接:${NC}"; echo -e "${GREEN}${link}${NC}"; echo
    if [[ -n "$detail" ]]; then echo -e "${BOLD}手动参数:${NC}"; echo -e "${detail}"; echo; fi
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${BOLD}二维码, 客户端扫码导入:${NC}"; qrencode -t ANSIUTF8 "$link"
    else
        warn "未安装 qrencode, 跳过二维码。"
    fi
    local cy; cy="$(clash_node_yaml "${LAST_NODE_TYPE:-}" "$name" "$link")"
    if [[ -n "$cy" ]]; then
        echo; echo -e "${BOLD}Clash / Mihomo 配置:${NC}"
        echo -e "${GREEN}proxies:"
        echo -e "${cy}${NC}"
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

# --- VMess-(TCP/mKCP/QUIC) ----------------------------------------------
add_vmess_plain() {
    local transport="$1"
    require_xray || return 1
    local label default_name tag_prefix stream net vm_type transport_desc
    case "$transport" in
        tcp)
            label="VMess-TCP"; default_name="VMess-TCP"; tag_prefix="vmess-tcp"; net="tcp"; vm_type="none"
            stream='{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}'
            transport_desc="TCP"
            ;;
        kcp)
            label="VMess-mKCP"; default_name="VMess-mKCP"; tag_prefix="vmess-kcp"; net="kcp"; vm_type="none"
            stream='{"network":"kcp","security":"none","kcpSettings":{"header":{"type":"none"}}}'
            transport_desc="mKCP UDP, header: none"
            ;;
        quic)
            label="VMess-QUIC"; default_name="VMess-QUIC"; tag_prefix="vmess-quic"; net="quic"; vm_type="none"
            stream='{"network":"quic","security":"none","quicSettings":{"security":"none","key":"","header":{"type":"none"}}}'
            transport_desc="QUIC UDP, security/header: none"
            ;;
        *) err "未知 VMess 传输: $transport"; return 1 ;;
    esac

    echo -e "\n${MAGENTA}${BOLD}${label}${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "${default_name}-${port}"; local name="$REPLY_NAME"
    local uuid host tag inbound vmjson link detail
    ask_uuid_value "UUID"; uuid="$REPLY_UUID"; host="$(server_host)"; tag="${tag_prefix}-${port}"
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
    local c; read -rp "$(echo -e "${CYAN}请选择 [1-3, 默认2]: ${NC}")" c
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
    local c; read -rp "$(echo -e "${CYAN}请选择 [1-3, 默认2]: ${NC}")" c
    case "$c" in
        1) REPLY_METHOD="2022-blake3-aes-128-gcm" ;;
        3) REPLY_METHOD="2022-blake3-chacha20-poly1305" ;;
        *) REPLY_METHOD="2022-blake3-aes-256-gcm" ;;
    esac
}

add_shadowsocks() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}Shadowsocks${NC} 经典 AEAD"
    ask_port "监听端口"; local port="$REPLY_PORT"
    choose_ss_method; local method="$REPLY_METHOD"
    ask_name "SS-${port}"; local name="$REPLY_NAME"
    ask_secret_value "Shadowsocks 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS" tag; tag="ss-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg m "$method" --arg pw "$pw" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"shadowsocks",
        settings:{ method:$m, password:$pw, network:"tcp,udp" } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="ss://$(b64_urlsafe "${method}:${pw}")@${host}:${port}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  加密: ${method}\n  密码: ${pw}\n  类型: Shadowsocks"
    save_node "xray" "$tag" "Shadowsocks" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

add_ss2022() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}Shadowsocks 2022${NC}"
    ensure_time_sync || return 1
    ask_port "监听端口"; local port="$REPLY_PORT"
    choose_ss2022_method; local method="$REPLY_METHOD"
    ask_name "SS2022-${port}"; local name="$REPLY_NAME"
    ask_ss2022_psk "$method"; local pw="$REPLY_PASS" tag; tag="ss2022-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg m "$method" --arg pw "$pw" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"shadowsocks",
        settings:{ method:$m, password:$pw, network:"tcp,udp" } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="ss://$(b64_urlsafe "${method}:${pw}")@${host}:${port}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  加密: ${method}\n  密码: ${pw}"
    save_node "xray" "$tag" "SS2022" "$name" "$link" "$detail"
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
    ask_name "Hysteria2-${port}"; local name="$REPLY_NAME"
    ask_secret_value "Hysteria2 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS"; local tag="hysteria2-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$pw" --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
        type:"hysteria2", tag:$tag, listen:"::", listen_port:$port,
        users:[{password:$pw}],
        tls:{ enabled:true, alpn:["h3"], certificate_path:$cert, key_path:$key } }')"
    core_add_inbounds "singbox" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="hysteria2://${pw}@${host}:${port}?insecure=1&sni=www.bing.com#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port} UDP\n  密码: ${pw}\n  SNI : www.bing.com\n  证书: 自签名, 客户端需开启允许不安全"
    save_node "singbox" "$tag" "Hysteria2" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- TUIC v5 --------------------------------------------------------------
add_tuic() {
    require_singbox || return 1; ensure_cert
    echo -e "\n${MAGENTA}${BOLD}TUIC v5${NC} 基于 QUIC"
    ask_port "监听端口 UDP"; local port="$REPLY_PORT"
    ask_name "TUIC-${port}"; local name="$REPLY_NAME"
    ask_uuid_value "TUIC UUID"; local uuid="$REPLY_UUID"
    ask_secret_value "TUIC 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS"; local tag="tuic-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg uuid "$uuid" --arg pw "$pw" --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
        type:"tuic", tag:$tag, listen:"::", listen_port:$port,
        users:[{uuid:$uuid, password:$pw}], congestion_control:"bbr",
        tls:{ enabled:true, alpn:["h3"], certificate_path:$cert, key_path:$key } }')"
    core_add_inbounds "singbox" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="tuic://${uuid}:${pw}@${host}:${port}?congestion_control=bbr&alpn=h3&sni=www.bing.com&allow_insecure=1#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port} UDP\n  UUID: ${uuid}\n  密码: ${pw}\n  拥塞控制: bbr  ALPN: h3\n  证书: 自签名, 客户端需允许不安全"
    save_node "singbox" "$tag" "TUIC" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- AnyTLS ---------------------------------------------------------------
add_anytls() {
    require_singbox || return 1; ensure_cert
    echo -e "\n${MAGENTA}${BOLD}AnyTLS${NC} 新型抗指纹协议, 需 sing-box 1.12+ 客户端"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "AnyTLS-${port}"; local name="$REPLY_NAME"
    ask_secret_value "AnyTLS 密码" "$(gen_pass 16)"; local pw="$REPLY_PASS"; local tag="anytls-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg pw "$pw" --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
        type:"anytls", tag:$tag, listen:"::", listen_port:$port,
        users:[{password:$pw}],
        tls:{ enabled:true, certificate_path:$cert, key_path:$key } }')"
    core_add_inbounds "singbox" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="anytls://${pw}@${host}:${port}?insecure=1&sni=www.bing.com#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  密码: ${pw}\n  SNI : www.bing.com\n  证书: 自签名, 客户端需允许不安全"
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
    method="2022-blake3-aes-128-gcm"; ask_ss2022_psk "$method"; ss_pw="$REPLY_PASS"
    inner_port="$(random_port)"; while port_used "$inner_port" || [[ "$inner_port" == "$port" ]]; do inner_port="$(random_port)"; done
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
    local detail="  地址: ${host}\n  端口: ${port}\n  ── ShadowTLS ──\n  版本: 3\n  ShadowTLS 密码: ${stls_pw}\n  握手域名 SNI: ${sni}\n  ── 内层 Shadowsocks ──\n  加密: ${method}\n  SS 密码: ${ss_pw}\n  提示: 该协议多数客户端需手动填写以上参数。"
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
    ask_name "Naive-${port}"; local name="$REPLY_NAME"
    ask_username_value "NaïveProxy 用户名" "naive$(openssl rand -hex 3)"; local user="$REPLY_USER"
    ask_secret_value "NaïveProxy 密码" "$(gen_pass 12)"; local pass="$REPLY_PASS"
    local tag="naive-${port}"

    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg u "$user" --arg p "$pass" \
        --arg cert "$SB_CERT" --arg key "$SB_KEY" '{
        type:"naive", tag:$tag, listen:"::", listen_port:$port,
        users:[{username:$u, password:$p}],
        tls:{ enabled:true, server_name:"www.bing.com", certificate_path:$cert, key_path:$key } }')"
    core_add_inbounds "singbox" "$inbound" || return 1

    local host; host="$(server_host)"
    local link="naive+https://${user}:${pass}@${host}:${port}?insecure=1#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  用户名: ${user}\n  密码: ${pass}\n  证书: 自签名, 建议配真实域名证书, 自签需客户端允许不安全"
    save_node "singbox" "$tag" "NaïveProxy" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# ===========================================================================
#  十一、Snell (独立内核, v4/v5)
# ===========================================================================
snell_installed() { [[ -x "$SNELL_BIN" ]]; }
snell_running()   { systemctl is-active --quiet "$SNELL_SERVICE" 2>/dev/null; }

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

snell_mihomo_yaml() {
    local name="$1" host="$2" port="$3" psk="$4" ver="$5"
    [[ "$ver" =~ ^[0-9]+$ ]] || ver=4
    printf '  - name: "%s"\n    type: snell\n    server: "%s"\n    port: %s\n    psk: "%s"\n    version: %s\n    tfo: true\n' \
        "$name" "$host" "$port" "$psk" "$ver"
    (( ver >= 3 )) && printf '    udp: true\n'
    (( ver >= 4 )) && printf '    reuse: true\n'
}

install_snell_version() {
    local major="$1" ver="$2"
    echo -e "\n${MAGENTA}${BOLD}Snell v${major}${NC} Surge 官方协议"
    if snell_installed; then
        confirm "已安装 Snell, 继续会覆盖当前 Snell 服务与配置, 是否继续?" "n" || return 0
        systemctl stop "$SNELL_SERVICE" 2>/dev/null
    fi
    local url tmp
    url="https://dl.nssurge.com/snell/snell-server-${ver}-linux-${SNELL_ARCH}.zip"
    command -v unzip >/dev/null 2>&1 || pkg_install unzip
    ask_port "Snell 监听端口"; local port="$REPLY_PORT"
    ask_secret_value "Snell PSK" "$(gen_pass 16)"; local psk="$REPLY_PASS"
    info "下载 Snell ${ver} (${SNELL_ARCH})..."
    tmp="$(mktemp -d)"
    curl -fL --max-time 60 "$url" -o "$tmp/snell.zip" || { err "下载失败: $url"; rm -rf "$tmp"; return 1; }
    unzip -oq "$tmp/snell.zip" -d "$tmp" || { err "解压失败。"; rm -rf "$tmp"; return 1; }
    install -m 755 "$tmp/snell-server" "$SNELL_BIN" || { err "安装失败。"; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
    mkdir -p "$(dirname "$SNELL_CONF")" "$STATE_DIR"
    cat > "$SNELL_CONF" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
EOF
    cat > "$SNELL_SERVICE_FILE" <<EOF
[Unit]
Description=Snell Proxy Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${SNELL_BIN} -c ${SNELL_CONF}
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SNELL_SERVICE" >/dev/null 2>&1
    systemctl restart "$SNELL_SERVICE"; sleep 1
    if ! snell_running; then err "Snell 启动失败:"; journalctl -u "$SNELL_SERVICE" -n 10 --no-pager | sed 's/^/    /'; return 1; fi

    cat > "$SNELL_STATE" <<EOF
SNELL_VERSION='${major}'
SNELL_PORT=${port}
SNELL_PSK='${psk}'
EOF
    chmod 600 "$SNELL_STATE"

    local host; host="$(server_host)"
    local surge="Snell-${port} = snell, ${host}, ${port}, psk=${psk}, version=${major}, reuse=true, tfo=true"
    echo; hr; ok "  ✅ Snell v${major} 部署成功!"; hr
    echo -e "${BOLD}Surge 节点配置行:${NC}"; echo -e "${GREEN}${surge}${NC}"; echo
    echo -e "${BOLD}Mihomo 配置:${NC}"
    echo -e "${GREEN}proxies:"
    snell_mihomo_yaml "Snell-v${major}-${port}" "$host" "$port" "$psk" "$major"
    echo -e "${NC}"
    echo -e "${BOLD}手动参数:${NC}"
    echo -e "  地址: ${host}\n  端口: ${port}\n  PSK : ${psk}\n  版本: ${major}"
    hr
}

install_snell_v4() { install_snell_version "4" "v4.1.1"; }
install_snell_v5() { install_snell_version "5" "v5.0.1"; }

install_snell() {
    echo -e "\n${YELLOW}${BOLD}=== Snell ===${NC}"
    echo -e "  ${GREEN}1.${NC} Snell v4"
    echo -e "  ${GREEN}2.${NC} Snell v5 ${DIM}(默认)${NC}"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择 [默认2]: ${NC}")" c
    case "$c" in
        1) install_snell_v4 ;;
        0) return 0 ;;
        2|"") install_snell_v5 ;;
        *) err "无效选项。" ;;
    esac
}

snell_show_link() {
    snell_load_state || { warn "未找到 Snell 配置。"; return 0; }
    local host; host="$(server_host)"
    local surge="Snell-${SNELL_PORT} = snell, ${host}, ${SNELL_PORT}, psk=${SNELL_PSK}, version=${SNELL_VERSION}, reuse=true, tfo=true"
    echo -e "${BOLD}[Snell v${SNELL_VERSION}]${NC} ${SNELL_PORT}"
    echo -e "${GREEN}${surge}${NC}"
    echo
    echo -e "${BOLD}Mihomo 配置:${NC}"
    echo -e "${GREEN}proxies:"
    snell_mihomo_yaml "Snell-v${SNELL_VERSION}-${SNELL_PORT}" "$host" "$SNELL_PORT" "$SNELL_PSK" "$SNELL_VERSION"
    echo -e "${NC}"
}

uninstall_snell() {
    snell_installed || { warn "Snell 未安装。"; return 0; }
    [[ "$1" == "quiet" ]] || confirm "确认卸载 Snell?" "n" || return 0
    systemctl stop "$SNELL_SERVICE" 2>/dev/null; systemctl disable "$SNELL_SERVICE" 2>/dev/null
    rm -f "$SNELL_SERVICE_FILE" "$SNELL_BIN" "$SNELL_STATE"; rm -rf "$(dirname "$SNELL_CONF")"
    systemctl daemon-reload; ok "Snell 已卸载。"
}

# ===========================================================================
#  十一之二、Mieru / mita (独立内核, enfein/mieru)
# ===========================================================================
mita_bin() { command -v mita 2>/dev/null || { [[ -x /usr/bin/mita ]] && echo /usr/bin/mita; }; }
mieru_installed() { [[ -n "$(mita_bin)" ]]; }
mieru_running()   { systemctl is-active --quiet "$MITA_SERVICE" 2>/dev/null; }

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

install_mieru() {
    echo -e "\n${BLUE}${BOLD}Mieru${NC} 高抗审查底层协议"
    local march deb_arch rpm_arch
    case "$ARCH" in
        amd64) march="amd64"; deb_arch="amd64"; rpm_arch="x86_64" ;;
        arm64) march="arm64"; deb_arch="arm64"; rpm_arch="aarch64" ;;
        *) err "Mieru 仅支持 amd64 / arm64 架构, 当前: ${ARCH}。"; return 1 ;;
    esac

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

    # 选择传输协议
    echo -e "${CYAN}请选择传输协议:${NC}"
    echo -e "  ${GREEN}1.${NC} TCP 推荐   ${GREEN}2.${NC} UDP   ${GREEN}3.${NC} TCP+UDP 双协议"
    local pc; read -rp "$(echo -e "${CYAN}选择 [1-3, 默认1]: ${NC}")" pc
    local proto
    case "$pc" in 2) proto="UDP" ;; 3) proto="BOTH" ;; *) proto="TCP" ;; esac

    ask_port "监听端口"; local port="$REPLY_PORT"
    # 双协议: UDP 使用 port+1, 需确保 port+1 空闲
    if [[ "$proto" == "BOTH" ]]; then
        if port_used "$((port+1))"; then err "双协议需要 端口+1 (${port}→$((port+1))) 空闲, 请换一个端口。"; return 1; fi
    fi
    ask_username_value "Mieru 用户名" "mieru$(openssl rand -hex 3)"; local user="$REPLY_USER"
    ask_secret_value "Mieru 密码" "$(gen_pass 12)"; local pass="$REPLY_PASS"

    # 生成服务端配置
    local cfg bindings; cfg="$(mktemp)"
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
  "mtu": 1400
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

    # 保存状态
    mkdir -p "$STATE_DIR"
    cat > "$MIERU_STATE" <<EOF
MIERU_USER='${user}'
MIERU_PASS='${pass}'
MIERU_PORT=${port}
MIERU_PROTO='${proto}'
EOF
    chmod 600 "$MIERU_STATE"

    echo; hr; ok "  ✅ Mieru (mita) 部署成功!"; hr
    mieru_show_link
}

# 读取状态并输出 mierus:// 链接 + 二维码
mieru_show_link() {
    [[ -f "$MIERU_STATE" ]] || { warn "未找到 Mieru 配置。"; return 0; }
    # shellcheck disable=SC1090
    source "$MIERU_STATE"
    local host; host="$(server_host)"
    local eu ep; eu="$(url_encode "$MIERU_USER")"; ep="$(url_encode "$MIERU_PASS")"
    echo -e "${BOLD}用户: ${NC}${MIERU_USER}   ${BOLD}密码: ${NC}${MIERU_PASS}   ${BOLD}协议: ${NC}${MIERU_PROTO}"
    local -a plist=()
    case "$MIERU_PROTO" in
        TCP)  plist=("TCP:${MIERU_PORT}") ;;
        UDP)  plist=("UDP:${MIERU_PORT}") ;;
        BOTH) plist=("TCP:${MIERU_PORT}" "UDP:$((MIERU_PORT+1))") ;;
    esac
    local item pr po link
    for item in "${plist[@]}"; do
        pr="${item%%:*}"; po="${item##*:}"
        link="mierus://${eu}:${ep}@${host}:${po}?handshake-mode=HANDSHAKE_STANDARD&mtu=1400&multiplexing=MULTIPLEXING_LOW&port=${po}&profile=default&protocol=${pr}"
        echo; echo -e "${BOLD}[${pr}] 分享链接:${NC}"; echo -e "${GREEN}${link}${NC}"
        command -v qrencode >/dev/null 2>&1 && qrencode -t ANSIUTF8 "$link"
    done
    echo -e "${DIM}提示: mierus:// 为客户端分享链接; 请在 mieru 客户端 / Clash Verge 等导入, 勿在服务器执行 apply。${NC}"
    echo; echo -e "${BOLD}Clash / Mihomo 配置:${NC}"
    echo -e "${GREEN}proxies:"
    for item in "${plist[@]}"; do
        pr="${item%%:*}"; po="${item##*:}"
        local mname="Mieru"; [[ "$MIERU_PROTO" == "BOTH" ]] && mname="Mieru-${pr}"
        printf '  - name: "%s"\n    type: mieru\n    server: %s\n    port: %s\n    transport: %s\n    username: "%s"\n    password: "%s"\n    multiplexing: MULTIPLEXING_LOW\n' "$mname" "$host" "$po" "$pr" "$MIERU_USER" "$MIERU_PASS"
    done
    echo -e "${NC}"
    hr
}

uninstall_mieru() {
    mieru_installed || { warn "Mieru 未安装。"; return 0; }
    [[ "$1" == "quiet" ]] || confirm "确认卸载 Mieru?" "n" || return 0
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

install_wireguard() {
    echo -e "\n${BLUE}${BOLD}WireGuard${NC} 现代轻量 VPN"
    if ! command -v wg >/dev/null 2>&1; then
        info "安装 wireguard-tools..."
        pkg_install wireguard-tools || pkg_install wireguard || { err "wireguard-tools 安装失败, 请手动安装。"; return 1; }
    fi
    command -v wg >/dev/null 2>&1 || { err "未找到 wg 命令。"; return 1; }
    if [[ -f "$WG_CONF" ]]; then
        confirm "已存在 WireGuard 配置, 覆盖重建?" "n" || return 0
        systemctl stop "wg-quick@${WG_IFACE}" 2>/dev/null
    fi

    ask_port "监听端口 UDP"; local port="$REPLY_PORT"
    local iface; iface="$(default_iface)"; [[ -n "$iface" ]] || iface="eth0"

    local s_priv s_pub c_priv c_pub
    ask_wg_private_key "WireGuard 服务端私钥"; s_priv="$REPLY_WG_PRIV"; s_pub="$REPLY_WG_PUB"
    ask_wg_private_key "WireGuard 客户端私钥"; c_priv="$REPLY_WG_PRIV"; c_pub="$REPLY_WG_PUB"
    local s_addr="10.66.66.1" c_addr="10.66.66.2"

    mkdir -p "$WG_DIR"; umask 077
    cat > "$WG_CONF" <<EOF
[Interface]
Address = ${s_addr}/24
ListenPort = ${port}
PrivateKey = ${s_priv}
PostUp = iptables -A FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${iface} -j MASQUERADE

[Peer]
PublicKey = ${c_pub}
AllowedIPs = ${c_addr}/32
EOF
    chmod 600 "$WG_CONF"

    # 开启转发
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1

    systemctl enable --now "wg-quick@${WG_IFACE}" >/dev/null 2>&1
    sleep 1
    if ! wg_running; then err "WireGuard 启动失败:"; journalctl -u "wg-quick@${WG_IFACE}" -n 10 --no-pager 2>/dev/null | sed 's/^/    /'; return 1; fi

    mkdir -p "$STATE_DIR"
    cat > "$WG_STATE" <<EOF
WG_SERVER_PUB='${s_pub}'
WG_CLIENT_PRIV='${c_priv}'
WG_CLIENT_ADDR='${c_addr}'
WG_PORT=${port}
EOF
    chmod 600 "$WG_STATE"

    echo; hr; ok "  ✅ WireGuard 部署成功!"; hr
    wg_show_link
}

# 输出 WireGuard 客户端配置 + 二维码
wg_show_link() {
    [[ -f "$WG_STATE" ]] || { warn "未找到 WireGuard 配置。"; return 0; }
    # shellcheck disable=SC1090
    source "$WG_STATE"
    local host; host="$(server_host)"
    local conf
    conf="$(cat <<EOF
[Interface]
PrivateKey = ${WG_CLIENT_PRIV}
Address = ${WG_CLIENT_ADDR}/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${WG_SERVER_PUB}
Endpoint = ${host}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
)"
    echo -e "${BOLD}客户端配置, 保存为 wg-client.conf 或用 App 扫码:${NC}"
    echo -e "${GREEN}${conf}${NC}"
    echo
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${BOLD}二维码, WireGuard App 扫码导入:${NC}"
        printf '%s' "$conf" | qrencode -t ANSIUTF8
    fi
    echo; echo -e "${BOLD}Clash / Mihomo 配置:${NC}"
    echo -e "${GREEN}proxies:"
    printf '  - name: "WireGuard"\n    type: wireguard\n    server: %s\n    port: %s\n    ip: %s\n    private-key: %s\n    public-key: %s\n    udp: true\n' "$host" "$WG_PORT" "$WG_CLIENT_ADDR" "$WG_CLIENT_PRIV" "$WG_SERVER_PUB"
    echo -e "${NC}"
    hr
}

uninstall_wireguard() {
    wg_installed || { warn "WireGuard 未安装/未配置。"; return 0; }
    [[ "$1" == "quiet" ]] || confirm "确认卸载 WireGuard?" "n" || return 0
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
    if mieru_installed; then
        echo; hr; echo -e "${BOLD}[Mieru]${NC}"; mieru_show_link
    fi
    if wg_installed; then
        echo; hr; echo -e "${BOLD}[WireGuard]${NC}"; wg_show_link
    fi
}

manage_nodes() {
    if [[ "$(node_count)" == "0" ]]; then warn "当前没有可管理的节点。"; return 0; fi
    local -a tags=() names=() cores=() types=() t
    while IFS= read -r t; do
        [[ -z "$t" ]] && continue
        tags+=("$t")
        names+=("$(jq -r --arg t "$t" '.nodes[$t].name' "$STATE")")
        cores+=("$(jq -r --arg t "$t" '.nodes[$t].core' "$STATE")")
        types+=("$(jq -r --arg t "$t" '.nodes[$t].type' "$STATE")")
    done <<< "$(jq -r '.nodes | keys[]' "$STATE")"

    echo -e "\n${BOLD}已部署节点:${NC}"
    local i
    for i in "${!tags[@]}"; do
        printf "  ${GREEN}%2d.${NC} [%s] %s\n" "$((i+1))" "${types[$i]}" "${names[$i]}"
    done
    echo -e "  ${GREEN} 0.${NC} 返回"
    local choice
    read -rp "$(echo -e "${CYAN}选择要删除的节点编号: ${NC}")" choice
    [[ "$choice" == "0" || -z "$choice" ]] && return 0
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#tags[@]} )); then err "无效编号。"; return 1; fi
    local tag="${tags[$((choice-1))]}"
    confirm "确认删除节点 [${names[$((choice-1))]}]?" "n" || return 0
    delete_node "$tag"
}

delete_node() {
    local tag="$1" core extra cfg bin tmp
    core="$(jq -r --arg t "$tag" '.nodes[$t].core // "singbox"' "$STATE")"
    extra="$(jq -r --arg t "$tag" '.nodes[$t].extra_tag // empty' "$STATE")"
    if [[ "$core" == "xray" ]]; then cfg="$XRAY_CONFIG"; else cfg="$SB_CONFIG"; fi

    tmp="$(mktemp_json)" || { err "创建临时配置文件失败。"; return 1; }
    if [[ -n "$extra" ]]; then
        jq --arg t "$tag" --arg e "$extra" '.inbounds |= map(select(.tag != $t and .tag != $e))' "$cfg" > "$tmp"
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
            printf '  - name: "%s"\n    type: hysteria2\n    server: %s\n    port: %s\n    password: "%s"\n    sni: www.bing.com\n    skip-cert-verify: true\n    alpn:\n      - h3\n' \
                "$name" "$CL_HOST" "$CL_PORT" "$pw"
            ;;
        TUIC)
            clash_hostport "$link"
            local ui="${link#tuic://}"; ui="${ui%%@*}"
            printf '  - name: "%s"\n    type: tuic\n    server: %s\n    port: %s\n    uuid: %s\n    password: "%s"\n    sni: www.bing.com\n    skip-cert-verify: true\n    udp-relay-mode: native\n    congestion-controller: bbr\n    alpn:\n      - h3\n' \
                "$name" "$CL_HOST" "$CL_PORT" "${ui%%:*}" "${ui#*:}"
            ;;
        AnyTLS)
            clash_hostport "$link"
            local pw="${link#anytls://}"; pw="${pw%%@*}"
            printf '  - name: "%s"\n    type: anytls\n    server: %s\n    port: %s\n    password: "%s"\n    sni: www.bing.com\n    skip-cert-verify: true\n    client-fingerprint: chrome\n    udp: true\n' \
                "$name" "$CL_HOST" "$CL_PORT" "$pw"
            ;;
        *) return ;;  # ShadowTLS / NaïveProxy 等 Mihomo 不便直接导出
    esac
}

# ---- 编辑节点配置 ----
node_get_port() {
    local tag="$1" core="$2"
    if [[ "$core" == "xray" ]]; then
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
    mieru_installed && specials+=("mieru")
    wg_installed && specials+=("wireguard")
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
            confirm "Mieru 为独立服务, 将重新应用配置覆盖当前节点, 是否继续?" "n" && install_mieru
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
    echo -e "  ${RED}6.${NC} 全部卸载"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) uninstall_core_singbox ;;
        2) uninstall_core_xray ;;
        3) uninstall_snell ;;
        4) uninstall_mieru ;;
        5) uninstall_wireguard ;;
        6) uninstall_all ;;
        *) return 0 ;;
    esac
}

uninstall_all() {
    confirm "确认全部卸载并清理脚本环境? 这会删除本脚本创建的服务、配置、状态与 pm 快捷命令。" "n" || return 0
    local had_wg_state=""
    [[ -f "$WG_STATE" || -f "$WG_CONF" ]] && had_wg_state="1"

    uninstall_core_singbox quiet
    uninstall_core_xray quiet
    uninstall_snell quiet
    uninstall_mieru quiet
    uninstall_wireguard quiet

    systemctl stop "$SB_SERVICE" "$XRAY_SERVICE" "$SNELL_SERVICE" "$MITA_SERVICE" "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
    systemctl disable "$SB_SERVICE" "$XRAY_SERVICE" "$SNELL_SERVICE" "$MITA_SERVICE" "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
    rm -f "$SB_SERVICE_FILE" "$XRAY_SERVICE_FILE" "$SNELL_SERVICE_FILE" "$MITA_SERVICE_FILE"
    rm -f "$SB_BIN" "$XRAY_BIN" "$SNELL_BIN" /usr/local/bin/mita /usr/bin/mita
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

restart_all() {
    sb_installed && restart_singbox
    xray_installed && restart_xray
    { sb_installed || xray_installed; } || warn "尚未安装任何内核。"
}

core_manage_menu() {
    echo -e "\n${YELLOW}${BOLD}=== 内核与服务管理 ===${NC}"
    echo -e "  ${GREEN}1.${NC} 安装 / 更新 Xray 内核"
    echo -e "  ${GREEN}2.${NC} 安装 / 更新 sing-box 内核"
    echo -e "  ${GREEN}3.${NC} 重启所有服务"
    echo -e "  ${GREEN}0.${NC} 返回"
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
    if mieru_installed; then
        if mieru_running; then echo -e "${CYAN}│${NC} Mieru    : ${GREEN}● 运行中${NC}"
        else echo -e "${CYAN}│${NC} Mieru    : ${RED}● 已停止${NC}"; fi
    fi
    if wg_installed; then
        if wg_running; then echo -e "${CYAN}│${NC} WireGuard: ${GREEN}● 运行中${NC}"
        else echo -e "${CYAN}│${NC} WireGuard: ${RED}● 已停止${NC}"; fi
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
    echo -e "${BLUE}${BOLD}╭─ VLESS 协议${NC}"
    echo -e "  ${GREEN}1.${NC} VLESS-Reality-Vision"
    echo -e "  ${GREEN}2.${NC} VLESS-XHTTP-Reality"
    echo -e "  ${GREEN}3.${NC} VLESS-gRPC-Reality"
    echo -e "  ${GREEN}4.${NC} VLESS-Encryption"
    echo -e "  ${GREEN}5.${NC} VLESS-Encryption-XHTTP"
    echo -e "  ${GREEN}6.${NC} VLESS-WS-TLS"
    echo -e "  ${GREEN}7.${NC} VLESS-gRPC-TLS"
    echo -e "  ${GREEN}8.${NC} VLESS-H2-TLS"
    echo -e "  ${GREEN}9.${NC} VLESS-XHTTP-TLS"
    echo -e "${BLUE}${BOLD}├─ FinalMask 抗审查${NC}"
    echo -e " ${GREEN}10.${NC} VLESS-Encryption-XHTTP-FinalMask"
    echo -e " ${GREEN}11.${NC} VLESS-Encryption-FinalMask sudoku"
    echo -e " ${GREEN}12.${NC} FullStack REALITY+XHTTP+FinalMask"
    echo -e "${MAGENTA}${BOLD}├─ VMess 协议${NC}"
    echo -e " ${GREEN}13.${NC} VMess-TCP"
    echo -e " ${GREEN}14.${NC} VMess-mKCP"
    echo -e " ${GREEN}15.${NC} VMess-QUIC"
    echo -e " ${GREEN}16.${NC} VMess-WebSocket"
    echo -e " ${GREEN}17.${NC} VMess-WS-TLS"
    echo -e " ${GREEN}18.${NC} VMess-gRPC-TLS"
    echo -e " ${GREEN}19.${NC} VMess-H2-TLS"
    echo -e "${MAGENTA}${BOLD}├─ Trojan 协议${NC}"
    echo -e " ${GREEN}20.${NC} Trojan-Reality"
    echo -e " ${GREEN}21.${NC} Trojan-TCP-TLS"
    echo -e " ${GREEN}22.${NC} Trojan-WS-TLS"
    echo -e " ${GREEN}23.${NC} Trojan-gRPC-TLS"
    echo -e " ${GREEN}24.${NC} Trojan-H2-TLS"
    echo -e "${MAGENTA}${BOLD}├─ Shadowsocks / SOCKS / HTTP${NC}"
    echo -e " ${GREEN}25.${NC} Shadowsocks"
    echo -e " ${GREEN}26.${NC} SOCKS5"
    echo -e " ${GREEN}27.${NC} HTTP Proxy"
    echo -e "${MAGENTA}${BOLD}├─ QUIC / 抗审查${NC}"
    echo -e " ${GREEN}28.${NC} Hysteria2"
    echo -e " ${GREEN}29.${NC} TUIC v5"
    echo -e " ${GREEN}30.${NC} AnyTLS"
    echo -e " ${GREEN}31.${NC} ShadowTLS v3"
    echo -e " ${GREEN}32.${NC} NaïveProxy"
    echo -e "${BLUE}${BOLD}├─ 独立协议${NC}"
    echo -e " ${GREEN}33.${NC} Snell"
    echo -e " ${GREEN}34.${NC} Mieru"
    echo -e " ${GREEN}35.${NC} WireGuard"
    echo -e "${YELLOW}${BOLD}╰─ 节点与系统管理${NC}"
    echo -e " ${GREEN}36.${NC} 查看全部节点"
    echo -e " ${GREEN}37.${NC} 编辑节点配置"
    echo -e " ${GREEN}38.${NC} 删除指定节点"
    echo -e " ${GREEN}39.${NC} 内核与服务管理"
    echo -e " ${RED}40.${NC} 卸载"
    echo -e "  ${GREEN}0.${NC} 退出"
    hr
}

main_loop() {
    while true; do
        show_menu
        read -rp "$(echo -e "${CYAN}请输入选项 [0-40]: ${NC}")" choice
        echo
        case "$choice" in
            1)  add_xray_vision_reality ;;
            2)  add_xray_xhttp_reality ;;
            3)  add_vless_grpc_reality ;;
            4)  add_xray_vless_encryption ;;
            5)  add_vless_encryption_xhttp ;;
            6)  add_vless_tls ws ;;
            7)  add_vless_tls grpc ;;
            8)  add_vless_tls h2 ;;
            9)  add_vless_tls xhttp ;;
            10) add_vless_enc_xhttp_finalmask ;;
            11) add_vless_enc_finalmask ;;
            12) add_vless_fullstack ;;
            13) add_vmess_plain tcp ;;
            14) add_vmess_plain kcp ;;
            15) add_vmess_plain quic ;;
            16) add_vmess_ws ;;
            17) add_vmess_tls ws ;;
            18) add_vmess_tls grpc ;;
            19) add_vmess_tls h2 ;;
            20) add_trojan_reality ;;
            21) add_trojan_tls tcp ;;
            22) add_trojan_tls ws ;;
            23) add_trojan_tls grpc ;;
            24) add_trojan_tls h2 ;;
            25) shadowsocks_menu ;;
            26) add_socks ;;
            27) add_http_proxy ;;
            28) add_hysteria2 ;;
            29) add_tuic ;;
            30) add_anytls ;;
            31) add_shadowtls ;;
            32) add_naive ;;
            33) install_snell ;;
            34) install_mieru ;;
            35) install_wireguard ;;
            36) view_all_nodes ;;
            37) edit_node_menu ;;
            38) manage_nodes ;;
            39) core_manage_menu ;;
            40) uninstall_menu ;;
            0)  ok "感谢使用, 再见!"; exit 0 ;;
            *)  err "无效选项, 请输入 0-40。" ;;
        esac
        pause
    done
}

# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
main() {
    check_root
    detect_system
    [[ -n "$PKG" ]] || warn "未识别到受支持的包管理器 apt/dnf/yum/apk, 依赖需手动安装。"
    check_dependencies
    init_state
    install_shortcut
    main_loop
}

main "$@"
