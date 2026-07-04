#!/usr/bin/env bash
# =============================================================================
#  Proxy Node Manager  (Sing-box + Xray 双内核)
#  多协议一键部署 / 节点生成 / 分享链接 + 二维码
#
#  支持协议:
#  支持协议:
#    VLESS: Reality-Vision / XHTTP-Reality / gRPC-Reality / Encryption / Encryption-XHTTP
#    FinalMask(官方 Xray v26.3.27+): Enc-XHTTP-FinalMask / Enc-FinalMask-sudoku / FullStack
#    其他: VMess-WS / Trojan-Reality / Shadowsocks-2022 / SOCKS5 /
#          Hysteria2 / TUIC v5 / AnyTLS / ShadowTLS v3 / NaïveProxy /
#          Snell v4 / Mieru / WireGuard
#  内核: VLESS/VMess/Trojan/SS/SOCKS/FinalMask 走 Xray; QUIC 系走 sing-box; Snell/Mieru/WireGuard 独立
# =============================================================================

set -o pipefail

# ---------------------------------------------------------------------------
# 一、颜色与输出辅助
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[0;33m'
    BLUE='\033[0;34m';   CYAN='\033[0;36m';   MAGENTA='\033[0;35m'
    BOLD='\033[1m';      DIM='\033[2m';        NC='\033[0m'
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
SCRIPT_VERSION="1.4.0"
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

gen_b64()  { openssl rand -base64 "${1:-16}" | tr -d '\n'; }
gen_pass() { openssl rand -hex "${1:-16}" | tr -d '\n'; }
gen_short_id() { openssl rand -hex 8; }

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

b64_line() { printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 | tr -d '\n'; }

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

REPLY_NAME=""
ask_name() {
    local def="$1" n
    read -rp "$(echo -e "${CYAN}节点备注名, 回车默认 ${def}: ${NC}")" n
    REPLY_NAME="${n:-$def}"
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
    tmp="$(mktemp)"
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

# VLESS Encryption: 生成 decryption(服务端)/encryption(客户端), 取 X25519 组
XRAY_VLESS_DEC=""; XRAY_VLESS_ENC=""
gen_xray_vless_enc() {
    local out; out="$("$XRAY_BIN" vlessenc 2>/dev/null)"
    XRAY_VLESS_DEC="$(echo "$out" | grep -m1 '"decryption"' | sed -E 's/.*"decryption": *"([^"]+)".*/\1/')"
    XRAY_VLESS_ENC="$(echo "$out" | grep -m1 '"encryption"' | sed -E 's/.*"encryption": *"([^"]+)".*/\1/')"
    [[ -n "$XRAY_VLESS_DEC" && -n "$XRAY_VLESS_ENC" ]]
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
    local uuid sid path; uuid="$(gen_uuid)"; sid="$(gen_short_id)"; path="/$(openssl rand -hex 4)"
    gen_xray_reality_keys || { err "Xray Reality 密钥生成失败。"; return 1; }
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
    local uuid sid; uuid="$(gen_uuid)"; sid="$(gen_short_id)"
    gen_xray_reality_keys || { err "Xray Reality 密钥生成失败。"; return 1; }
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
    local uuid; uuid="$(gen_uuid)"
    # 生成 decryption(服务端)/encryption(客户端), 取 X25519 组
    local out dec enc
    out="$("$XRAY_BIN" vlessenc 2>/dev/null)"
    dec="$(echo "$out" | grep -m1 '"decryption"' | sed -E 's/.*"decryption": *"([^"]+)".*/\1/')"
    enc="$(echo "$out" | grep -m1 '"encryption"' | sed -E 's/.*"encryption": *"([^"]+)".*/\1/')"
    if [[ -z "$dec" || -z "$enc" ]]; then
        err "生成 VLESS 加密参数失败, 请确认 Xray 版本 >= v25.9.5 (菜单可更新 Xray)。"; return 1
    fi
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
    local uuid sid svc; uuid="$(gen_uuid)"; sid="$(gen_short_id)"; svc="grpc$(openssl rand -hex 3)"
    gen_xray_reality_keys || { err "Reality 密钥生成失败。"; return 1; }
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
    local uuid path; uuid="$(gen_uuid)"; path="/$(openssl rand -hex 4)"
    gen_xray_vless_enc || { err "VLESS 加密参数生成失败, 请确认 Xray >= v25.9.5。"; return 1; }
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

# --- VLESS-Encryption-XHTTP-FinalMask (官方 Xray v26.3.27+ finalmask) ---
add_vless_enc_xhttp_finalmask() {
    require_xray || return 1
    echo -e "\n${BLUE}${BOLD}VLESS-Encryption-XHTTP-FinalMask${NC} 需 Xray v26.3.27+ 客户端"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "ENC-XHTTP-FM-${port}"; local name="$REPLY_NAME"
    local uuid path; uuid="$(gen_uuid)"; path="/$(openssl rand -hex 4)"
    gen_xray_vless_enc || { err "VLESS 加密参数生成失败, 需 Xray >= v25.9.5。"; return 1; }
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
    local uuid; uuid="$(gen_uuid)"
    gen_xray_vless_enc || { err "VLESS 加密参数生成失败, 需 Xray >= v25.9.5。"; return 1; }
    local spw; spw="$(gen_pass 16)"
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
    local uuid path sid; uuid="$(gen_uuid)"; path="/$(openssl rand -hex 4)"; sid="$(gen_short_id)"
    gen_xray_vless_enc || { err "VLESS 加密参数生成失败, 需 Xray >= v25.9.5。"; return 1; }
    gen_xray_reality_keys || { err "Reality 密钥生成失败。"; return 1; }
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
    local uuid path; uuid="$(gen_uuid)"; path="/$(openssl rand -hex 4)"
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

# --- Trojan-Reality ---
add_trojan_reality() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}Trojan-Reality${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_sni;             local sni="$REPLY_SNI"
    ask_name "Trojan-Reality-${port}"; local name="$REPLY_NAME"
    local pw sid; pw="$(gen_pass 16)"; sid="$(gen_short_id)"
    gen_xray_reality_keys || { err "Reality 密钥生成失败。"; return 1; }
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

# --- Shadowsocks 2022 ---
add_ss2022() {
    require_xray || return 1
    echo -e "\n${MAGENTA}${BOLD}Shadowsocks 2022${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "SS2022-${port}"; local name="$REPLY_NAME"
    local method="2022-blake3-aes-128-gcm" pw tag
    pw="$(gen_b64 16)"; tag="ss2022-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg m "$method" --arg pw "$pw" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"shadowsocks",
        settings:{ method:$m, password:$pw, network:"tcp,udp" } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="ss://$(b64_line "${method}:${pw}")@${host}:${port}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  加密: ${method}\n  密码: ${pw}"
    save_node "xray" "$tag" "SS2022" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- Hysteria2 ------------------------------------------------------------
add_hysteria2() {
    require_singbox || return 1; ensure_cert
    echo -e "\n${MAGENTA}${BOLD}Hysteria2${NC} 基于 QUIC, 弱网强"
    ask_port "监听端口 UDP"; local port="$REPLY_PORT"
    ask_name "Hysteria2-${port}"; local name="$REPLY_NAME"
    local pw; pw="$(gen_pass 16)"; local tag="hysteria2-${port}"

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
    local uuid pw; uuid="$(gen_uuid)"; pw="$(gen_pass 16)"; local tag="tuic-${port}"

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
    local pw; pw="$(gen_pass 16)"; local tag="anytls-${port}"

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
    stls_pw="$(gen_pass 16)"; ss_pw="$(gen_b64 16)"; method="2022-blake3-aes-128-gcm"
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
    local ss_userinfo; ss_userinfo="$(b64_line "${method}:${ss_pw}")"
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
    local user pass; user="user$(openssl rand -hex 2)"; pass="$(gen_pass 8)"
    local tag="socks-${port}"
    local inbound
    inbound="$(jq -n --arg tag "$tag" --argjson port "$port" --arg u "$user" --arg p "$pass" '{
        tag:$tag, listen:"0.0.0.0", port:$port, protocol:"socks",
        settings:{ auth:"password", accounts:[{user:$u, pass:$p}], udp:true } }')"
    core_add_inbounds "xray" "$inbound" || return 1
    local host; host="$(server_host)"
    local link="socks://$(b64_line "${user}:${pass}")@${host}:${port}#$(url_encode "$name")"
    local detail="  地址: ${host}\n  端口: ${port}\n  用户名: ${user}\n  密码: ${pass}\n  协议: SOCKS5"
    save_node "xray" "$tag" "SOCKS5" "$name" "$link" "$detail"
    show_result "$name" "$link" "$detail"
}

# --- NaïveProxy (sing-box naive 入站) ------------------------------------
add_naive() {
    require_singbox || return 1; ensure_cert
    echo -e "\n${MAGENTA}${BOLD}NaïveProxy${NC}"
    ask_port "监听端口"; local port="$REPLY_PORT"
    ask_name "Naive-${port}"; local name="$REPLY_NAME"
    local user pass; user="naive$(openssl rand -hex 3)"; pass="$(gen_pass 12)"
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
#  十一、Snell v4 (独立内核)
# ===========================================================================
snell_installed() { [[ -x "$SNELL_BIN" ]]; }
snell_running()   { systemctl is-active --quiet "$SNELL_SERVICE" 2>/dev/null; }

install_snell() {
    echo -e "\n${MAGENTA}${BOLD}Snell v4${NC} Surge 官方协议"
    local ver="v4.1.1" url tmp
    url="https://dl.nssurge.com/snell/snell-server-${ver}-linux-${SNELL_ARCH}.zip"
    command -v unzip >/dev/null 2>&1 || pkg_install unzip
    ask_port "Snell 监听端口"; local port="$REPLY_PORT"
    local psk; psk="$(gen_pass 16)"
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

    local host; host="$(server_host)"
    local surge="Snell-${port} = snell, ${host}, ${port}, psk=${psk}, version=4, reuse=true, tfo=true"
    echo; hr; ok "  ✅ Snell v4 部署成功!"; hr
    echo -e "${BOLD}Surge 节点配置行:${NC}"; echo -e "${GREEN}${surge}${NC}"; echo
    echo -e "${BOLD}手动参数:${NC}"
    echo -e "  地址: ${host}\n  端口: ${port}\n  PSK : ${psk}\n  版本: 4"
    hr
}

uninstall_snell() {
    snell_installed || { warn "Snell 未安装。"; return 0; }
    confirm "确认卸载 Snell?" "n" || return 0
    systemctl stop "$SNELL_SERVICE" 2>/dev/null; systemctl disable "$SNELL_SERVICE" 2>/dev/null
    rm -f "$SNELL_SERVICE_FILE" "$SNELL_BIN"; rm -rf "$(dirname "$SNELL_CONF")"
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
    local user pass; user="mieru$(openssl rand -hex 3)"; pass="$(gen_pass 12)"

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
    s_priv="$(wg genkey)"; s_pub="$(printf '%s' "$s_priv" | wg pubkey)"
    c_priv="$(wg genkey)"; c_pub="$(printf '%s' "$c_priv" | wg pubkey)"
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
        echo -e "${BOLD}[Snell v4]${NC} 已安装, 端口 $(grep -oP 'listen = ::0:\K[0-9]+' "$SNELL_CONF" 2>/dev/null)"
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

    tmp="$(mktemp)"
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
        newlink="$(echo "$link" | sed -E "s#@[^:/@]+:#@${host}:#")"
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
        VLESS-Reality-Vision|VLESS-XHTTP-Reality|VLESS-gRPC-Reality|VLESS-Encryption|VLESS-Encryption-XHTTP)
            clash_hostport "$link"
            local uuid="${link#vless://}"; uuid="${uuid%%@*}"
            local security net sni pbk sid flow svc path enc
            security="$(clash_q "$link" security)"; net="$(clash_q "$link" type)"; [[ -z "$net" ]] && net=tcp
            sni="$(clash_q "$link" sni)"; pbk="$(clash_q "$link" pbk)"; sid="$(clash_q "$link" sid)"
            flow="$(clash_q "$link" flow)"; svc="$(clash_q "$link" serviceName)"
            path="$(clash_q "$link" path)"; enc="$(clash_q "$link" encryption)"
            printf '  - name: "%s"\n    type: vless\n    server: %s\n    port: %s\n    uuid: %s\n    udp: true\n    network: %s\n' \
                "$name" "$CL_HOST" "$CL_PORT" "$uuid" "$net"
            [[ -n "$flow" ]] && printf '    flow: %s\n' "$flow"
            [[ -n "$enc" ]] && printf '    encryption: "%s"\n' "$enc"
            if [[ "$security" == reality ]]; then
                printf '    tls: true\n    servername: %s\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: "%s"\n' "$sni" "$pbk" "$sid"
            fi
            [[ "$net" == grpc && -n "$svc" ]] && printf '    grpc-opts:\n      grpc-service-name: "%s"\n' "$svc"
            [[ "$net" == ws && -n "$path" ]] && printf '    ws-opts:\n      path: "%s"\n' "$path"
            [[ "$net" == xhttp && -n "$path" ]] && printf '    xhttp-opts:\n      path: "%s"\n' "$path"
            ;;
        VMess-WS)
            local js; js="$(printf '%s' "${link#vmess://}" | base64 -d 2>/dev/null)"
            [[ -z "$js" ]] && return
            printf '  - name: "%s"\n    type: vmess\n    server: %s\n    port: %s\n    uuid: %s\n    alterId: 0\n    cipher: auto\n    udp: true\n    network: ws\n    ws-opts:\n      path: "%s"\n' \
                "$name" "$(echo "$js" | jq -r .add)" "$(echo "$js" | jq -r .port)" "$(echo "$js" | jq -r .id)" "$(echo "$js" | jq -r .path)"
            ;;
        Trojan-Reality)
            clash_hostport "$link"
            local pw="${link#trojan://}"; pw="${pw%%@*}"
            local sni pbk sid; sni="$(clash_q "$link" sni)"; pbk="$(clash_q "$link" pbk)"; sid="$(clash_q "$link" sid)"
            printf '  - name: "%s"\n    type: trojan\n    server: %s\n    port: %s\n    password: "%s"\n    udp: true\n    network: tcp\n    tls: true\n    sni: %s\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: "%s"\n' \
                "$name" "$CL_HOST" "$CL_PORT" "$pw" "$sni" "$pbk" "$sid"
            ;;
        SS2022)
            clash_hostport "$link"
            local ui="${link#ss://}"; ui="${ui%%@*}"
            local dec; dec="$(printf '%s' "$ui" | base64 -d 2>/dev/null)"
            printf '  - name: "%s"\n    type: ss\n    server: %s\n    port: %s\n    cipher: %s\n    password: "%s"\n    udp: true\n' \
                "$name" "$CL_HOST" "$CL_PORT" "${dec%%:*}" "${dec#*:}"
            ;;
        SOCKS5)
            clash_hostport "$link"
            local ui="${link#socks://}"; ui="${ui%%@*}"
            local dec; dec="$(printf '%s' "$ui" | base64 -d 2>/dev/null)"
            printf '  - name: "%s"\n    type: socks5\n    server: %s\n    port: %s\n    username: "%s"\n    password: "%s"\n    udp: true\n' \
                "$name" "$CL_HOST" "$CL_PORT" "${dec%%:*}" "${dec#*:}"
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
    local core="$1" tmp="$2" cfg
    if [[ "$core" == "xray" ]]; then
        cfg="$XRAY_CONFIG"
        "$XRAY_BIN" -test -config "$tmp" >/tmp/pm_check.log 2>&1 || { err "配置校验失败:"; sed 's/^/    /' /tmp/pm_check.log; rm -f "$tmp"; return 1; }
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

PICKED_TAG=""
pick_node() {
    PICKED_TAG=""
    if [[ "$(node_count)" == "0" ]]; then warn "当前没有可编辑的节点。"; return 1; fi
    local -a tags=(); local t
    while IFS= read -r t; do [[ -z "$t" ]] && continue; tags+=("$t"); done <<< "$(jq -r '.nodes|keys[]' "$STATE")"
    if [[ ${#tags[@]} -eq 1 ]]; then PICKED_TAG="${tags[0]}"; return 0; fi
    local i
    for i in "${!tags[@]}"; do
        printf "  ${GREEN}%2d.${NC} [%s] %s\n" "$((i+1))" \
            "$(jq -r --arg t "${tags[$i]}" '.nodes[$t].type' "$STATE")" \
            "$(jq -r --arg t "${tags[$i]}" '.nodes[$t].name' "$STATE")"
    done
    echo -e "  ${GREEN} 0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}选择节点编号: ${NC}")" c
    [[ "$c" == "0" || -z "$c" ]] && return 1
    if ! [[ "$c" =~ ^[0-9]+$ ]] || (( c<1 || c>${#tags[@]} )); then err "无效编号。"; return 1; fi
    PICKED_TAG="${tags[$((c-1))]}"
}

edit_single_node() {
    local tag="$1" core type name port
    [[ -n "$tag" ]] || return 0
    core="$(jq -r --arg t "$tag" '.nodes[$t].core' "$STATE")"
    type="$(jq -r --arg t "$tag" '.nodes[$t].type' "$STATE")"
    name="$(jq -r --arg t "$tag" '.nodes[$t].name' "$STATE")"
    port="$(node_get_port "$tag" "$core")"
    echo -e "\n${BOLD}编辑节点: [${type}] ${name}   当前端口: ${port:-未知}${NC}"
    echo -e "  ${GREEN}1.${NC} 修改端口"
    echo -e "  ${GREEN}2.${NC} 修改备注名"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) change_node_port "$tag" ;;
        2) change_node_name "$tag" ;;
        *) return 0 ;;
    esac
}

edit_node_menu() {
    echo -e "\n${YELLOW}${BOLD}=== 编辑节点配置 ===${NC}"
    echo -e "  ${GREEN}1.${NC} 修改节点地址, 域名或 IP"
    echo -e "  ${GREEN}2.${NC} 编辑单个节点, 端口或备注名"
    echo -e "  ${GREEN}0.${NC} 返回"
    local c; read -rp "$(echo -e "${CYAN}请选择: ${NC}")" c
    case "$c" in
        1) set_node_host ;;
        2) pick_node && edit_single_node "$PICKED_TAG" ;;
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
        6) confirm "确认全部卸载?" "n" && { uninstall_core_singbox quiet; uninstall_core_xray quiet; uninstall_snell; uninstall_mieru quiet; uninstall_wireguard quiet; rm -rf "$STATE_DIR"; ok "已全部卸载并清空状态。"; } ;;
        *) return 0 ;;
    esac
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
    echo -e "${CYAN}┌──────────────────── 服务状态 ────────────────────┐${NC}"
    if sb_installed; then
        if sb_running; then echo -e "${CYAN}│${NC} sing-box: ${GREEN}● 运行中${NC}  版本 $(sb_version)"
        else echo -e "${CYAN}│${NC} sing-box: ${RED}● 已停止${NC}  版本 $(sb_version)"; fi
    else echo -e "${CYAN}│${NC} sing-box: ${YELLOW}○ 未安装${NC}"; fi
    if xray_installed; then
        if xray_running; then echo -e "${CYAN}│${NC} Xray    : ${GREEN}● 运行中${NC}  版本 $(xray_version)"
        else echo -e "${CYAN}│${NC} Xray    : ${RED}● 已停止${NC}  版本 $(xray_version)"; fi
    else echo -e "${CYAN}│${NC} Xray    : ${YELLOW}○ 未安装${NC}"; fi
    if snell_installed; then
        if snell_running; then echo -e "${CYAN}│${NC} Snell   : ${GREEN}● 运行中${NC}"
        else echo -e "${CYAN}│${NC} Snell   : ${RED}● 已停止${NC}"; fi
    fi
    if mieru_installed; then
        if mieru_running; then echo -e "${CYAN}│${NC} Mieru   : ${GREEN}● 运行中${NC}"
        else echo -e "${CYAN}│${NC} Mieru   : ${RED}● 已停止${NC}"; fi
    fi
    if wg_installed; then
        if wg_running; then echo -e "${CYAN}│${NC} WireGuard: ${GREEN}● 运行中${NC}"
        else echo -e "${CYAN}│${NC} WireGuard: ${RED}● 已停止${NC}"; fi
    fi
    echo -e "${CYAN}│${NC} 已部署节点: ${GREEN}$(node_count)${NC} 个"
    echo -e "${CYAN}└──────────────────────────────────────────────────┘${NC}"
}

show_menu() {
    clear 2>/dev/null || true
    echo -e "${MAGENTA}${BOLD}"
    echo "   ╔═══════════════════════════════════════════════╗"
    echo "   ║             Proxy Node Manager                ║"
    echo "   ║        多协议代理节点一键生成脚本             ║"
    echo -e "   ╚═══════════════════════════════════════════════╝${NC}"
    echo -e "   ${DIM}v${SCRIPT_VERSION} | 系统 ${OS_ID:-?}/${ARCH} | 快捷命令: pm${NC}"
    echo
    show_status
    echo
    echo -e "${BLUE}${BOLD}─── VLESS 协议 ───${NC}"
    echo -e "  ${GREEN}1.${NC} VLESS-Reality-Vision"
    echo -e "  ${GREEN}2.${NC} VLESS-XHTTP-Reality"
    echo -e "  ${GREEN}3.${NC} VLESS-gRPC-Reality"
    echo -e "  ${GREEN}4.${NC} VLESS-Encryption"
    echo -e "  ${GREEN}5.${NC} VLESS-Encryption-XHTTP"
    echo -e "${BLUE}${BOLD}─── FinalMask 抗审查 ───${NC}"
    echo -e "  ${GREEN}6.${NC} VLESS-Encryption-XHTTP-FinalMask"
    echo -e "  ${GREEN}7.${NC} VLESS-Encryption-FinalMask sudoku"
    echo -e "  ${GREEN}8.${NC} FullStack REALITY+XHTTP+FinalMask"
    echo -e "${MAGENTA}${BOLD}─── VMess / Trojan ───${NC}"
    echo -e "  ${GREEN}9.${NC} VMess-WebSocket"
    echo -e " ${GREEN}10.${NC} Trojan-Reality"
    echo -e "${MAGENTA}${BOLD}─── Shadowsocks / SOCKS ───${NC}"
    echo -e " ${GREEN}11.${NC} Shadowsocks-2022"
    echo -e " ${GREEN}12.${NC} SOCKS5"
    echo -e "${MAGENTA}${BOLD}─── QUIC / 抗审查 ───${NC}"
    echo -e " ${GREEN}13.${NC} Hysteria2"
    echo -e " ${GREEN}14.${NC} TUIC v5"
    echo -e " ${GREEN}15.${NC} AnyTLS"
    echo -e " ${GREEN}16.${NC} ShadowTLS v3"
    echo -e " ${GREEN}17.${NC} NaïveProxy"
    echo -e "${BLUE}${BOLD}─── 独立协议 ───${NC}"
    echo -e " ${GREEN}18.${NC} Snell v4"
    echo -e " ${GREEN}19.${NC} Mieru"
    echo -e " ${GREEN}20.${NC} WireGuard"
    echo -e "${YELLOW}${BOLD}─── 节点与系统管理 ───${NC}"
    echo -e " ${GREEN}21.${NC} 查看全部节点"
    echo -e " ${GREEN}22.${NC} 编辑节点配置"
    echo -e " ${GREEN}23.${NC} 删除指定节点"
    echo -e " ${GREEN}24.${NC} 内核与服务管理"
    echo -e " ${RED}25.${NC} 卸载"
    echo -e "  ${GREEN}0.${NC} 退出"
    hr
}

main_loop() {
    while true; do
        show_menu
        read -rp "$(echo -e "${CYAN}请输入选项 [0-25]: ${NC}")" choice
        echo
        case "$choice" in
            1)  add_xray_vision_reality ;;
            2)  add_xray_xhttp_reality ;;
            3)  add_vless_grpc_reality ;;
            4)  add_xray_vless_encryption ;;
            5)  add_vless_encryption_xhttp ;;
            6)  add_vless_enc_xhttp_finalmask ;;
            7)  add_vless_enc_finalmask ;;
            8)  add_vless_fullstack ;;
            9)  add_vmess_ws ;;
            10) add_trojan_reality ;;
            11) add_ss2022 ;;
            12) add_socks ;;
            13) add_hysteria2 ;;
            14) add_tuic ;;
            15) add_anytls ;;
            16) add_shadowtls ;;
            17) add_naive ;;
            18) install_snell ;;
            19) install_mieru ;;
            20) install_wireguard ;;
            21) view_all_nodes ;;
            22) edit_node_menu ;;
            23) manage_nodes ;;
            24) core_manage_menu ;;
            25) uninstall_menu ;;
            0)  ok "感谢使用, 再见!"; exit 0 ;;
            *)  err "无效选项, 请输入 0-25。" ;;
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
