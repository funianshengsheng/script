#!/usr/bin/env bash
# ============================================================
#  SS-Rust 一键安装 & 管理脚本 v2.0
#  支持 2022-blake3-aes-128-gcm + aes-128-gcm 双模式
#  融合 MTU/MSS 优化 + Realm 首连修复
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

CONFIG_DIR="/etc/shadowsocks-rust"
CONFIG_FILE="${CONFIG_DIR}/config.json"
ENV_FILE="${CONFIG_DIR}/.env"
BIN_DIR="/usr/local/bin"
SVC="shadowsocks-rust"
SS_REPO="shadowsocks/shadowsocks-rust"
BOX_W=58

info()  { echo -e "  ${GREEN}✔${NC} $*"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $*"; }
error() { echo -e "  ${RED}✘${NC} $*"; exit 1; }
step()  { echo -e "  ${CYAN}▶${NC} $*"; }

_box_top()    { echo -e "  ╔$(printf '═%.0s' $(seq 1 $((BOX_W+2))))╗"; }
_box_bottom() { echo -e "  ╚$(printf '═%.0s' $(seq 1 $((BOX_W+2))))╝"; }
_box_mid()    { echo -e "  ╠$(printf '═%.0s' $(seq 1 $((BOX_W+2))))╣"; }
_box_empty()  { echo -e "  ║$(printf ' %.0s' $(seq 1 $((BOX_W+2))))║"; }
_box_line() {
    local raw="$*"
    local stripped
    stripped=$(echo -e "$raw" | sed 's/\x1b\[[0-9;]*m//g')
    local len=${#stripped}
    local pad=$((BOX_W - len))
    (( pad < 0 )) && pad=0
    echo -e "  ║ ${raw}$(printf ' %.0s' $(seq 1 $((pad+1))))║"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 运行"
    fi
}

get_main_iface() {
    ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}

validate_port() {
    local p="$1"
    [[ ! "$p" =~ ^[0-9]+$ ]] && { warn "端口必须是数字"; return 1; }
    (( p < 1 || p > 65535 )) && { warn "端口范围 1-65535"; return 1; }
    if ss -tlnp 2>/dev/null | grep -q ":${p} "; then
        warn "端口 ${p} 已被占用"; return 1
    fi
    return 0
}

get_arch() {
    case "$(uname -m)" in
        x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        armv7l)  echo "armv7-unknown-linux-gnueabihf" ;;
        *)       error "不支持的架构: $(uname -m)" ;;
    esac
}

get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${SS_REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/'
}

get_current_version() {
    if [[ -x "${BIN_DIR}/ssserver" ]]; then
        "${BIN_DIR}/ssserver" --version 2>/dev/null | awk '{print $2}' || echo "未知"
    else
        echo "未安装"
    fi
}

get_pkg_manager() {
    if command -v apt &>/dev/null; then PKG="apt"
    elif command -v yum &>/dev/null; then PKG="yum"
    elif command -v dnf &>/dev/null; then PKG="dnf"
    else error "不支持的包管理器"; fi
}

install_deps() {
    step "安装依赖..."
    case "$PKG" in
        apt) apt update -qq &>/dev/null; apt install -y -qq curl openssl xz-utils tar chrony python3 file iptables &>/dev/null ;;
        yum) yum install -y -q curl openssl xz tar chrony python3 file iptables &>/dev/null ;;
        dnf) dnf install -y -q curl openssl xz tar chrony python3 file iptables &>/dev/null ;;
    esac
    info "依赖就绪"
}

sync_time() {
    step "同步时间..."
    if systemctl is-active chronyd &>/dev/null; then
        chronyc makestep &>/dev/null 2>&1 || true
    else
        systemctl start chronyd 2>/dev/null || systemctl start chrony 2>/dev/null || true
        chronyc makestep &>/dev/null 2>&1 || true
    fi
    info "时间同步完成"
}

download_ssrust() {
    local version="$1"
    local arch
    arch=$(get_arch)
    local url="https://github.com/${SS_REPO}/releases/download/v${version}/shadowsocks-v${version}.${arch}.tar.xz"
    step "下载 ss-rust v${version}..."
    (
        cd /tmp
        curl -fsSL -o ss.tar.xz "$url" || error "下载失败"
        tar xf ss.tar.xz
        install -m 755 ssserver "${BIN_DIR}/ssserver"
        [[ -f sslocal ]] && install -m 755 sslocal "${BIN_DIR}/sslocal"
        [[ -f ssurl ]]   && install -m 755 ssurl   "${BIN_DIR}/ssurl"
        rm -f ss.tar.xz ssserver sslocal ssurl ssmanager ssservice
    )
    info "ss-rust v${version} 安装完成"
}

install_ssrust() {
    local version
    version=$(get_latest_version)
    [[ -z "$version" ]] && error "无法获取最新版本"
    download_ssrust "$version"
}

_gen_config_json() {
    local mode="$1" p2022="$2" praw="$3" k2022="$4" kraw="$5" m2022="$6" mraw="$7"
    export SS_MODE="$mode" SS_PORT_2022="$p2022" SS_PORT_RAW="$praw"
    export SS_KEY_2022="$k2022" SS_KEY_RAW="$kraw" SS_METHOD_2022="$m2022" SS_METHOD_RAW="$mraw"
    python3 -c '
import json, os
mode = os.environ["SS_MODE"]
servers = []
if mode in ("1","3"):
    servers.append({
        "server":"0.0.0.0","server_port":int(os.environ["SS_PORT_2022"]),
        "method":os.environ["SS_METHOD_2022"],"password":os.environ["SS_KEY_2022"],
        "mode":"tcp_and_udp","fast_open":True,"no_delay":True
    })
if mode in ("2","3"):
    servers.append({
        "server":"0.0.0.0","server_port":int(os.environ["SS_PORT_RAW"]),
        "method":os.environ["SS_METHOD_RAW"],"password":os.environ["SS_KEY_RAW"],
        "mode":"tcp_and_udp","fast_open":True,"no_delay":True
    })
with open("'"$CONFIG_FILE"'","w") as f:
    json.dump({"servers": servers}, f, indent=2)
'
}

select_and_configure() {
    echo ""
    _box_top
    _box_line "${BOLD}选择加密模式${NC}"
    _box_mid
    _box_line "  ${GREEN}1.${NC} 2022-blake3-aes-128-gcm ${DIM}(推荐)${NC}"
    _box_line "  ${GREEN}2.${NC} aes-128-gcm ${DIM}(兼容)${NC}"
    _box_line "  ${GREEN}3.${NC} 双模式 (两个端口同时运行)"
    _box_bottom
    echo ""
    read -rp "  请选择 [1-3] (默认3): " mode_choice
    mode_choice=${mode_choice:-3}

    local port_2022="" port_raw="" key_2022="" key_raw="" method_2022="" method_raw=""

    if [[ "$mode_choice" == "1" || "$mode_choice" == "3" ]]; then
        method_2022="2022-blake3-aes-128-gcm"
        read -rp "  SS2022 端口 (默认随机): " port_2022
        if [[ -z "$port_2022" ]]; then
            port_2022=$((RANDOM % 50000 + 10000))
        fi
        validate_port "$port_2022" || error "端口无效"
        key_2022=$(openssl rand -base64 16)
    fi

    if [[ "$mode_choice" == "2" || "$mode_choice" == "3" ]]; then
        method_raw="aes-128-gcm"
        read -rp "  AES-128 端口 (默认随机): " port_raw
        if [[ -z "$port_raw" ]]; then
            port_raw=$((RANDOM % 50000 + 10000))
        fi
        validate_port "$port_raw" || error "端口无效"
        key_raw=$(openssl rand -base64 16)
    fi

    mkdir -p "$CONFIG_DIR"
    cat > "$ENV_FILE" <<ENVEOF
PORT_2022=${port_2022}
PORT_RAW=${port_raw}
KEY_2022=${key_2022}
KEY_RAW=${key_raw}
METHOD_2022=${method_2022}
METHOD_RAW=${method_raw}
MODE=${mode_choice}
ENVEOF
    chmod 600 "$ENV_FILE"
    _gen_config_json "$mode_choice" "$port_2022" "$port_raw" "$key_2022" "$key_raw" "$method_2022" "$method_raw"
    info "配置已生成: ${CONFIG_FILE}"
}

setup_service() {
    step "配置 systemd 服务..."
    cat > "/etc/systemd/system/${SVC}.service" <<SVCEOF
[Unit]
Description=Shadowsocks-Rust Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/ssserver -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable ${SVC} &>/dev/null
    systemctl restart ${SVC}
    info "服务已启动"
}

get_server_ip() {
    local ip
    ip=$(curl -4 -fsSL --max-time 5 ifconfig.me 2>/dev/null) || \
    ip=$(curl -4 -fsSL --max-time 5 ipinfo.io/ip 2>/dev/null) || \
    ip=$(curl -4 -fsSL --max-time 5 icanhazip.com 2>/dev/null) || \
    ip="YOUR_SERVER_IP"
    echo "$ip"
}

_gen_uris() {
    local ip
    ip=$(get_server_ip)
    URI_2022=""; URI_RAW=""
    if [[ -n "${METHOD_2022:-}" && -n "${PORT_2022:-}" && -n "${KEY_2022:-}" ]]; then
        local userinfo
        userinfo=$(echo -n "${METHOD_2022}:${KEY_2022}" | base64 -w0)
        URI_2022="ss://${userinfo}@${ip}:${PORT_2022}#SS2022-${ip}"
    fi
    if [[ -n "${METHOD_RAW:-}" && -n "${PORT_RAW:-}" && -n "${KEY_RAW:-}" ]]; then
        local userinfo
        userinfo=$(echo -n "${METHOD_RAW}:${KEY_RAW}" | base64 -w0)
        URI_RAW="ss://${userinfo}@${ip}:${PORT_RAW}#AES128-${ip}"
    fi
}

gen_subscribe() {
    _gen_uris
    local all=""
    [[ -n "${URI_2022:-}" ]] && all+="${URI_2022}"$'\n'
    [[ -n "${URI_RAW:-}" ]]  && all+="${URI_RAW}"$'\n'
    if [[ -n "$all" ]]; then
        echo -n "$all" | base64 -w0 > "${CONFIG_DIR}/subscribe.txt"
    fi
}

load_config() {
    [[ ! -f "$ENV_FILE" ]] && return 1
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    _gen_uris
    return 0
}

show_result() {
    load_config || true
    local ip
    ip=$(get_server_ip)
    echo ""
    _box_top
    _box_line "${BOLD}🎉 安装完成${NC}"
    _box_mid
    _box_line "  服务器: ${YELLOW}${ip}${NC}"
    _box_empty
    if [[ -n "${PORT_2022:-}" ]]; then
        _box_line "${BOLD}  ── SS2022-blake3-aes-128-gcm ──${NC}"
        _box_line "  端口: ${GREEN}${PORT_2022}${NC}"
        _box_line "  密钥: ${GREEN}${KEY_2022}${NC}"
        [[ -n "${URI_2022:-}" ]] && _box_line "  ${DIM}${URI_2022}${NC}"
        _box_empty
    fi
    if [[ -n "${PORT_RAW:-}" ]]; then
        _box_line "${BOLD}  ── AES-128-GCM ──${NC}"
        _box_line "  端口: ${GREEN}${PORT_RAW}${NC}"
        _box_line "  密钥: ${GREEN}${KEY_RAW}${NC}"
        [[ -n "${URI_RAW:-}" ]] && _box_line "  ${DIM}${URI_RAW}${NC}"
        _box_empty
    fi
    _box_bottom
    echo ""
}

show_config() {
    load_config || error "未安装"
    show_result
}

change_port() {
    load_config || error "未安装"
    echo ""
    if [[ -n "${PORT_2022:-}" ]]; then
        read -rp "  SS2022 新端口 (当前${PORT_2022}, 回车跳过): " np
        if [[ -n "$np" ]]; then
            validate_port "$np" || return
            PORT_2022="$np"
        fi
    fi
    if [[ -n "${PORT_RAW:-}" ]]; then
        read -rp "  AES128 新端口 (当前${PORT_RAW}, 回车跳过): " np
        if [[ -n "$np" ]]; then
            validate_port "$np" || return
            PORT_RAW="$np"
        fi
    fi
    sed -i "s/^PORT_2022=.*/PORT_2022=${PORT_2022}/" "$ENV_FILE"
    sed -i "s/^PORT_RAW=.*/PORT_RAW=${PORT_RAW}/" "$ENV_FILE"
    _gen_config_json "$MODE" "$PORT_2022" "$PORT_RAW" "$KEY_2022" "$KEY_RAW" "$METHOD_2022" "$METHOD_RAW"
    systemctl restart ${SVC}
    gen_subscribe
    info "端口已更新，服务已重启"
    show_result
}

reset_keys() {
    load_config || error "未安装"
    [[ -n "${KEY_2022:-}" ]] && KEY_2022=$(openssl rand -base64 16)
    [[ -n "${KEY_RAW:-}" ]]  && KEY_RAW=$(openssl rand -base64 16)
    sed -i "s|^KEY_2022=.*|KEY_2022=${KEY_2022}|" "$ENV_FILE"
    sed -i "s|^KEY_RAW=.*|KEY_RAW=${KEY_RAW}|" "$ENV_FILE"
    _gen_config_json "$MODE" "$PORT_2022" "$PORT_RAW" "$KEY_2022" "$KEY_RAW" "$METHOD_2022" "$METHOD_RAW"
    systemctl restart ${SVC}
    gen_subscribe
    info "密钥已重置，服务已重启"
    show_result
}

update_ssrust() {
    local cur latest
    cur=$(get_current_version)
    latest=$(get_latest_version)
    [[ -z "$latest" ]] && error "无法获取最新版本"
    if [[ "$cur" == "$latest" ]]; then
        info "已是最新版本: v${cur}"; return
    fi
    step "更新: v${cur} → v${latest}"
    systemctl stop ${SVC} 2>/dev/null || true
    download_ssrust "$latest"
    systemctl start ${SVC}
    info "更新完成: v${latest}"
}

backup_config() {
    [[ ! -f "$CONFIG_FILE" ]] && error "无配置可备份"
    local bak="/root/ss-rust-backup-$(date +%Y%m%d%H%M%S).tar.gz"
    tar czf "$bak" -C / "etc/shadowsocks-rust"
    info "已备份到: ${bak}"
}

restore_config() {
    local latest
    latest=$(ls -t /root/ss-rust-backup-*.tar.gz 2>/dev/null | head -1)
    [[ -z "$latest" ]] && error "未找到备份文件"
    echo "  找到备份: ${latest}"
    read -rp "  确认恢复? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    tar xzf "$latest" -C /
    systemctl restart ${SVC} 2>/dev/null || true
    info "配置已恢复并重启服务"
}

show_connections() {
    load_config || error "未安装"
    echo ""
    _box_top
    _box_line "${BOLD}🌐 连接状态${NC}"
    _box_mid
    local st
    st=$(systemctl is-active ${SVC} 2>/dev/null || echo "未知")
    local sc si
    if [[ "$st" == "active" ]]; then sc="${GREEN}"; si="●"; st="运行中"
    else sc="${RED}"; si="○"; [[ "$st" == "inactive" ]] && st="已停止"; fi
    _box_line "  服务: ${sc}${si} ${st}${NC}"
    local ver
    ver=$(get_current_version)
    _box_line "  版本: ${ver}"
    local uptime_str
    uptime_str=$(systemctl show ${SVC} --property=ActiveEnterTimestamp --value 2>/dev/null || true)
    [[ -n "$uptime_str" ]] && _box_line "  启动: ${DIM}${uptime_str}${NC}"
    _box_mid
    _box_line "${BOLD}  端口连接数${NC}"
    _box_empty
    if [[ -n "${PORT_2022:-}" ]]; then
        local c2022
        c2022=$(ss -tnp 2>/dev/null | grep -c ":${PORT_2022} " || true)
        _box_line "  SS2022-128 :${PORT_2022}  ${YELLOW}${c2022}${NC} 个连接"
    fi
    if [[ -n "${PORT_RAW:-}" ]]; then
        local craw
        craw=$(ss -tnp 2>/dev/null | grep -c ":${PORT_RAW} " || true)
        _box_line "  SS-AES-128 :${PORT_RAW}  ${YELLOW}${craw}${NC} 个连接"
    fi
    _box_mid
    _box_line "${BOLD}  最近连接 IP (Top 10)${NC}"
    _box_empty
    local ports_regex=""
    [[ -n "${PORT_2022:-}" ]] && ports_regex=":${PORT_2022} "
    [[ -n "${PORT_RAW:-}" ]]  && ports_regex="${ports_regex}|:${PORT_RAW} "
    ports_regex=${ports_regex#|}
    if [[ -n "$ports_regex" ]]; then
        local ips
        ips=$(ss -tnp 2>/dev/null | grep -E "$ports_regex" \
            | awk '{print $5}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -10 || true)
        if [[ -n "$ips" ]]; then
            while read -r cnt ip; do
                _box_line "    ${ip}  ${DIM}(${cnt})${NC}"
            done <<< "$ips"
        else
            _box_line "  ${DIM}暂无活跃连接${NC}"
        fi
    fi
    _box_empty
    _box_bottom
    echo ""
}

setup_bbr() {
    echo ""
    _box_top
    _box_line "${BOLD}⚡ BBR + TCP 调优${NC}"
    _box_mid
    local cc qd
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
    if [[ "$cc" == "bbr" && "$qd" == "fq" ]] && grep -q "BBR Blast" /etc/sysctl.conf 2>/dev/null; then
        _box_line "  ${GREEN}●${NC} BBR + TCP 完整调优已启用"
        _box_bottom
        return 0
    fi
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        _box_line "  系统: ${ID:-unknown} ${VERSION_ID:-}"
    fi
    local mem
    mem=$(free -m | awk '/^Mem:/{print $2}')
    local profile rmem wmem tcp_rmem tcp_wmem
    if   (( mem < 512 ));  then profile="micro";  rmem=8388608;   wmem=8388608;   tcp_rmem="4096 32768 8388608";   tcp_wmem="4096 32768 8388608"
    elif (( mem < 1024 )); then profile="small";  rmem=16777216;  wmem=16777216;  tcp_rmem="4096 65536 16777216";  tcp_wmem="4096 65536 16777216"
    elif (( mem < 2048 )); then profile="medium"; rmem=33554432;  wmem=33554432;  tcp_rmem="4096 87380 33554432";  tcp_wmem="4096 65536 33554432"
    elif (( mem < 4096 )); then profile="large";  rmem=67108864;  wmem=67108864;  tcp_rmem="4096 87380 67108864";  tcp_wmem="4096 65536 67108864"
    else                    profile="xlarge"; rmem=134217728; wmem=134217728; tcp_rmem="4096 87380 134217728"; tcp_wmem="4096 65536 134217728"
    fi
    _box_line "  内存: ${mem}MB | Profile: ${profile}"
    _box_bottom
    echo ""
    [[ -f /etc/sysctl.conf ]] && cp /etc/sysctl.conf "/etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)"
    sed -i '/# === BBR Blast/,/# === END BBR/d' /etc/sysctl.conf 2>/dev/null || true
    cat >> /etc/sysctl.conf <<SYSCTL
# === BBR Blast + TCP Tuning (Profile: ${profile}) ===
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=${rmem}
net.core.wmem_max=${wmem}
net.core.rmem_default=$((rmem/4))
net.core.wmem_default=$((wmem/4))
net.ipv4.tcp_rmem=${tcp_rmem}
net.ipv4.tcp_wmem=${tcp_wmem}
net.core.optmem_max=65536
net.core.netdev_max_backlog=16384
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_max_orphans=65535
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_fin_timeout=8
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries=3
net.ipv4.tcp_retries2=8
net.ipv4.tcp_orphan_retries=2
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
fs.file-max=2097152
fs.nr_open=2097152
# === END BBR Blast ===
SYSCTL
    sysctl -p >/dev/null 2>&1
    info "BBR + TCP 完整调优已应用 (profile=${profile})"
}

detect_and_fix_mtu() {
    local iface
    iface=$(get_main_iface)
    [[ -z "$iface" ]] && { warn "无法检测主网卡"; return 1; }
    echo ""
    _box_top
    _box_line "${BOLD}📐 MTU/MSS 检测与优化${NC}"
    _box_mid
    local current_mtu
    current_mtu=$(ip link show "$iface" | awk '/mtu/{for(i=1;i<=NF;i++) if($i=="mtu") print $(i+1)}')
    _box_line "  网卡: ${YELLOW}${iface}${NC}  当前 MTU: ${YELLOW}${current_mtu}${NC}"
    _box_bottom
    echo ""
    step "探测最佳 MTU..."
    local target="1.1.1.1" best_mtu=1500 found=false
    for try_mtu in 1500 1492 1480 1460 1440 1420 1400; do
        local pkt_size=$((try_mtu - 28))
        if ping -c1 -W2 -M do -s "$pkt_size" "$target" &>/dev/null; then
            best_mtu=$try_mtu; found=true; break
        fi
    done
    if $found; then
        info "探测最佳 MTU: ${best_mtu}"
    else
        warn "MTU 探测失败，保持默认 ${current_mtu}"; return 0
    fi
    if [[ "$current_mtu" -ne "$best_mtu" ]]; then
        ip link set "$iface" mtu "$best_mtu"
        info "已设置 MTU=${best_mtu} (原值=${current_mtu})"
    else
        info "MTU 已是最佳值: ${best_mtu}"
    fi
    local mss=$((best_mtu - 40))
    step "设置 MSS Clamping: ${mss}"
    if command -v iptables &>/dev/null; then
        iptables  -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss" 2>/dev/null || true
        iptables  -t mangle -D OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss" 2>/dev/null || true
        iptables  -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
        iptables  -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
        info "iptables MSS clamping 已设置"
    fi
    if command -v ip6tables &>/dev/null; then
        ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss" 2>/dev/null || true
        ip6tables -t mangle -D OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss" 2>/dev/null || true
        ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
        ip6tables -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
        info "ip6tables MSS clamping 已设置"
    fi
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null && info "iptables 规则已持久化"
    fi
}

fix_realm_first_connect() {
    echo ""
    _box_top
    _box_line "${BOLD}🔧 Realm 首连超时修复${NC}"
    _box_mid
    local changed=false
    local -a params=(
        "net.ipv4.tcp_syn_retries|2|SYN 重传次数"
        "net.ipv4.tcp_synack_retries|2|SYNACK 重传次数"
        "net.ipv4.tcp_slow_start_after_idle|0|慢启动重启"
        "net.ipv4.tcp_no_metrics_save|1|路由指标缓存"
        "net.ipv4.tcp_fastopen|3|TCP Fast Open"
        "net.ipv4.tcp_fin_timeout|8|FIN 超时"
        "net.ipv4.tcp_mtu_probing|1|MTU 探测"
    )
    for entry in "${params[@]}"; do
        IFS='|' read -r key target desc <<< "$entry"
        local cur
        cur=$(sysctl -n "$key" 2>/dev/null || echo "0")
        local need=false
        case "$key" in
            *slow_start*|*no_metrics*|*fastopen*|*mtu_probing*)
                [[ "$cur" -ne "$target" ]] && need=true ;;
            *)
                [[ "$cur" -gt "$target" ]] && need=true ;;
        esac
        if $need; then
            sysctl -w "${key}=${target}" >/dev/null 2>&1
            sed -i "/^${key}/d" /etc/sysctl.conf
            echo "${key}=${target}" >> /etc/sysctl.conf
            _box_line "  ${GREEN}✓${NC} ${desc}: ${cur} → ${YELLOW}${target}${NC}"
            changed=true
        else
            _box_line "  ${DIM}● ${desc}: ${cur} (已最优)${NC}"
        fi
    done
    _box_mid
    if $changed; then
        _box_line "  ${GREEN}优化已应用${NC}"
    else
        _box_line "  ${GREEN}所有参数已处于最优状态${NC}"
    fi
    _box_bottom
    echo ""
}

uninstall() {
    echo ""
    read -rp "  确认卸载 ss-rust? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { info "已取消"; return; }
    systemctl stop ${SVC} 2>/dev/null || true
    systemctl disable ${SVC} 2>/dev/null || true
    rm -f "/etc/systemd/system/${SVC}.service"
    systemctl daemon-reload
    rm -f "${BIN_DIR}/ssserver" "${BIN_DIR}/sslocal" "${BIN_DIR}/ssurl"
    rm -rf "$CONFIG_DIR"
    info "卸载完成"
}

do_install() {
    check_root
    get_pkg_manager
    install_deps
    sync_time
    install_ssrust
    select_and_configure
    setup_service
    gen_subscribe
    show_result
}

show_menu() {
    while true; do
        load_config 2>/dev/null || true
        local st
        st=$(systemctl is-active ${SVC} 2>/dev/null || echo "未知")
        local sc si
        if [[ "$st" == "active" ]]; then sc="${GREEN}"; si="●"; st="运行中"
        else sc="${RED}"; si="○"; [[ "$st" == "inactive" ]] && st="已停止" || true; fi
        local ver
        ver=$(get_current_version)
        echo ""
        _box_top
        _box_line "${BOLD}  SS-Rust 管理面板${NC}"
        _box_line "  ${sc}${si} ${st}${NC}  ${DIM}v${ver}${NC}"
        _box_mid
        _box_line "${DIM}  ── 配置管理 ──${NC}"
        _box_line "  ${GREEN} 1.${NC} 查看配置"
        _box_line "  ${GREEN} 2.${NC} 修改端口"
        _box_line "  ${GREEN} 3.${NC} 重置密钥"
        _box_empty
        _box_line "${DIM}  ── 服务控制 ──${NC}"
        _box_line "  ${GREEN} 4.${NC} 启动服务"
        _box_line "  ${GREEN} 5.${NC} 停止服务"
        _box_line "  ${GREEN} 6.${NC} 重启服务"
        _box_line "  ${GREEN} 7.${NC} 查看日志"
        _box_line "  ${GREEN} 8.${NC} 连接状态"
        _box_empty
        _box_line "${DIM}  ── 系统维护 ──${NC}"
        _box_line "  ${GREEN} 9.${NC} 更新 ss-rust"
        _box_line "  ${GREEN}10.${NC} BBR 加速优化"
        _box_line "  ${GREEN}11.${NC} MTU/MSS 优化"
        _box_line "  ${GREEN}12.${NC} Realm 首连修复"
        _box_line "  ${GREEN}13.${NC} 备份配置"
        _box_line "  ${GREEN}14.${NC} 恢复配置"
        _box_empty
        _box_line "  ${GREEN}15.${NC} 重新安装"
        _box_line "  ${RED}16.${NC} 卸载"
        _box_line "  ${YELLOW} 0.${NC} 退出"
        _box_bottom
        echo ""
        read -rp "  请选择 [0-16]: " choice
        case "$choice" in
            1)  show_config ;;
            2)  change_port ;;
            3)  reset_keys ;;
            4)  systemctl start ${SVC} && info "已启动" || warn "启动失败" ;;
            5)  systemctl stop ${SVC} && info "已停止" || warn "停止失败" ;;
            6)  systemctl restart ${SVC} && info "已重启" || warn "重启失败" ;;
            7)  journalctl -u ${SVC} --no-pager -n 30 ;;
            8)  show_connections ;;
            9)  update_ssrust ;;
            10) setup_bbr ;;
            11) detect_and_fix_mtu ;;
            12) fix_realm_first_connect ;;
            13) backup_config ;;
            14) restore_config ;;
            15) do_install ;;
            16) uninstall ;;
            0)  exit 0 ;;
            *)  warn "无效选择" ;;
        esac
        echo ""
        read -rp "  按回车返回菜单..." _
    done
}

main() {
    check_root
    case "${1:-}" in
        show)      show_config ;;
        restart)   systemctl restart ${SVC} && info "已重启" ;;
        update)    update_ssrust ;;
        backup)    backup_config ;;
        restore)   restore_config ;;
        status)    show_connections ;;
        reset)     reset_keys ;;
        bbr)       setup_bbr ;;
        mtu)       detect_and_fix_mtu ;;
        realm)     fix_realm_first_connect ;;
        uninstall) uninstall ;;
        "")
            if [[ -f "$CONFIG_FILE" ]]; then
                show_menu
            else
                do_install
            fi
            ;;
        *) warn "未知命令: $1"; exit 1 ;;
    esac
}

main "$@"