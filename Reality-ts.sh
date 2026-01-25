#!/bin/bash

# 脚本在任何命令失败时立即退出
set -e

# --- 配置 ---
LOG_FILE="reality-check.log"
REALI_TL_SCANNER_VERSION="v0.2.1"
REALI_TL_SCANNER_URL="https://github.com/XTLS/RealiTLScanner/releases/download/${REALI_TL_SCANNER_VERSION}/RealiTLScanner-linux-64"
REALI_TL_SCANNER_BIN="RealiTLScanner-linux-64"
REALITY_CHECKER_BIN="reality-checker"

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# --- 函数定义 ---

# 日志记录函数
log() {
    echo -e "$1" | tee -a "${LOG_FILE}"
}

# 错误处理函数
error_exit() {
    log "${RED}错误: $1${NC}"
    exit 1
}

# 清理函数
cleanup() {
    log "${YELLOW}--- 开始清理下载的临时文件 ---${NC}"
    rm -f "${REALI_TL_SCANNER_BIN}" "${REALITY_CHECKER_BIN}" "reality-checker-linux-*.zip"
    log "${GREEN}--- 清理完成 ---${NC}"
}

# 依赖安装函数，自动检测包管理器
install_dependencies() {
    log "正在检测包管理器并安装依赖..."
    # 检查并安装 coreutils (为了 timeout 命令)
    local pkgs="unzip curl wget coreutils"

    if command -v apt-get &> /dev/null; then
        log "检测到 apt-get (Debian/Ubuntu)，正在更新和安装..."
        apt-get update > /dev/null
        apt-get install -y $pkgs
    elif command -v dnf &> /dev/null; then
        log "检测到 dnf (Fedora/RHEL)，正在安装..."
        dnf install -y $pkgs
    elif command -v yum &> /dev/null; then
        log "检测到 yum (CentOS)，正在安装..."
        yum install -y $pkgs
    elif command -v pacman &> /dev/null; then
        log "检测到 pacman (Arch Linux)，正在更新和安装..."
        pacman -Syu --noconfirm $pkgs
    else
        error_exit "未能检测到支持的包管理器 (apt/dnf/yum/pacman)。请手动安装: $pkgs"
    fi
    log "${GREEN}依赖安装完成。${NC}"
}

# --- 主逻辑 ---

# 将所有输出重定向到日志文件和屏幕
exec &> >(tee -a "${LOG_FILE}")
exec 2>&1

echo "--- Reality 检测脚本开始执行 ---"
date

# 检查是否以root用户运行
if [ "$(id -u)" -ne 0 ]; then
   error_exit "此脚本需要以 root 权限运行。"
fi

# 注册清理函数，在脚本退出时执行
trap cleanup EXIT

install_dependencies

log "${GREEN}--- 步骤 2: 获取本机公网IP ---${NC}"
My_Ip=$(curl -s https://api.ipify.org)
if [ -z "${My_Ip}" ]; then
    error_exit "无法获取服务器的公网IP地址。"
fi
log "本机公网IP: ${My_Ip}"
log "将使用本机公网IP作为检测目标。"
Reality_Ip="${My_Ip}"

log "${GREEN}--- 步骤 3: 下载并准备 RealiTLScanner ---${NC}"
wget -q --show-progress -O "${REALI_TL_SCANNER_BIN}" "${REALI_TL_SCANNER_URL}"
chmod +x "${REALI_TL_SCANNER_BIN}"

log "${GREEN}--- 步骤 4: 运行 RealiTLScanner (最大执行时间3分钟) ---${NC}"
log "正在扫描本机 ${Reality_Ip}:443 ..."
# 该指令，设置一个执行最大时间为3m
# My_Ip为服务器的公网IP地址
timeout 3m ./"${REALI_TL_SCANNER_BIN}" -addr "${My_Ip}" -port 443 -thread 100 -timeout 5 -out "${Reality_Ip}.csv" || log "${YELLOW}RealiTLScanner 运行超时或被中断，这可能是正常的。${NC}"

log "${GREEN}--- 步骤 5: 下载并准备 RealityChecker (根据系统架构) ---${NC}"
# 根据自己的系统架构下载相对应的版本
ARCH=$(uname -m)
REALITY_CHECKER_URL=""
if [ "$ARCH" = "x86_64" ]; then
    log "检测到系统架构为 x86_64 (amd64)，下载对应版本。"
    REALITY_CHECKER_URL="https://github.com/V2RaySSR/RealityChecker/releases/latest/download/reality-checker-linux-amd64.zip"
    wget -q --show-progress "${REALITY_CHECKER_URL}"
    unzip -o reality-checker-linux-amd64.zip
elif [ "$ARCH" = "aarch64" ]; then
    log "检测到系统架构为 aarch64 (arm64)，下载对应版本。"
    REALITY_CHECKER_URL="https://github.com/V2RaySSR/RealityChecker/releases/latest/download/reality-checker-linux-arm64.zip"
    wget -q --show-progress "${REALITY_CHECKER_URL}"
    unzip -o reality-checker-linux-arm64.zip
else
    error_exit "不支持的系统架构: $ARCH"
fi

chmod +x "${REALITY_CHECKER_BIN}"

log "${GREEN}--- 步骤 6: 运行 RealityChecker 并保存结果 ---${NC}"
# 开始检测 并将该检测结果保存到一个文件中以便查看
./"${REALITY_CHECKER_BIN}" csv "${Reality_Ip}.csv"

log "${GREEN}--- 检测完成 ---${NC}"
log "详细日志请查看: ${LOG_FILE}"
log "扫描结果CSV文件: ${Reality_Ip}.csv"