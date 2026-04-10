#!/bin/bash
##############################################################################
# OpenOCD 自动化构建脚本
# 功能：从 OpenOCD 官方 SourceForge 仓库克隆最新代码并编译
# 支持平台：Linux、macOS、Windows
# 官方文档：
#   - https://openocd.org/doc-release/README
#   - https://openocd.org/doc-release/README.macOS
#   - https://openocd.org/doc-release/README.Windows
# 作者：OpenOCD-GUI 项目团队
# 版本：2.1
##############################################################################

set -e
set -o pipefail

# 保存脚本启动时的工作目录，以便函数内部切换目录后能返回
ORIGINAL_PWD="$(pwd)"

##############################################################################
# 全局变量定义
##############################################################################

TOOLS_DIR="${PWD}/tools"
OPENOCD_DIR="${TOOLS_DIR}/openocd-code"
BUILD_DIR="${PWD}/build"
OUTPUT_DIR="${PWD}/output"

BUILD_VERSION=${BUILD_VERSION:-$(date +%Y%m%d)}

##############################################################################
# 平台检测与标准化
##############################################################################

OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
    Linux*)
        PLATFORM="linux"
        ;;
    Darwin*)
        PLATFORM="macos"
        ;;
    MINGW*|CYGWIN*|MSYS*)
        PLATFORM="windows"
        ;;
    *)
        echo "错误：不支持的操作系统类型 - ${OS}"
        exit 1
        ;;
esac

case "${ARCH}" in
    x86_64|amd64)
        ARCH_NAME="x86_64"
        ;;
    arm64|aarch64)
        ARCH_NAME="arm64"
        ;;
    *)
        ARCH_NAME="${ARCH}"
        ;;
esac

PACKAGE_NAME="openocd-${PLATFORM}-${ARCH_NAME}-${BUILD_VERSION}"
PACKAGE_PATH="${OUTPUT_DIR}/${PACKAGE_NAME}"

##############################################################################
# 函数：打印构建配置信息
##############################################################################

print_build_config() {
    echo "========================================="
    echo "  OpenOCD 自动化构建配置"
    echo "========================================="
    echo "  操作系统: ${OS} (${PLATFORM})"
    echo "  硬件架构: ${ARCH} (${ARCH_NAME})"
    echo "  构建版本: ${BUILD_VERSION}"
    echo "  包名称: ${PACKAGE_NAME}"
    echo "  源代码目录: ${OPENOCD_DIR}"
    echo "  编译目录: ${BUILD_DIR}"
    echo "  输出目录: ${OUTPUT_DIR}"
    echo "========================================="
    echo ""
}

##############################################################################
# 函数：创建必要的目录结构
##############################################################################

create_directories() {
    echo "=== 创建目录结构 ==="
    mkdir -p "${TOOLS_DIR}"
    mkdir -p "${BUILD_DIR}"
    mkdir -p "${OUTPUT_DIR}"
    echo "✓ 目录结构创建完成"
    echo ""
}

##############################################################################
# 函数：检查构建环境
##############################################################################

check_build_environment() {
    echo "=== 检查构建环境 ==="
    
    local tools=("git" "make" "gcc" "autoconf" "automake" "libtool" "libtoolize" "glibtool" "pkg-config")
    
    for tool in "${tools[@]}"; do
        if command -v "${tool}" &> /dev/null; then
            echo "✓ 找到 ${tool}"
        fi
    done
    
    echo "✓ 环境检查完成"
    echo ""
}

##############################################################################
# 函数：安装平台相关的依赖库
##############################################################################

install_platform_dependencies() {
    echo "=== 安装平台依赖库 ==="
    
    case "${PLATFORM}" in
        linux)
            install_linux_dependencies
            ;;
        macos)
            install_macos_dependencies
            ;;
        windows)
            install_windows_dependencies
            ;;
    esac
    
    echo "✓ 依赖库安装完成"
    echo ""
}

##############################################################################
# 函数：安装 Linux 平台依赖
##############################################################################

install_linux_dependencies() {
    if command -v apt-get &> /dev/null; then
        echo "检测到 Debian/Ubuntu 系统，使用 apt-get 安装依赖"
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            git \
            autoconf \
            automake \
            libtool \
            pkg-config \
            libusb-1.0-0-dev \
            libftdi-dev \
            libftdi1-dev \
            libhidapi-dev \
            zlib1g-dev \
            zip
    elif command -v yum &> /dev/null; then
        echo "检测到 CentOS/RHEL 系统，使用 yum 安装依赖"
        sudo yum install -y \
            gcc \
            make \
            git \
            autoconf \
            automake \
            libtool \
            pkgconfig \
            libusb1-devel \
            libftdi-devel \
            hidapi-devel \
            zlib-devel
    fi
}

##############################################################################
# 函数：安装 macOS 平台依赖
##############################################################################

install_macos_dependencies() {
    if command -v brew &> /dev/null; then
        echo "检测到 Homebrew，使用 brew 安装依赖"
        brew install \
            autoconf \
            automake \
            libtool \
            pkg-config \
            libusb \
            libftdi \
            hidapi
        
        if ! command -v texinfo &> /dev/null; then
            echo "安装 texinfo (OpenOCD 文档构建需要)"
            brew install texinfo
            export PATH="/usr/local/opt/texinfo/bin:$PATH"
        fi
    else
        echo "警告：未找到 Homebrew，请手动安装依赖库或先安装 Homebrew"
        echo "Homebrew 安装地址：https://brew.sh/"
    fi
}

##############################################################################
# 函数：安装 Windows 平台依赖
##############################################################################

install_windows_dependencies() {
    if command -v pacman &> /dev/null; then
        echo "检测到 MSYS2，使用 pacman 安装依赖"
        pacman -S --noconfirm \
            mingw-w64-x86_64-toolchain \
            mingw-w64-x86_64-autotools \
            mingw-w64-x86_64-libusb \
            mingw-w64-x86_64-libftdi \
            mingw-w64-x86_64-hidapi \
            mingw-w64-x86_64-pkg-config \
            zip
    else
        echo "警告：请确保已在 Windows 上安装 MSYS2 或 MinGW 及必要的依赖库"
        echo "MSYS2 安装地址：https://www.msys2.org/"
    fi
}

##############################################################################
# 函数：获取 OpenOCD 源代码
##############################################################################

fetch_openocd_source() {
    echo "=== 获取 OpenOCD 源代码 ==="
    
    if [ ! -d "${OPENOCD_DIR}" ]; then
        echo "从 SourceForge 克隆 OpenOCD 仓库..."
        git clone https://git.code.sf.net/p/openocd/code "${OPENOCD_DIR}"
    else
        echo "OpenOCD 仓库已存在，更新到最新版本..."
    fi
    
    cd "${OPENOCD_DIR}"
    
    git checkout master
    git pull origin master
    
    local git_short_hash=$(git rev-parse --short HEAD)
    local git_commit_date=$(git log -1 --format=%cd --date=short)
    local git_commit_message=$(git log -1 --format=%s)
    
    echo "✓ 当前代码版本: ${git_short_hash}"
    echo "✓ 提交日期: ${git_commit_date}"
    echo "✓ 提交信息: ${git_commit_message}"
    
    # 返回到脚本启动时的工作目录
    cd "${ORIGINAL_PWD}"
    echo ""
}

##############################################################################
# 函数：编译 OpenOCD
##############################################################################

build_openocd() {
    echo "=== 编译 OpenOCD ==="
    
    cd "${OPENOCD_DIR}"
    
    echo "运行 bootstrap..."
    ./bootstrap
    
    echo "配置编译选项..."
    local configure_opts="--prefix=${BUILD_DIR} --disable-werror"
    
    if [ "${PLATFORM}" = "macos" ]; then
        if [ -d "/usr/local/opt/libusb" ]; then
            export LIBUSB_CFLAGS="-I/usr/local/opt/libusb/include"
            export LIBUSB_LIBS="-L/usr/local/opt/libusb/lib -lusb-1.0"
        fi
        if [ -d "/usr/local/opt/libftdi" ]; then
            export LIBFTDI_CFLAGS="-I/usr/local/opt/libftdi/include"
            export LIBFTDI_LIBS="-L/usr/local/opt/libftdi/lib -lftdi1"
        fi
        if [ -d "/opt/local" ]; then
            export LDFLAGS="-L/opt/local/lib"
            export CPPFLAGS="-I/opt/local/include"
        fi
    fi
    
    ./configure ${configure_opts} \
        --enable-dummy \
        --enable-usb-blaster \
        --enable-ftdi \
        --enable-stlink \
        --enable-jlink \
        --enable-cmsis-dap \
        --enable-hidapi-libusb
    
    echo "开始编译 (使用 $(nproc) 个线程)..."
    make clean
    make -j$(nproc)
    
    echo "安装编译产物..."
    make install
    
    # 返回到脚本启动时的工作目录
    cd "${ORIGINAL_PWD}"
    echo "✓ OpenOCD 编译完成"
    echo ""
}

##############################################################################
# 函数：保存构建版本信息
##############################################################################

{