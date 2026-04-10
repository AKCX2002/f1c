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

set -euo pipefail
set -x

# 保存脚本启动时的工作目录，以便函数内部切换目录后能返回
ORIGINAL_PWD="$(pwd)"

##############################################################################
# 全局变量定义
##############################################################################

TOOLS_DIR="${PWD}/tools"
OPENOCD_DIR="${TOOLS_DIR}/openocd-code"
BUILD_DIR="${PWD}/build"
OUTPUT_DIR="${PWD}/output"
PROGRAM_LIB_ROOT="${PWD}/lib/openocd"

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
    
    local tools=("git" "make" "gcc" "autoconf" "automake" "libtool" "pkg-config")
    
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
            zip \
            libjim-dev \
            libjaylink-dev
        # 检查 jimtcl 是否可用：优先通过 pkg-config，再检查常见头文件路径
        if pkg-config --exists jimtcl; then
            echo "✓ 已通过 pkg-config 检测到 jimtcl"
        elif [ -f /usr/include/jim.h ] || [ -f /usr/local/include/jim.h ] || [ -f /usr/include/jimtcl/jim.h ]; then
            echo "✓ 在系统头文件中检测到 jim.h（jimtcl 可用）"
        else
            echo "⚠ 未检测到 jimtcl（pkg-config/jim.h 均失败）。继续构建，但 configure 可能会失败。"
            echo "如果 CI 环境缺少 jimtcl，请在运行器上安装 libjim-dev 或从源码构建 jimtcl。"
            # 不在此处直接退出；让 configure 阶段显示错误以便更具体的调试信息
        fi
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
            hidapi \
            jimtcl
        
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
    local msystem_name="${MSYSTEM:-MINGW64}"
    local msys_pkg_prefix="mingw-w64-x86_64"

    if [ "${msystem_name}" = "UCRT64" ]; then
        msys_pkg_prefix="mingw-w64-ucrt-x86_64"
    fi

    if command -v pacman &> /dev/null; then
        echo "检测到 MSYS2(${msystem_name})，使用 pacman 安装依赖"
        pacman -S --noconfirm \
            autoconf \
            automake \
            libtool \
            ${msys_pkg_prefix}-gcc \
            ${msys_pkg_prefix}-make \
            ${msys_pkg_prefix}-pkgconf \
            ${msys_pkg_prefix}-libusb \
            ${msys_pkg_prefix}-libftdi \
            ${msys_pkg_prefix}-hidapi \
            zip

        # ---------------------------------------------------------------
        # 安装系统 jimtcl 包（关键修复）
        # 问题：jimtcl 内部 configure.gnu 在 MSYS2/UCRT64 上编译 bootstrap
        # 二进制时产生 jimsh0.exe，但随后尝试执行 ./jimsh0（无 .exe 扩展名）
        # 导致报告 "No working C compiler found"，实为 .exe 后缀问题。
        # 解决方案：优先安装系统 jimtcl 包并使用 --disable-internal-jimtcl。
        # ---------------------------------------------------------------
        if pacman -S --noconfirm --needed ${msys_pkg_prefix}-jimtcl 2>/dev/null; then
            echo "✓ 安装系统 jimtcl (${msys_pkg_prefix}-jimtcl)，将跳过内部 jimtcl 构建"
        else
            echo "⚠ ${msys_pkg_prefix}-jimtcl 不可用，将尝试内部 jimtcl（可能遇到 .exe 扩展名问题）"
        fi

        # capstone 为可选功能，部分镜像可能没有对应包，安装失败不阻断主构建
        if ! pacman -S --noconfirm --needed ${msys_pkg_prefix}-capstone; then
            echo "⚠ 未安装 ${msys_pkg_prefix}-capstone（可选），将继续构建"
        fi
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
        git clone --recurse-submodules https://git.code.sf.net/p/openocd/code "${OPENOCD_DIR}"
    else
        echo "OpenOCD 仓库已存在，更新到最新版本..."
    fi
    
    cd "${OPENOCD_DIR}"
    
    git checkout master
    git pull origin master
    
    # 确保所有子模块（特别是 jimtcl）都已正确初始化和更新
    echo "初始化和更新 git submodules..."
    git submodule init
    git submodule update --recursive
    
    local git_short_hash
    local git_commit_date
    local git_commit_message

    git_short_hash=$(git rev-parse --short HEAD)
    git_commit_date=$(git log -1 --format=%cd --date=short)
    git_commit_message=$(git log -1 --format=%s)
    
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

    # MSYS2/MINGW64 下，OpenOCD 的 jimtcl 子配置有时不会自动继承可用编译器。
    # 显式导出工具链（使用完整路径），避免 configure.gnu 误判"找不到可工作的 C compiler"。
    if [ "${PLATFORM}" = "windows" ]; then
        local tool_prefix="/mingw64/bin"
        if [ "${MSYSTEM:-MINGW64}" = "UCRT64" ]; then
            tool_prefix="/ucrt64/bin"
        fi

        export CC="${tool_prefix}/gcc"
        export CXX="${tool_prefix}/g++"
        export AR="${tool_prefix}/ar"
        export RANLIB="${tool_prefix}/ranlib"
        export STRIP="${tool_prefix}/strip"
        export NM="${tool_prefix}/nm"
        export PKG_CONFIG="${tool_prefix}/pkg-config"
        export PATH="${tool_prefix}:${PATH}"
        echo "Windows toolchain (${MSYSTEM:-MINGW64}): CC=${CC}, CXX=${CXX}, PKG_CONFIG=${PKG_CONFIG}"
    fi
    
    # 确保 jimtcl 子模块已正确初始化
    if [ ! -f "jimtcl/configure" ]; then
        echo "确保 jimtcl 子模块已正确检出..."
        git submodule sync --recursive
        git submodule update --init --recursive --force
    fi
    
    # -----------------------------------------------------------------------
    # 确定 jimtcl 链接策略（Windows 特有）
    # jimtcl configure.gnu 在 MSYS2 上存在 .exe 扩展名 bug：
    #   gcc 生成 jimsh0.exe → 脚本执行 ./jimsh0 → 找不到文件 → configure 失败
    # 优先使用系统包（${msys_pkg_prefix}-jimtcl），若已安装则使用
    # --disable-internal-jimtcl；否则回退至内部构建并额外设置 cc 符号链接。
    # -----------------------------------------------------------------------
    local JIMTCL_OPT="--enable-internal-jimtcl"
    if [ "${PLATFORM}" = "windows" ]; then
        local _pkgcfg="${PKG_CONFIG:-pkg-config}"
        if "${_pkgcfg}" --exists jimtcl 2>/dev/null; then
            JIMTCL_OPT="--disable-internal-jimtcl"
            echo "✓ 检测到系统 jimtcl，使用 --disable-internal-jimtcl"
        else
            echo "⚠ 未检测到系统 jimtcl，回退至 --enable-internal-jimtcl"
            # 创建 cc → gcc 的包装器，解决 jimtcl configure.gnu 仅查找 cc/gcc 的问题
            local _tmp_cc_dir
            _tmp_cc_dir=$(mktemp -d)
            printf '#!/bin/sh\nexec "%s" "$@"\n' "${CC}" > "${_tmp_cc_dir}/cc"
            printf '#!/bin/sh\nexec "%s" "$@"\n' "${CC}" > "${_tmp_cc_dir}/gcc"
            chmod +x "${_tmp_cc_dir}/cc" "${_tmp_cc_dir}/gcc"
            export PATH="${_tmp_cc_dir}:${PATH}"
            echo "  已创建 cc/gcc 包装器：${_tmp_cc_dir}"
        fi
    fi

    echo "运行 bootstrap..."
    ./bootstrap
    
    echo "配置编译选项..."
    local configure_opts="--prefix=${BUILD_DIR} --disable-werror"
    # 检查 libjaylink（SEGGER J-Link 支持）是否可用；如果不可用则在 configure 时禁用 jlink
    ENABLE_JLINK="--enable-jlink"
    if ! pkg-config --exists libjaylink-0.2 2>/dev/null; then
        if [ -f /usr/include/jaylink.h ] || [ -f /usr/local/include/jaylink.h ] || [ -f /opt/homebrew/include/jaylink.h ]; then
            echo "✓ 在系统头文件中检测到 libjaylink（headers 存在）"
        else
            echo "⚠ libjaylink 未检测到，构建将禁用 J-Link 支持以避免 configure 失败"
            ENABLE_JLINK=""
        fi
    else
        echo "✓ 通过 pkg-config 检测到 libjaylink"
    fi
    
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
        ${ENABLE_JLINK} \
        --enable-cmsis-dap \
        --enable-hidapi-libusb \
        ${JIMTCL_OPT}
    
    cpu_count() {
        if command -v nproc >/dev/null 2>&1; then
            nproc
        elif command -v sysctl >/dev/null 2>&1; then
            sysctl -n hw.ncpu
        else
            echo 2
        fi
    }

    if [ "${PLATFORM}" = "macos" ]; then
        echo "开始编译 (macOS 使用单线程编译以避免并行编译问题)..."
        make clean
        make
    else
        echo "开始编译 (使用 $(cpu_count) 个线程)..."
        make clean
        make -j"$(cpu_count)"
    fi
    
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

save_version_info() {
    echo "=== 保存版本信息 ==="
    
    cd "${OPENOCD_DIR}"
    
    git_short_hash=$(git rev-parse --short HEAD)
    git_full_hash=$(git rev-parse HEAD)
    git_commit_date=$(git log -1 --format=%cd --date=short)
    
    cat > "${OUTPUT_DIR}/version_info.txt" << VERSION_INFO
# OpenOCD 构建版本信息
# 生成时间: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

OPENOCD_GIT_SHORT_HASH=${git_short_hash}
OPENOCD_GIT_FULL_HASH=${git_full_hash}
OPENOCD_BRANCH=master
OPENOCD_COMMIT_DATE=${git_commit_date}
OPENOCD_REPOSITORY=https://git.code.sf.net/p/openocd/code

BUILD_VERSION=${BUILD_VERSION}
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_PLATFORM=${PLATFORM}
BUILD_ARCH=${ARCH_NAME}
VERSION_INFO
    
    # 返回到脚本启动时的工作目录
    cd "${ORIGINAL_PWD}"
    
    echo "✓ 版本信息已保存到 ${OUTPUT_DIR}/version_info.txt"
    echo ""
}

##############################################################################
# 函数：打包构建产物
##############################################################################

package_build_artifacts() {
    echo "=== 打包构建产物 ==="
    
    mkdir -p "${PACKAGE_PATH}"
    
    if [ "${PLATFORM}" = "windows" ]; then
        package_windows_build
    else
        package_unix_build
    fi
    
    cp "${OUTPUT_DIR}/version_info.txt" "${PACKAGE_PATH}/"
    create_readme_file
    create_archive
    sync_to_program_lib
    
    echo "✓ 打包完成"
    echo ""
}

##############################################################################
# 函数：同步构建结果到程序 lib 目录
##############################################################################

sync_to_program_lib() {
    echo "=== 同步构建结果到程序 lib 库 ==="

    local target_lib_dir="${PROGRAM_LIB_ROOT}/${PLATFORM}-${ARCH_NAME}"
    local archive_ext="tar.gz"
    if [ "${PLATFORM}" = "windows" ]; then
        archive_ext="zip"
    fi

    mkdir -p "${target_lib_dir}"
    rm -rf "${target_lib_dir:?}/"*

    cp -r "${PACKAGE_PATH}/"* "${target_lib_dir}/"
    cp "${OUTPUT_DIR}/${PACKAGE_NAME}.${archive_ext}" "${target_lib_dir}/"

    cat > "${target_lib_dir}/BUILD_INFO.txt" << BUILD_INFO
PACKAGE_NAME=${PACKAGE_NAME}
PLATFORM=${PLATFORM}
ARCH=${ARCH_NAME}
BUILD_VERSION=${BUILD_VERSION}
SYNCED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_INFO

    echo "✓ 已同步到 ${target_lib_dir}"
    echo ""
}

##############################################################################
# 函数：打包 Unix 系统（Linux/macOS）构建产物
##############################################################################

package_unix_build() {
    if [ -f "${BUILD_DIR}/bin/openocd" ]; then
        cp "${BUILD_DIR}/bin/openocd" "${PACKAGE_PATH}/"
        chmod +x "${PACKAGE_PATH}/openocd"
        echo "✓ 复制 openocd 可执行文件"
    elif [ -f "${OPENOCD_DIR}/src/openocd" ]; then
        cp "${OPENOCD_DIR}/src/openocd" "${PACKAGE_PATH}/"
        chmod +x "${PACKAGE_PATH}/openocd"
        echo "✓ 复制 openocd 可执行文件 (从源码目录)"
    fi
    
    if [ -d "${BUILD_DIR}/share/openocd" ]; then
        mkdir -p "${PACKAGE_PATH}/share"
        cp -r "${BUILD_DIR}/share/openocd" "${PACKAGE_PATH}/share/"
        echo "✓ 复制 OpenOCD 配置文件"
    elif [ -d "${OPENOCD_DIR}/tcl" ]; then
        mkdir -p "${PACKAGE_PATH}/share/openocd"
        cp -r "${OPENOCD_DIR}/tcl" "${PACKAGE_PATH}/share/openocd/scripts"
        echo "✓ 复制 OpenOCD 配置文件 (从源码目录)"
    fi
}

##############################################################################
# 函数：打包 Windows 系统构建产物
##############################################################################

package_windows_build() {
    if [ -f "${BUILD_DIR}/bin/openocd.exe" ]; then
        cp "${BUILD_DIR}/bin/openocd.exe" "${PACKAGE_PATH}/"
        echo "✓ 复制 openocd.exe 可执行文件"
    else
        cp "${OPENOCD_DIR}/src/openocd.exe" "${PACKAGE_PATH}/" 2>/dev/null || \
            cp "${OPENOCD_DIR}/src/openocd" "${PACKAGE_PATH}/"
        echo "✓ 复制 openocd 可执行文件 (从源码目录)"
    fi
    
    if [ -d "${BUILD_DIR}/share/openocd" ]; then
        mkdir -p "${PACKAGE_PATH}/share"
        cp -r "${BUILD_DIR}/share/openocd" "${PACKAGE_PATH}/share/"
        echo "✓ 复制 OpenOCD 配置文件"
    elif [ -d "${OPENOCD_DIR}/tcl" ]; then
        mkdir -p "${PACKAGE_PATH}/share/openocd"
        cp -r "${OPENOCD_DIR}/tcl" "${PACKAGE_PATH}/share/openocd/scripts"
        echo "✓ 复制 OpenOCD 配置文件 (从源码目录)"
    fi
}

##############################################################################
# 函数：创建 README 文件
##############################################################################

create_readme_file() {
    cat > "${PACKAGE_PATH}/README.txt" << 'README'
=======================================================================
OpenOCD 二进制分发包
=======================================================================

本目录包含预编译的 OpenOCD 可执行文件及相关配置文件。

OpenOCD (Open On-Chip Debugger) 提供片上编程和调试支持，具有
JTAG 接口和 TAP 支持的分层架构，包括：

- (X)SVF 播放，支持自动化边界扫描和 FPGA/CPLD 编程
- 调试目标支持（如 ARM、MIPS）：单步执行、断点/观察点、gprof 分析等
- Flash 芯片驱动（如 CFI、NAND、内部 Flash）
- 嵌入式 TCL 解释器，便于脚本编写

有几种网络接口可用于与 OpenOCD 交互：telnet、TCL 和 GDB。
GDB 服务器使 OpenOCD 可以作为使用 GNU GDB 程序（以及其他使用
GDB 协议的程序，如 IDA Pro）的嵌入式系统源代码级调试的"远程目标"。

目录结构：
  openocd[.exe]      - OpenOCD 主程序
  share/openocd/      - 配置文件和脚本目录

快速开始（Quickstart）：
  如果您有一块流行的开发板，只需使用其配置启动 OpenOCD，例如：
    openocd -f board/stm32f4discovery.cfg

  如果您连接特定的适配器和目标，需要同时加载 jtag 接口和目标配置，例如：
    openocd -f interface/ftdi/jtagkey2.cfg -c "transport select jtag" \
            -f target/ti_calypso.cfg

    openocd -f interface/stlink.cfg -c "transport select hla_swd" \
            -f target/stm32l0.cfg

  OpenOCD 启动后，使用以下命令连接 GDB：
    (gdb) target extended-remote localhost:3333

OpenOCD 文档：
  除了源代码中的文档外，最新的手册可以在以下网址在线查看：

  OpenOCD 用户指南：
    http://openocd.org/doc/html/index.html

  OpenOCD 开发者手册：
    http://openocd.org/doc/doxygen/html/index.html

  这些反映了最新的开发版本。

更多信息请访问：
  - OpenOCD 官方网站：https://openocd.org/
  - SourceForge 项目页面：https://sourceforge.net/projects/openocd/
  - 主 Git 仓库：git://git.code.sf.net/p/openocd/code
  - Gitweb 界面：http://repo.or.cz/w/openocd.git

  有关更多信息，请参考这些文档或通过订阅 OpenOCD 开发者邮件列表
  联系开发者：openocd-devel@lists.sourceforge.net

从 GIT 获取 OpenOCD：
  您可以使用您选择的 GIT 客户端从主仓库下载当前的 GIT 版本：
    git://git.code.sf.net/p/openocd/code

  您可能更喜欢使用镜像：
    http://repo.or.cz/r/openocd.git
    git://repo.or.cz/openocd.git

  使用 GIT 命令行客户端，您可以使用以下命令设置当前仓库的本地副本
  （确保当前目录中没有名为"openocd"的目录）：
    git clone git://git.code.sf.net/p/openocd/code openocd

  然后您可以随时使用以下命令更新：
    git pull

OpenOCD 依赖：
  构建 OpenOCD 当前需要 GCC 或 Clang。

  您还需要：
  - make
  - libtool
  - pkg-config >= 0.23 或 pkgconf

  此外，从 git 构建时需要：
  - autoconf >= 2.69
  - automake >= 1.14
  - texinfo >= 5.0

  可选的基于 USB 的适配器驱动程序需要 libusb-1.0。
  可选的 USB-Blaster、ASIX Presto 和 OpenJTAG 接口适配器驱动程序需要 libftdi。
  可选的 CMSIS-DAP 适配器驱动程序需要 HIDAPI 库。

编译 OpenOCD：
  要构建 OpenOCD，请使用以下命令序列：
    ./bootstrap (从 git 仓库构建时)
    ./configure [options]
    make
    sudo make install

许可证：
  OpenOCD 采用 GPLv2 许可证发布。
=======================================================================
README
    
    echo "✓ 创建 README.txt"
}

##############################################################################
# 函数：创建压缩归档文件
##############################################################################

create_archive() {
    cd "${OUTPUT_DIR}"
    
    if [ "${PLATFORM}" = "windows" ]; then
        archive_file="${PACKAGE_NAME}.zip"
        echo "创建 ZIP 压缩包..."
        zip -r -q "${archive_file}" "${PACKAGE_NAME}"
    else
        archive_file="${PACKAGE_NAME}.tar.gz"
        echo "创建 tar.gz 压缩包..."
        tar -czf "${archive_file}" "${PACKAGE_NAME}"
    fi
    
    if command -v sha256sum &> /dev/null; then
        sha256sum "${archive_file}" > "${archive_file}.sha256"
        echo "✓ 计算 SHA256 校验和"
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "${archive_file}" > "${archive_file}.sha256"
        echo "✓ 计算 SHA256 校验和"
    fi
    
    echo "✓ 压缩包已创建: ${archive_file}"
    
    # 返回到脚本启动时的工作目录
    cd "${ORIGINAL_PWD}"
}

##############################################################################
# 函数：验证构建产物
##############################################################################

validate_build_artifacts() {
    echo "=== 验证构建产物 ==="
    
    validation_passed=true
    openocd_executable=""
    
    if [ "${PLATFORM}" = "windows" ]; then
        openocd_executable="openocd.exe"
    else
        openocd_executable="openocd"
    fi
    
    if [ -f "${PACKAGE_PATH}/${openocd_executable}" ]; then
        echo "✓ 找到 ${openocd_executable}"
        
        if [ "${PLATFORM}" != "windows" ]; then
            if "${PACKAGE_PATH}/${openocd_executable}" --version &> /dev/null; then
                echo "✓ ${openocd_executable} 可正常执行"
            else
                echo "⚠ 警告：${openocd_executable} 执行失败（可能缺少运行时依赖）"
            fi
        fi
    else
        echo "✗ 错误：找不到 ${openocd_executable}"
        validation_passed=false
    fi
    
    if [ -d "${PACKAGE_PATH}/share/openocd/scripts" ] || [ -d "${PACKAGE_PATH}/share/openocd" ]; then
        echo "✓ 找到 OpenOCD 配置文件"
    else
        echo "⚠ 警告：未找到 OpenOCD 配置文件"
    fi
    
    if [ -f "${PACKAGE_PATH}/version_info.txt" ]; then
        echo "✓ 找到版本信息文件"
    else
        echo "⚠ 警告：未找到版本信息文件"
    fi
    
    echo ""
    if [ "${validation_passed}" = true ]; then
        echo "✓ 构建产物验证通过"
    else
        echo "✗ 构建产物验证失败"
        exit 1
    fi
    echo ""
}

##############################################################################
# 函数：打印构建完成信息
##############################################################################

print_build_summary() {
    echo "========================================="
    echo "  OpenOCD 构建完成！"
    echo "========================================="
    echo ""
    echo "构建产物位置："
    echo "  ${OUTPUT_DIR}/"
    echo ""
    echo "可用的文件："
    
    cd "${OUTPUT_DIR}"
    for file in *; do
        if [ -f "${file}" ]; then
            file_size=$(du -h "${file}" | cut -f1)
            echo "  - ${file} (${file_size})"
        fi
    done
    # 返回到脚本启动时的工作目录
    cd "${ORIGINAL_PWD}"
    
    echo ""
    echo "========================================="
}

##############################################################################
# 主函数：执行完整的构建流程
##############################################################################

main() {
    echo ""
    echo "╔══════════════════════════════════════╗"
    echo "║     OpenOCD 自动化构建脚本            ║"
    echo "╚══════════════════════════════════════╝"
    echo ""
    
    print_build_config
    create_directories
    check_build_environment
    install_platform_dependencies
    fetch_openocd_source
    build_openocd
    save_version_info
    package_build_artifacts
    validate_build_artifacts
    print_build_summary
}

main