# OpenOCD-GUI

**版本：0.0.1alpha**

[![Build OpenOCD Tools](https://github.com/yourusername/openocd-gui/actions/workflows/build-tools.yml/badge.svg)](https://github.com/yourusername/openocd-gui/actions/workflows/build-tools.yml)

## 项目概述

OpenOCD-GUI 是一个跨平台的固件下载工具，重点支持通过 OpenOCD 对各种 32 位 MCU 进行固件烧录和调试。

### 支持的平台
- Linux
- Windows
- macOS

### 支持的设备
- STM32 系列
- AT32 系列
- GD32 系列
- 其他支持 OpenOCD 的 MCU

## 核心功能

- **设备管理**：支持多种设备类型的检测和管理
- **固件管理**：支持 .bin、.hex、.elf 等多种固件格式
- **烧录工具**：集成 OpenOCD 烧录工具
- **操作功能**：设备检测、固件烧录、全片擦除、复位等
- **用户界面**：边栏式布局，提供直观的操作界面
- **日志系统**：实时显示操作日志和进度

## 技术架构

### 前端
- Flutter 框架，跨平台 UI
- Dart 语言，处理核心逻辑

### 后端
- 集成 OpenOCD 工具
- 自动工具拉取和编译
- 可扩展的设备驱动系统

## 安装和使用

### 前置依赖

#### 通用依赖
构建 OpenOCD 需要：
- GCC 或 Clang
- make
- libtool
- pkg-config >= 0.23 或 pkgconf

从 Git 仓库构建时还需要：
- autoconf >= 2.69
- automake >= 1.14
- texinfo >= 5.0

#### Linux (Debian/Ubuntu)
```bash
sudo apt install build-essential git autoconf automake libtool pkg-config \
  libusb-1.0-0-dev libftdi-dev libftdi1-dev libhidapi-dev zlib1g-dev
```

#### Linux (CentOS/RHEL)
```bash
sudo yum install gcc make git autoconf automake libtool pkgconfig \
  libusb1-devel libftdi-devel hidapi-devel zlib-devel
```

#### Windows
- 安装 MSYS2（推荐）或 MinGW-w64
- 使用 MSYS2 时，通过 pacman 安装依赖：
  ```bash
  pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-autotools \
    mingw-w64-x86_64-libusb mingw-w64-x86_64-libftdi \
    mingw-w64-x86_64-hidapi mingw-w64-x86_64-pkg-config zip
  ```

#### macOS
使用 Homebrew 安装依赖：
```bash
brew install autoconf automake libtool pkg-config libusb libftdi hidapi

# 如果需要构建文档，还需要：
brew install texinfo
export PATH="/usr/local/opt/texinfo/bin:$PATH"
```

### 构建工具

项目包含自动构建脚本，可自动拉取和编译 OpenOCD：

```bash
./build_tools.sh
```

### 运行应用

```bash
flutter run -d linux    # Linux
flutter run -d windows  # Windows
flutter run -d macos    # macOS
```

## 项目结构

```
openocd-gui/
├── lib/
│   ├── app.dart                # 应用入口
│   ├── main.dart              # 主入口
│   ├── pages/
│   │   ├── home_page.dart     # 主页面
│   │   └── settings_page.dart # 设置页面
│   ├── services/
│   │   ├── firmware_service.dart  # 固件服务
│   │   ├── device_service.dart    # 设备服务
│   │   └── tool_service.dart      # 工具服务
│   ├── models/
│   │   ├── device.dart       # 设备模型
│   │   └── firmware.dart     # 固件模型
│   └── widgets/
│       ├── sidebar.dart       # 侧边栏
│       ├── file_selector.dart # 文件选择器
│       └── log_viewer.dart    # 日志查看器
├── tools/
│   └── openocd/               # OpenOCD 源代码目录
├── .github/
│   └── workflows/
│       └── build-tools.yml    # GitHub Actions 配置
├── build_tools.sh             # 工具构建脚本
├── pubspec.yaml               # 项目配置
└── README.md                  # 本文件
```

## 核心功能使用

### 1. 设备选择

在侧边栏中选择设备类型（STM32、AT32、GD32 等）。

### 2. 固件选择

点击 "浏览..." 按钮选择固件文件，支持 .bin、.hex、.elf 等格式。

### 3. 烧录设置

- **地址**：设置烧录地址（对于 .hex 和 .elf 文件可自动识别）
- **验证**：选择是否验证烧录结果
- **复位**：选择烧录后是否复位设备

### 4. 执行操作

- **开始下载**：执行固件烧录
- **执行功能**：执行其他操作，如设备检测、全片擦除、复位等

## 工具自动构建

项目使用 GitHub Actions 自动构建各平台的 OpenOCD 工具：

- **Linux**：在 Ubuntu 环境中构建
- **Windows**：在 Windows 环境中构建
- **macOS**：在 macOS 环境中构建（支持 x86_64 和 arm64）

### 触发构建

1. **推送代码**：推送到 main 分支会自动触发构建
2. **手动触发**：在 GitHub Actions 页面手动运行工作流
3. **发布版本**：推送 `v*` 标签（如 `v0.0.1alpha`）会自动创建 Release

### 构建产物

每个构建产物包包含：
- OpenOCD 可执行文件
- 完整的 OpenOCD 配置脚本
- `version_info.txt`（版本和构建信息）
- `README.txt`（使用说明）
- 压缩包文件及其 SHA256 校验和

## OpenOCD 构建脚本说明

`build_tools.sh` 是一个自动化构建脚本，完全遵循 OpenOCD 官方文档的构建说明：

- **源代码仓库**：使用 OpenOCD 官方 SourceForge 仓库（`https://git.code.sf.net/p/openocd/code`）
- **跨平台支持**：Linux、macOS、Windows
- **自动依赖安装**：根据官方文档安装所有必需和可选依赖
- **完整的环境检查**：验证构建环境
- **详细的构建日志**：清晰的构建过程输出
- **自动打包和校验和**：生成带 SHA256 校验和的压缩包
- **构建产物验证**：确保构建完整性

### 官方 OpenOCD 文档参考

构建脚本基于以下官方文档：
- [OpenOCD README](https://openocd.org/doc-release/README)
- [OpenOCD macOS README](https://openocd.org/doc-release/README.macOS)
- [OpenOCD Windows README](https://openocd.org/doc-release/README.Windows)
- [OpenOCD 用户指南](http://openocd.org/doc/html/index.html)
- [OpenOCD 开发者手册](http://openocd.org/doc/doxygen/html/index.html)

### 使用方法

```bash
# 基本使用
./build_tools.sh

# 自定义构建版本
BUILD_VERSION=0.0.1alpha ./build_tools.sh
```

### OpenOCD 官方获取方式

您也可以直接从官方仓库获取 OpenOCD 源代码：

```bash
# 从主仓库克隆
git clone git://git.code.sf.net/p/openocd/code openocd-code

# 或使用镜像
git clone git://repo.or.cz/openocd.git openocd-code

# 更新代码
cd openocd-code
git pull
```

### OpenOCD 依赖说明

根据官方文档，构建 OpenOCD 需要：

**必需依赖**：
- GCC 或 Clang
- make
- libtool
- pkg-config >= 0.23 或 pkgconf

**从 Git 构建时需要**：
- autoconf >= 2.69
- automake >= 1.14
- texinfo >= 5.0

**可选依赖（适配器支持）**：
- libusb-1.0（基于 USB 的适配器）
- libftdi（USB-Blaster、ASIX Presto、OpenJTAG）
- HIDAPI（CMSIS-DAP）

## 故障排除

### 1. 工具未找到

如果应用提示找不到 OpenOCD 工具，请运行构建脚本：

```bash
./build_tools.sh
```

### 2. 设备未检测到

- 确保设备已正确连接
- 确保驱动程序已安装
- 尝试不同的 USB 端口

### 3. 烧录失败

- 检查固件文件是否正确
- 检查烧录地址是否正确
- 检查设备是否处于可烧录状态

## 版本历史

### 0.0.1alpha (2026-04-09)
- 初始版本发布
- 支持基本的 OpenOCD 集成
- 实现跨平台自动构建
- 添加 GitHub Actions CI/CD 流程

## 贡献

欢迎贡献代码和提出建议！请提交 Pull Request 或 Issue。

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 致谢

- OpenOCD 项目团队：https://openocd.org/
- Flutter 框架：https://flutter.dev/

## 联系方式

如有问题或建议，请通过 GitHub Issues 联系我们。
