# f1c GUI 工具

这是一个基于 Tkinter 的图形界面，用于通过 `sunxi-fel`（SPI / Allwinner）或 `openocd`（AT32）向设备烧录固件、查看 SPI 信息及执行常用调试命令。

## **主要功能**

- 通过 `sunxi-fel` 写入 SPI flash（BOOT0 / LOGO / EXEC 等）。
- 通过 `openocd` 向 AT32 设备写入固件（支持 `.bin`、`.hex`、`.elf`）。
- Intel HEX 文件地址自动识别（地址留空时可解析起始地址）。
- ELF 支持（openocd 模式下，ELF 可不填地址，openocd 将使用 ELF 内置段地址）。
- 提供“常用功能”下拉（如 device/version、spiflash-info、reset、flash erase 等）。
- sunxi 模式下提供“全片擦除（写 0xFF）”作为擦除替代方案（当本地 sunxi-fel 版本没有 spiflash-erase 命令时）。

## 注意与限制

- 本工具为 GUI 前端，实际烧录依赖系统上可执行的 `sunxi-fel` 与/或 `openocd`。
- 在 Windows 下推荐在 WSL/WSL2 的 Linux 环境中使用 `sunxi-fel`。
- `sunxi-fel` 的全片擦除这里采用“写 0xFF”分块写入实现，速度较慢，请谨慎使用并确保电源稳定。
- HEX 自动识别基于解析 Intel HEX 格式；若格式不合规可能无法识别，请手动输入地址或转换为 bin。
- ELF 支持目前仅在 openocd 模式使用；若想用 ELF 写入 SPI（sunxi），请先用 `objcopy` 转为二进制：

  ```bash
  arm-none-eabi-objcopy -O binary input.elf output.bin
  ```

## 快速开始

1. 安装依赖（至少需要 Python + Tkinter）：

```bash
sudo apt update
sudo apt install -y python3 python3-tk
# 安装 openocd / sunxi-fel（按需）
sudo apt install -y openocd sunxi-tools
# 或自行编译并把可执行放到 PATH 或项目 lib 下
```

1. 运行 GUI：

```bash
python3 f1c_gui.py
```

1. 在程序目录选择 `bin/`（或你放固件的目录），点击“刷新”，界面会自动列出 `.bin/.hex/.elf` 文件。

## 使用建议

- 如果使用 `sunxi-fel` 模式，请确保选择的是 `.bin` 文件（界面会只在 BOOT0/EXEC/LOGO 下列出 `.bin`，避免误操作）。
- 如果使用 `openocd` 模式，`.hex` 和 `.elf` 可不填写地址（启用“HEX 自动识别地址”或依赖 ELF 内置地址）。模板 `program {file} {addr} verify reset; exit` 可按需修改，例如 `program {file} verify reset; exit`（ELF 无需 {addr}）。

## 故障排查

- 启动时报错提示缺少 Tkinter：请按提示安装 `python3-tk`。
- 报错找不到 `sunxi-fel` 或 `openocd`：请把可执行加入 `PATH`，或在界面中手动指定本地可执行路径。
- HEX 地址无法识别：检查 HEX 文件是否为标准 Intel HEX，或使用 objcopy 转换后再烧录。

## 文件

- 主脚本：`f1c_gui.py`

