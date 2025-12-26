#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading

import sys
try:
    import tkinter as tk
    from tkinter import messagebox
    from tkinter import ttk
    from tkinter import filedialog
    _TK_ERROR: Exception | None = None
except Exception as e:  # Tk 依赖缺失（常见：python3-tk / libtk8.6）
    tk = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    _TK_ERROR = e


BOOT0_ADDR = "0x0"
LOGO_ADDRS = ["0x6000", "0x36000", "0x65000", "0x71000", "0x77000"]
F1C_ADDR = "0x100000"
AT32_DEFAULT_ADDRS = ["0x08000000", "0x08002800"]


def script_dir() -> str:
    # 使用 pathlib 确保在 Windows 下也能正确解析文件路径
    return str(Path(__file__).resolve().parent)


def bin_dir() -> str:
    return str(Path(script_dir()) / "bin")


def require_tool(tool_name: str) -> None:
    if shutil.which(tool_name) is None:
        # 在 Windows 上通常没有可用的原生 sunxi-fel，提示使用 WSL
        if os.name == "nt":
            raise RuntimeError(
                f"未找到 {tool_name}（Windows 下通常不可用）。\n"
                "建议在 WSL/WSL2 的 Linux 环境中安装 sunxi-tools 并从 WSL 运行本程序，或在真实 Linux 机器上运行。"
            )
        raise RuntimeError(
            f"未找到 {tool_name}（请安装或加入 PATH）。\n"
            f"可参考：apt install sunxi-tools 或自行编译 sunxi-tools。"
        )


def list_bin_files(directory: str) -> list[str]:
    p = Path(directory or ".")
    if not p.exists() or not p.is_dir():
        return []
    files: list[str] = []
    exts = {".bin", ".hex", ".ihex", ".ihx", ".elf"}
    for f in p.iterdir():
        if not f.is_file():
            continue
        if f.suffix.lower() not in exts:
            continue
        try:
            files.append(str(f.resolve()))
        except Exception:
            files.append(str(f.absolute()))
    files.sort(key=lambda pth: Path(pth).name.lower())
    return files


def suggest_file(files: list[str], pattern: str) -> str | None:
    pattern_lower = pattern.lower()
    for path in files:
        base = os.path.basename(path).lower()
        if pattern_lower in base:
            return path
    return None


def logo_matches(files: list[str]) -> list[str]:
    matches = []
    for path in files:
        if "logo" in os.path.basename(path).lower():
            matches.append(path)
    return matches


def run_command(argv: list[str], log: callable) -> None:
    log("$ " + " ".join(argv) + "\n")
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        creationflags=creationflags,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        log(line)
    rc = proc.wait()
    if rc != 0:
        raise RuntimeError(f"命令执行失败，退出码 {rc}: {' '.join(argv)}")


def _is_valid_addr(addr: str) -> bool:
    try:
        value = int(addr.strip(), 0)
        return value >= 0
    except Exception:
        return False


def find_local_sunxi_tool(search_root: str | Path) -> str | None:
    """在项目目录中搜索可执行的 sunxi-fel，可返回绝对路径或 None。"""
    root = Path(search_root)
    if not root.exists():
        return None
    # 常见位置： sunxi-tools-*/sunxi-fel 或 任意子目录下的 sunxi-fel
    for p in root.rglob("sunxi-fel"):
        try:
            p2 = p.resolve()
            if p2.is_file() and os.access(str(p2), os.X_OK):
                return str(p2)
        except Exception:
            continue
    return None


def find_local_executable(search_root: str | Path, name: str) -> str | None:
    """在项目目录中搜索指定可执行（按文件名匹配），返回绝对路径或 None。"""
    root = Path(search_root)
    if not root.exists():
        return None
    for p in root.rglob(name):
        try:
            p2 = p.resolve()
            if p2.is_file() and os.access(str(p2), os.X_OK):
                return str(p2)
        except Exception:
            continue
    return None


def resolve_sunxi_exec(preferred: str | None) -> str:
    """返回用于执行的 sunxi-fel 可执行文件路径；如果找不到则抛出 RuntimeError。"""
    # 如果用户输入了路径并且有效，直接使用
    if preferred:
        pref = Path(preferred)
        if pref.exists() and os.access(str(pref), os.X_OK):
            return str(pref)
        # 允许用户填写相对文件名（相对于脚本目录）
        rel = Path(script_dir()) / preferred
        if rel.exists() and os.access(str(rel), os.X_OK):
            return str(rel.resolve())

    # 尝试 PATH
    which = shutil.which("sunxi-fel")
    if which:
        return which

    # 尝试在项目目录里搜索
    local = find_local_sunxi_tool(script_dir())
    if local:
        return local

    # 无法找到
    raise RuntimeError("未找到 sunxi-fel（请安装或在界面中指定本地可执行文件）。")


def resolve_exec(name: str, preferred: str | None) -> str:
    """通用解析：优先 preferred -> PATH -> 在项目中搜索 name 文件名。"""
    if preferred:
        pref = Path(preferred)
        if pref.exists():
            if os.access(str(pref), os.X_OK) and pref.is_file():
                return str(pref)
            raise RuntimeError(f"已指定 {preferred} 但不可执行，请检查权限或选择正确的可执行文件。")
        rel = Path(script_dir()) / preferred
        if rel.exists():
            if os.access(str(rel), os.X_OK) and rel.is_file():
                return str(rel.resolve())
            raise RuntimeError(f"已指定 {preferred} 但不可执行，请检查权限或选择正确的可执行文件。")

    which = shutil.which(name)
    if which:
        return which

    local = find_local_executable(script_dir(), name)
    if local:
        return local

    raise RuntimeError(f"未找到 {name} 可执行文件（请安装或在界面中指定本地可执行文件）。")


def openocd_at32_root() -> Path:
    local = Path(script_dir()) / "lib" / "openocd-at32"
    opt_root = Path("/opt/artery32/at32-openocd")
    if local.exists():
        return local
    if opt_root.exists():
        return opt_root
    return local


def openocd_at32_scripts_dir() -> Path | None:
    root = openocd_at32_root()
    share = root / "share" / "openocd" / "scripts"
    scripts = root / "scripts"
    if share.is_dir():
        return share
    if scripts.is_dir():
        return scripts
    return None


def list_openocd_cfg_relpaths(base_scripts_dir: Path, subdir: str, *, only_prefix: str | None = None) -> list[str]:
    d = base_scripts_dir / subdir
    if not d.is_dir():
        return []
    items: list[str] = []
    for p in d.rglob("*.cfg"):
        try:
            rel = p.relative_to(base_scripts_dir).as_posix()
        except Exception:
            continue
        if only_prefix and not p.name.lower().startswith(only_prefix.lower()):
            continue
        items.append(rel)
    items.sort(key=lambda s: s.lower())
    return items


def _is_hex_file(path: str) -> bool:
    return Path(path).suffix.lower() in {".hex", ".ihex", ".ihx"}


def _is_elf_file(path: str) -> bool:
    return Path(path).suffix.lower() == ".elf"


def parse_intel_hex_address_range(file_path: str) -> tuple[int, int] | None:
    """解析 Intel HEX，返回 (min_addr, max_addr_exclusive)；解析失败返回 None。"""
    try:
        min_addr: int | None = None
        max_addr: int | None = None

        upper_linear = 0  # type 04: upper 16 bits
        upper_segment = 0  # type 02: segment base (<<4)
        use_linear = True

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                if not line.startswith(":"):
                    return None
                if len(line) < 11:
                    return None

                try:
                    byte_count = int(line[1:3], 16)
                    addr16 = int(line[3:7], 16)
                    rectype = int(line[7:9], 16)
                except Exception:
                    return None

                # 记录长度校验（不严格校验 checksum，避免兼容性差异）
                expected_len = 1 + 2 + 4 + 2 + (byte_count * 2) + 2
                if len(line) < expected_len:
                    return None

                data_hex = line[9: 9 + byte_count * 2]
                if len(data_hex) != byte_count * 2:
                    return None

                if rectype == 0x00:  # data
                    if use_linear:
                        base = (upper_linear << 16) + addr16
                    else:
                        base = (upper_segment << 4) + addr16
                    end = base + byte_count
                    if min_addr is None or base < min_addr:
                        min_addr = base
                    if max_addr is None or end > max_addr:
                        max_addr = end
                elif rectype == 0x01:  # EOF
                    break
                elif rectype == 0x04:  # extended linear address
                    if byte_count != 2:
                        return None
                    upper_linear = int(data_hex, 16)
                    use_linear = True
                elif rectype == 0x02:  # extended segment address
                    if byte_count != 2:
                        return None
                    upper_segment = int(data_hex, 16)
                    use_linear = False
                else:
                    continue

        if min_addr is None or max_addr is None:
            return None
        return min_addr, max_addr
    except Exception:
        return None


def format_hex_addr(value: int) -> str:
    return hex(value)


def parse_spiflash_size_bytes(text: str) -> int | None:
    """从 sunxi-fel spiflash-info 输出中解析容量（字节）。尽量兼容不同输出格式。"""
    patterns = [
        r"\bsize\b\s*[:=]\s*(\d+)\b",
        r"\bcapacity\b\s*[:=]\s*(\d+)\s*([kmg]?b)\b",
        r"\bsize\b\s*[:=]\s*(\d+)\s*([kmg]?i?b)\b",
    ]
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if not m:
            continue
        n = int(m.group(1))
        unit = (m.group(2) or "").lower() if m.lastindex and m.lastindex >= 2 else ""
        if not unit:
            return n
        unit = unit.replace("ib", "b")
        if unit == "kb":
            return n * 1024
        if unit == "mb":
            return n * 1024 * 1024
        if unit == "gb":
            return n * 1024 * 1024 * 1024
        if unit == "b":
            return n

    m2 = re.search(r"\b(\d+)\s*(mib|mb|kib|kb|gib|gb)\b", text, flags=re.IGNORECASE)
    if m2:
        n = int(m2.group(1))
        unit = m2.group(2).lower().replace("ib", "b")
        if unit == "kb":
            return n * 1024
        if unit == "mb":
            return n * 1024 * 1024
        if unit == "gb":
            return n * 1024 * 1024 * 1024

    return None


if tk is not None:
    class App:
        def __init__(self, root: tk.Tk):
            self.root = root
            self.root.title("下载工具")

            self._log_queue: queue.Queue[str] = queue.Queue()
            self._ui_queue: queue.Queue[callable] = queue.Queue()
            self._worker: threading.Thread | None = None

            self.files: list[str] = []
            self.file_by_name: dict[str, str] = {}

            self.bin_dir_var = tk.StringVar(value=bin_dir())

            if os.name == "nt":
                win_default = Path(script_dir()) / "lib" / "sunxi-win" / "sunxi-fel.exe"
                self.sunxi_var = tk.StringVar(value=str(win_default.resolve()) if win_default.exists() else "")
            else:
                # Linux: 默认走 PATH；如需本地可执行可手动浏览选择
                self.sunxi_var = tk.StringVar(value="")

            # sunxi SPI 全片擦除：容量可留空自动识别，也可手动填写 MiB
            self.spi_size_mib_var = tk.StringVar(value="")
            # Flasher 选择：sunxi-fel（SPI） 或 openocd-AT32（通过 openocd 烧录）
            self.flasher_var = tk.StringVar(value="sunxi-fel")
            # openocd 相关配置
            default_openocd = ""
            if os.name == "nt":
                bundled = openocd_at32_root() / "bin" / "openocd.exe"
                if bundled.exists():
                    default_openocd = str(bundled.resolve())
            else:
                # Linux: 兼容 /opt/artery32/at32-openocd（AUR/厂商安装包常见路径）
                candidates = [
                    openocd_at32_root() / "bin" / "openocd",
                    openocd_at32_root() / "OpenOCD" / "bin" / "openocd",
                    openocd_at32_root() / "openocd" / "bin" / "openocd",
                    Path("/mnt/wslg/distro/opt/artery32/at32-openocd/bin/openocd"),
                ]
                for c in candidates:
                    if c.is_file() and os.access(str(c), os.X_OK):
                        default_openocd = str(c.resolve())
                        break
            if not default_openocd:
                default_openocd = find_local_executable(script_dir(), "openocd") or ""
            self.openocd_var = tk.StringVar(value=default_openocd)

            self.openocd_scripts_dir: Path | None = openocd_at32_scripts_dir()
            self.openocd_interface_var = tk.StringVar(value="")
            self.openocd_target_var = tk.StringVar(value="")
            self.openocd_args_var = tk.StringVar(value="")
            self.openocd_extra_var = tk.StringVar(value="")
            self.openocd_cmdtpl_var = tk.StringVar(value="program {file} {addr} verify reset; exit")

            # openocd: HEX 文件地址自动识别（地址留空时）
            self.hex_auto_addr_var = tk.BooleanVar(value=True)

            # AT32(openocd) 下载：可增删多行（文件 + 地址）
            self.at32_entries: list[dict[str, object]] = []

            self.boot0_var = tk.StringVar(value="跳过")
            self.boot_addr_var = tk.StringVar(value=BOOT0_ADDR)
            self.exec_var = tk.StringVar(value="跳过")
            self.exec_addr_var = tk.StringVar(value=F1C_ADDR)

            self.logo_entries: list[dict[str, object]] = []
            self.progress_var = tk.DoubleVar(value=0.0)
            self.progress_max = 1

            # 常用功能
            self.action_var = tk.StringVar(value="")

            self._build_ui()
            self._add_logo_row(default_addr=LOGO_ADDRS[0])
            self._add_at32_row(default_addr=AT32_DEFAULT_ADDRS[0])
            self._add_at32_row(default_addr=AT32_DEFAULT_ADDRS[1])
            self.refresh_files()
            self._poll_log_queue()

        def _build_ui(self) -> None:
            main = ttk.Frame(self.root, padding=12)
            main.grid(row=0, column=0, sticky="nsew")

            self.root.columnconfigure(0, weight=1)
            self.root.rowconfigure(0, weight=1)
            main.columnconfigure(1, weight=1)

            row = 0
            ttk.Label(main, text="程序目录：").grid(row=row, column=0, sticky="w")
            bin_entry = ttk.Entry(main, textvariable=self.bin_dir_var, state="readonly")
            bin_entry.grid(row=row, column=1, sticky="ew", padx=(6, 6))
            btns = ttk.Frame(main)
            btns.grid(row=row, column=2, sticky="e")
            self.refresh_btn = ttk.Button(btns, text="刷新", command=self.refresh_files)
            self.refresh_btn.grid(row=0, column=0, padx=(0, 6))
            self.browse_btn = ttk.Button(btns, text="浏览...", command=self._on_browse_bin_dir)
            self.browse_btn.grid(row=0, column=1)

            row += 1
            ttk.Separator(main).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)

            row += 1
            ttk.Label(main, text="烧录器：").grid(row=row, column=0, sticky="w")
            self.flasher_combo = ttk.Combobox(main, textvariable=self.flasher_var, state="readonly")
            self.flasher_combo["values"] = ["sunxi-fel", "openocd-AT32"]
            self.flasher_combo.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(6, 0))

            row += 1
            self.sunxi_label = ttk.Label(main, text="sunxi-fel 可执行：")
            self.sunxi_label.grid(row=row, column=0, sticky="w")
            self.sunxi_entry = ttk.Entry(main, textvariable=self.sunxi_var)
            self.sunxi_entry.grid(row=row, column=1, sticky="ew", padx=(6, 6))
            self.sunxi_browse = ttk.Button(main, text="选择可执行", command=self._on_browse_sunxi)
            self.sunxi_browse.grid(row=row, column=2, sticky="w")

            row += 1
            self.spi_size_label = ttk.Label(main, text="SPI Flash 容量(MiB，留空自动识别)：")
            self.spi_size_label.grid(row=row, column=0, sticky="w")
            self.spi_size_entry = ttk.Entry(main, textvariable=self.spi_size_mib_var)
            self.spi_size_entry.grid(row=row, column=1, sticky="ew", padx=(6, 0))
            self.spi_size_hint = ttk.Label(main, text="仅用于全片擦除")
            self.spi_size_hint.grid(row=row, column=2, sticky="w", padx=(6, 0))

            # openocd 配置区域（隐藏/显示由选择决定）
            row += 1
            self.openocd_frame = ttk.Frame(main)
            self.openocd_frame.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(6, 6))
            ttk.Label(self.openocd_frame, text="openocd 可执行：").grid(row=0, column=0, sticky="w")
            ttk.Entry(self.openocd_frame, textvariable=self.openocd_var).grid(row=0, column=1, sticky="ew", padx=(6, 6))
            ttk.Button(self.openocd_frame, text="选择", command=self._on_browse_openocd).grid(row=0, column=2)
            ttk.Label(self.openocd_frame, text="调试器(interface)：").grid(row=1, column=0, sticky="w")
            self.openocd_interface_combo = ttk.Combobox(self.openocd_frame, textvariable=self.openocd_interface_var, state="readonly")
            self.openocd_interface_combo.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(6, 6))
            ttk.Label(self.openocd_frame, text="芯片(target)：").grid(row=2, column=0, sticky="w")
            self.openocd_target_combo = ttk.Combobox(self.openocd_frame, textvariable=self.openocd_target_var, state="readonly")
            self.openocd_target_combo.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(6, 6))
            ttk.Label(self.openocd_frame, text="自动参数：").grid(row=3, column=0, sticky="w")
            ttk.Entry(self.openocd_frame, textvariable=self.openocd_args_var).grid(row=3, column=1, columnspan=2, sticky="ew", padx=(6, 6))
            ttk.Label(self.openocd_frame, text="额外参数：").grid(row=4, column=0, sticky="w")
            ttk.Entry(self.openocd_frame, textvariable=self.openocd_extra_var).grid(row=4, column=1, columnspan=2, sticky="ew", padx=(6, 6))
            ttk.Label(self.openocd_frame, text="命令模板：").grid(row=5, column=0, sticky="w")
            ttk.Entry(self.openocd_frame, textvariable=self.openocd_cmdtpl_var).grid(row=5, column=1, columnspan=2, sticky="ew", padx=(6, 6))

            ttk.Checkbutton(
                self.openocd_frame,
                text="HEX 自动识别地址（地址留空时）",
                variable=self.hex_auto_addr_var,
            ).grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))

            ttk.Separator(self.openocd_frame).grid(row=7, column=0, columnspan=4, sticky="ew", pady=(8, 8))

            ttk.Label(self.openocd_frame, text="AT32 固件（可添加多条：文件 + 地址，支持 .bin/.hex/.elf）：").grid(row=8, column=0, columnspan=4, sticky="w")
            self.at32_box = ttk.Frame(self.openocd_frame)
            self.at32_box.grid(row=9, column=0, columnspan=4, sticky="ew", pady=(6, 0))
            self.at32_box.columnconfigure(1, weight=1)

            ttk.Label(self.at32_box, text="#").grid(row=0, column=0, sticky="w")
            ttk.Label(self.at32_box, text="固件文件").grid(row=0, column=1, sticky="w")
            ttk.Label(self.at32_box, text="地址(如 0x08000000；HEX/ELF可留空)").grid(row=0, column=2, sticky="w", padx=(8, 0))

            self.at32_rows_frame = ttk.Frame(self.at32_box)
            self.at32_rows_frame.grid(row=1, column=0, columnspan=3, sticky="ew")
            self.at32_rows_frame.columnconfigure(1, weight=1)

            at32_btns = ttk.Frame(self.at32_box)
            at32_btns.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
            self.at32_add_btn = ttk.Button(at32_btns, text="添加AT32固件", command=self._on_add_at32)
            self.at32_add_btn.grid(row=0, column=0, sticky="w")
            self.at32_del_btn = ttk.Button(at32_btns, text="删除最后一条", command=self._on_del_at32)
            self.at32_del_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))

            self.openocd_frame.columnconfigure(1, weight=1)
            self._populate_openocd_cfg_choices()
            self.openocd_interface_combo.bind("<<ComboboxSelected>>", lambda e: self._update_openocd_args_from_cfg())
            self.openocd_target_combo.bind("<<ComboboxSelected>>", lambda e: self._update_openocd_args_from_cfg())
            # flasher 切换时再显示/隐藏（首次调用挪到所有控件创建完成后）
            self.flasher_combo.bind("<<ComboboxSelected>>", lambda e: self._update_openocd_visibility())

            # shift following rows down by 1 (they were previously at row indices >=4)

            row += 1
            self.boot0_label = ttk.Label(main, text="BOOT0：")
            self.boot0_label.grid(row=row, column=0, sticky="w")
            self.boot0_combo = ttk.Combobox(main, textvariable=self.boot0_var, state="readonly")
            self.boot0_combo.grid(row=row, column=1, sticky="ew", padx=(6, 0))
            ttk.Entry(main, textvariable=self.boot_addr_var, width=12).grid(row=row, column=2, sticky="ew", padx=(6, 0))

            row += 1
            self.logo_label = ttk.Label(main, text="LOGO（可添加多条：文件 + 地址）：")
            self.logo_label.grid(row=row, column=0, sticky="w", pady=(8, 0))
            self.logo_box = ttk.Frame(main)
            self.logo_box.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(6, 0), pady=(8, 0))
            self.logo_box.columnconfigure(1, weight=1)

            ttk.Label(self.logo_box, text="#").grid(row=0, column=0, sticky="w")
            ttk.Label(self.logo_box, text="LOGO BIN").grid(row=0, column=1, sticky="w")
            ttk.Label(self.logo_box, text="地址(如 0x7000)").grid(row=0, column=2, sticky="w", padx=(8, 0))

            self.logo_rows_frame = ttk.Frame(self.logo_box)
            self.logo_rows_frame.grid(row=1, column=0, columnspan=3, sticky="ew")
            self.logo_rows_frame.columnconfigure(1, weight=1)

            logo_btns = ttk.Frame(self.logo_box)
            logo_btns.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
            self.logo_add_btn = ttk.Button(logo_btns, text="添加LOGO", command=self._on_add_logo)
            self.logo_add_btn.grid(row=0, column=0, sticky="w")
            self.logo_del_btn = ttk.Button(logo_btns, text="删除最后一条", command=self._on_del_logo)
            self.logo_del_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))

            row += 1
            self.exec_label = ttk.Label(main, text="EXEC/F1C：")
            self.exec_label.grid(row=row, column=0, sticky="w", pady=(8, 0))
            self.exec_combo = ttk.Combobox(main, textvariable=self.exec_var, state="readonly")
            self.exec_combo.grid(row=row, column=1, sticky="ew", padx=(6, 0), pady=(8, 0))
            ttk.Entry(main, textvariable=self.exec_addr_var, width=12).grid(row=row, column=2, sticky="ew", padx=(6, 0), pady=(8, 0))

            row += 1
            btn_row = ttk.Frame(main)
            btn_row.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(12, 8))
            btn_row.columnconfigure(0, weight=1)

            self.start_btn = ttk.Button(btn_row, text="开始下载", command=self.on_start)
            self.start_btn.grid(row=0, column=0, sticky="w")

            self.action_combo = ttk.Combobox(btn_row, textvariable=self.action_var, state="readonly", width=28)
            self.action_combo.grid(row=0, column=1, sticky="w", padx=(12, 6))
            self.action_btn = ttk.Button(btn_row, text="执行功能", command=self.on_run_action)
            self.action_btn.grid(row=0, column=2, sticky="w")

            self.quit_btn = ttk.Button(btn_row, text="退出", command=self.root.destroy)
            self.quit_btn.grid(row=0, column=3, sticky="e")

            row += 1
            ttk.Label(main, text="进度：").grid(row=row, column=0, sticky="w")
            self.progress = ttk.Progressbar(
                main,
                orient="horizontal",
                mode="determinate",
                variable=self.progress_var,
                maximum=self.progress_max,
            )
            self.progress.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(6, 0))

            row += 1
            ttk.Label(main, text="日志：").grid(row=row, column=0, sticky="w")
            self.log_text = tk.Text(main, height=16, wrap="word")
            self.log_text.grid(row=row+1, column=0, columnspan=3, sticky="nsew")
            main.rowconfigure(row+1, weight=1)

            # 初始显示/隐藏（必须在 F1C 控件创建完成后）
            self._update_openocd_visibility()
            self._update_action_choices()

        def _ui(self, fn: callable) -> None:
            self._ui_queue.put(fn)

        def _on_browse_bin_dir(self) -> None:
            if filedialog is None:
                return
            sel = filedialog.askdirectory(initialdir=self.bin_dir_var.get() or os.getcwd(), title="选择 bin 目录")
            if sel:
                self.bin_dir_var.set(sel)
                self.refresh_files()

        def _on_browse_sunxi(self) -> None:
            if filedialog is None:
                return
            sel = filedialog.askopenfilename(initialdir=script_dir(), title="选择 sunxi-fel 可执行")
            if sel:
                self.sunxi_var.set(sel)

        def _on_browse_openocd(self) -> None:
            if filedialog is None:
                return
            init_dir = script_dir()
            opt_bin = Path("/opt/artery32/at32-openocd") / "bin"
            opt_bin_wslg = Path("/mnt/wslg/distro/opt/artery32/at32-openocd/bin")
            if opt_bin.exists():
                init_dir = str(opt_bin)
            elif opt_bin_wslg.exists():
                init_dir = str(opt_bin_wslg)
            sel = filedialog.askopenfilename(initialdir=init_dir, title="选择 openocd 可执行")
            if sel:
                self.openocd_var.set(sel)

        def _update_openocd_visibility(self) -> None:
            show = (self.flasher_var.get() == "openocd-AT32")
            if show:
                self.openocd_frame.grid()
                # openocd 模式：隐藏 F1C(sunxi-fel) 相关控件
                if hasattr(self, "sunxi_label"):
                    self.sunxi_label.grid_remove()
                if hasattr(self, "sunxi_entry"):
                    self.sunxi_entry.grid_remove()
                if hasattr(self, "sunxi_browse"):
                    self.sunxi_browse.grid_remove()
                if hasattr(self, "spi_size_label"):
                    self.spi_size_label.grid_remove()
                if hasattr(self, "spi_size_entry"):
                    self.spi_size_entry.grid_remove()
                if hasattr(self, "spi_size_hint"):
                    self.spi_size_hint.grid_remove()
                if hasattr(self, "boot0_label"):
                    self.boot0_label.grid_remove()
                if hasattr(self, "boot0_combo"):
                    self.boot0_combo.grid_remove()
                if hasattr(self, "logo_label"):
                    self.logo_label.grid_remove()
                if hasattr(self, "logo_box"):
                    self.logo_box.grid_remove()
                if hasattr(self, "exec_label"):
                    self.exec_label.grid_remove()
                if hasattr(self, "exec_combo"):
                    self.exec_combo.grid_remove()
            else:
                self.openocd_frame.grid_remove()
                # sunxi-fel 模式：显示 F1C 相关控件
                if hasattr(self, "sunxi_label"):
                    self.sunxi_label.grid()
                if hasattr(self, "sunxi_entry"):
                    self.sunxi_entry.grid()
                if hasattr(self, "sunxi_browse"):
                    self.sunxi_browse.grid()
                if hasattr(self, "spi_size_label"):
                    self.spi_size_label.grid()
                if hasattr(self, "spi_size_entry"):
                    self.spi_size_entry.grid()
                if hasattr(self, "spi_size_hint"):
                    self.spi_size_hint.grid()
                if hasattr(self, "boot0_label"):
                    self.boot0_label.grid()
                if hasattr(self, "boot0_combo"):
                    self.boot0_combo.grid()
                if hasattr(self, "logo_label"):
                    self.logo_label.grid()
                if hasattr(self, "logo_box"):
                    self.logo_box.grid()
                if hasattr(self, "exec_label"):
                    self.exec_label.grid()
                if hasattr(self, "exec_combo"):
                    self.exec_combo.grid()

            self._update_action_choices()

        def _update_action_choices(self) -> None:
            if self.flasher_var.get() == "openocd-AT32":
                values = [
                    "连接测试（init/targets）",
                    "复位运行（reset run）",
                    "复位暂停（reset halt）",
                    "全片擦除（flash erase_sector 0 0 last）",
                ]
            else:
                values = [
                    "检测设备（version）",
                    "SPI 信息（spiflash-info）",
                    "全片擦除（写0xFF，较慢）",
                    "重启（wdreset）",
                ]
            self.action_combo["values"] = values
            if values and self.action_var.get() not in values:
                self.action_var.set(values[0])

        def _populate_openocd_cfg_choices(self) -> None:
            scripts_dir = self.openocd_scripts_dir
            if scripts_dir is None:
                self.openocd_interface_combo["values"] = []
                self.openocd_target_combo["values"] = []
                self.openocd_args_var.set("")
                return

            interfaces = list_openocd_cfg_relpaths(scripts_dir, "interface")
            targets = list_openocd_cfg_relpaths(scripts_dir, "target", only_prefix="at32")

            self.openocd_interface_combo["values"] = interfaces
            self.openocd_target_combo["values"] = targets

            if interfaces and not self.openocd_interface_var.get().strip():
                if "interface/cmsis-dap.cfg" in interfaces:
                    self.openocd_interface_var.set("interface/cmsis-dap.cfg")
                elif "interface/stlink.cfg" in interfaces:
                    self.openocd_interface_var.set("interface/stlink.cfg")
                else:
                    self.openocd_interface_var.set(interfaces[0])
            if targets and not self.openocd_target_var.get().strip():
                preferred_targets = [
                    "target/at32f413xx.cfg",
                    "target/at32f413x.cfg",
                    "target/at32f413.cfg",
                    "target/at32f403xx.cfg",
                ]
                chosen = next((t for t in preferred_targets if t in targets), None)
                self.openocd_target_var.set(chosen if chosen else targets[0])

            self._update_openocd_args_from_cfg()

        def _update_openocd_args_from_cfg(self) -> None:
            scripts_dir = self.openocd_scripts_dir
            if scripts_dir is None:
                self.openocd_args_var.set("")
                return

            iface = self.openocd_interface_var.get().strip()
            tgt = self.openocd_target_var.get().strip()
            # openocd 在 Windows 下对反斜杠敏感，统一转换为正斜杠
            scripts_arg = scripts_dir.as_posix() if hasattr(scripts_dir, "as_posix") else str(scripts_dir)
            parts: list[str] = ["-s", scripts_arg]
            if iface:
                parts += ["-f", iface]
            if tgt:
                parts += ["-f", tgt]
            self.openocd_args_var.set(" ".join(parts))

        def _set_progress(self, value: int, maximum: int) -> None:
            self.progress_max = max(1, int(maximum))
            self.progress.configure(maximum=self.progress_max)
            self.progress_var.set(float(value))

        def _add_logo_row(self, default_file: str = "跳过", default_addr: str = "") -> None:
            idx = len(self.logo_entries)

            file_var = tk.StringVar(value=default_file)
            addr_var = tk.StringVar(value=default_addr)

            lbl = ttk.Label(self.logo_rows_frame, text=str(idx + 1))
            combo = ttk.Combobox(self.logo_rows_frame, textvariable=file_var, state="readonly")
            entry = ttk.Entry(self.logo_rows_frame, textvariable=addr_var)

            lbl.grid(row=idx, column=0, sticky="w", pady=2)
            combo.grid(row=idx, column=1, sticky="ew", pady=2)
            entry.grid(row=idx, column=2, sticky="ew", padx=(8, 0), pady=2)

            self.logo_entries.append(
                {
                    "file_var": file_var,
                    "addr_var": addr_var,
                    "label": lbl,
                    "combo": combo,
                    "entry": entry,
                }
            )

        def _on_add_logo(self) -> None:
            next_addr = LOGO_ADDRS[len(self.logo_entries)] if len(self.logo_entries) < len(LOGO_ADDRS) else ""
            self._add_logo_row(default_addr=next_addr)
            self.refresh_files()

        def _on_del_logo(self) -> None:
            if len(self.logo_entries) <= 1:
                return
            row = self.logo_entries.pop()
            for key in ("label", "combo", "entry"):
                w = row.get(key)
                try:
                    if w is not None:
                        w.destroy()  # type: ignore[union-attr]
                except Exception:
                    pass

        def _add_at32_row(self, default_file: str = "跳过", default_addr: str = "") -> None:
            idx = len(self.at32_entries)
            file_var = tk.StringVar(value=default_file)
            addr_var = tk.StringVar(value=default_addr)

            lbl = ttk.Label(self.at32_rows_frame, text=str(idx + 1))
            combo = ttk.Combobox(self.at32_rows_frame, textvariable=file_var, state="readonly")
            entry = ttk.Entry(self.at32_rows_frame, textvariable=addr_var, width=14)

            lbl.grid(row=idx, column=0, sticky="w", pady=2)
            combo.grid(row=idx, column=1, sticky="ew", pady=2)
            entry.grid(row=idx, column=2, sticky="e", padx=(8, 0), pady=2)

            self.at32_entries.append(
                {
                    "file_var": file_var,
                    "addr_var": addr_var,
                    "default_addr": default_addr,
                    "last_addr": default_addr,
                    "label": lbl,
                    "combo": combo,
                    "entry": entry,
                }
            )

            combo.bind("<<ComboboxSelected>>", lambda e, r=self.at32_entries[-1]: self._apply_at32_addr_state(r))
            self._apply_at32_addr_state(self.at32_entries[-1])

        def _on_add_at32(self) -> None:
            self._add_at32_row(default_addr="")
            self.refresh_files()

        def _on_del_at32(self) -> None:
            if len(self.at32_entries) <= 1:
                return
            row = self.at32_entries.pop()
            for key in ("label", "combo", "entry"):
                w = row.get(key)
                try:
                    if w is not None:
                        w.destroy()  # type: ignore[union-attr]
                except Exception:
                    pass

        def _apply_at32_addr_state(self, row: dict[str, object]) -> None:
            fv = row.get("file_var")
            av = row.get("addr_var")
            entry = row.get("entry")
            if not isinstance(fv, tk.StringVar) or not isinstance(av, tk.StringVar):
                return

            path = self._selected_path(fv.get())
            is_special = path is not None and (_is_hex_file(path) or _is_elf_file(path))

            if is_special:
                # 禁用地址输入并清空，记录上一次填写便于恢复
                last = av.get().strip()
                if last:
                    row["last_addr"] = last
                av.set("")
                if entry is not None:
                    try:
                        entry.configure(state="disabled")  # type: ignore[union-attr]
                    except Exception:
                        pass
            else:
                if entry is not None:
                    try:
                        entry.configure(state="normal")  # type: ignore[union-attr]
                    except Exception:
                        pass
                if not av.get().strip():
                    prev = row.get("last_addr")
                    if isinstance(prev, str) and prev:
                        av.set(prev)
                    else:
                        default_addr = row.get("default_addr")
                        if isinstance(default_addr, str) and default_addr:
                            av.set(default_addr)

        def _refresh_at32_addr_states(self) -> None:
            for row in self.at32_entries:
                self._apply_at32_addr_state(row)

        def _collect_at32_jobs(self) -> tuple[list[tuple[str, str]], str | None]:
            jobs: list[tuple[str, str]] = []
            for row in self.at32_entries:
                fv = row.get("file_var")
                av = row.get("addr_var")
                default_addr = row.get("default_addr")
                if not isinstance(fv, tk.StringVar) or not isinstance(av, tk.StringVar):
                    continue
                file_name = fv.get()
                addr = av.get().strip()
                path = self._selected_path(file_name)
                if path is None and (not addr):
                    continue
                if path is None and addr:
                    return [], f"AT32 地址已填写但未选择文件：{addr}"
                if path is not None and (not addr):
                    # HEX：如果启用自动识别，改为留空地址交由 openocd 按文件内地址写入，避免重复偏移
                    if _is_hex_file(path) and bool(self.hex_auto_addr_var.get()):
                        # 仍尝试解析以供提示，但不把地址写回到任务中
                        rng = parse_intel_hex_address_range(path)
                        if rng is None:
                            return [], f"HEX 地址识别失败：{os.path.basename(path)}（请手动填写地址或检查 HEX 格式）"
                        addr = ""
                    # ELF：openocd 可直接按 ELF 内置段地址烧录，允许地址留空
                    elif _is_elf_file(path):
                        addr = ""
                    else:
                        eff = default_addr.strip() if isinstance(default_addr, str) else ""
                        if not eff:
                            return [], f"已选择 AT32 文件但地址为空：{os.path.basename(path)}"
                        addr = eff
                if path is None:
                    continue
                if addr and not _is_valid_addr(addr):
                    return [], f"AT32 地址格式非法：{addr}（示例：0x08000000）"
                jobs.append((addr, path))
            if not jobs:
                return [], "请至少选择一个 AT32 固件文件。"
            return jobs, None

        def refresh_files(self) -> None:
            directory = self.bin_dir_var.get()
            self.files = list_bin_files(directory)
            self.file_by_name = {os.path.basename(p): p for p in self.files}

            # sunxi-fel（SPI）仅支持写入二进制；openocd 支持 .bin/.hex
            bin_only = [p for p in self.files if Path(p).suffix.lower() == ".bin"]
            names_all = ["跳过"] + [os.path.basename(p) for p in self.files]
            names_bin = ["跳过"] + [os.path.basename(p) for p in bin_only]

            self.boot0_combo["values"] = names_bin
            self.exec_combo["values"] = names_bin

            for row in self.at32_entries:
                combo = row.get("combo")
                if combo is not None:
                    combo["values"] = names_all  # type: ignore[index]

            for row in self.logo_entries:
                combo = row.get("combo")
                if combo is not None:
                    combo["values"] = names_bin  # type: ignore[index]

            def_boot0 = suggest_file(self.files, "boot0")
            def_logo = suggest_file(self.files, "logo")
            def_exec = suggest_file(self.files, "f1c") or suggest_file(self.files, "exec") or suggest_file(self.files, "firmware")

            self.boot0_var.set(os.path.basename(def_boot0) if def_boot0 else "跳过")
            self.exec_var.set(os.path.basename(def_exec) if def_exec else "跳过")

            # AT32 默认：按关键词分别尝试 boot/app
            def_at32_boot = (
                suggest_file(self.files, "boot")
                or suggest_file(self.files, "at32_boot")
                or suggest_file(self.files, "boot0")
            )
            def_at32_app = (
                suggest_file(self.files, "app")
                or suggest_file(self.files, "at32_app")
                or suggest_file(self.files, "firmware")
            )
            if self.at32_entries:
                row0 = self.at32_entries[0]
                fv0 = row0.get("file_var")
                if isinstance(fv0, tk.StringVar) and fv0.get() == "跳过" and def_at32_boot:
                    fv0.set(os.path.basename(def_at32_boot))
            if len(self.at32_entries) >= 2:
                row1 = self.at32_entries[1]
                fv1 = row1.get("file_var")
                if isinstance(fv1, tk.StringVar) and fv1.get() == "跳过" and def_at32_app:
                    fv1.set(os.path.basename(def_at32_app))

            # 如果第一条 LOGO 还没选文件，则给一个常用默认值
            if self.logo_entries:
                row0 = self.logo_entries[0]
                fv = row0.get("file_var")
                av = row0.get("addr_var")
                if isinstance(fv, tk.StringVar) and fv.get() == "跳过" and def_logo:
                    fv.set(os.path.basename(def_logo))
                if isinstance(av, tk.StringVar) and not av.get().strip():
                    av.set(LOGO_ADDRS[0])

            # HEX/ELF 时自动关闭地址输入
            self._refresh_at32_addr_states()

            self._log(f"程序目录：{directory}\n")
            if not self.files:
                self._log("提示：未发现 .bin/.hex 文件，可先放入 bin/ 后点击 刷新。\n")

        def _selected_path(self, name: str) -> str | None:
            if not name or name == "跳过":
                return None
            return self.file_by_name.get(name)

        def _log(self, text: str) -> None:
            self._log_queue.put(text)

        def _poll_log_queue(self) -> None:
            try:
                while True:
                    msg = self._log_queue.get_nowait()
                    self.log_text.insert("end", msg)
                    self.log_text.see("end")
            except queue.Empty:
                pass

            try:
                while True:
                    fn = self._ui_queue.get_nowait()
                    try:
                        fn()
                    except Exception:
                        pass
            except queue.Empty:
                pass
            self.root.after(80, self._poll_log_queue)

        def _set_running(self, running: bool) -> None:
            state = "disabled" if running else "normal"
            self.start_btn.configure(state=state)
            self.refresh_btn.configure(state=state)
            self.quit_btn.configure(state=state)
            if hasattr(self, "action_btn"):
                self.action_btn.configure(state=state)
            if hasattr(self, "action_combo"):
                self.action_combo.configure(state=("disabled" if running else "readonly"))
            if running:
                self.boot0_combo.state(["disabled"])
                self.exec_combo.state(["disabled"])
                self.logo_add_btn.configure(state="disabled")
                self.logo_del_btn.configure(state="disabled")
                if hasattr(self, "at32_add_btn"):
                    self.at32_add_btn.configure(state="disabled")
                if hasattr(self, "at32_del_btn"):
                    self.at32_del_btn.configure(state="disabled")
                if hasattr(self, "spi_size_entry"):
                    self.spi_size_entry.configure(state="disabled")
                for row in self.logo_entries:
                    combo = row.get("combo")
                    entry = row.get("entry")
                    if combo is not None:
                        combo.state(["disabled"])  # type: ignore[union-attr]
                    if entry is not None:
                        entry.configure(state="disabled")  # type: ignore[union-attr]
                for row in self.at32_entries:
                    combo = row.get("combo")
                    entry = row.get("entry")
                    if combo is not None:
                        combo.state(["disabled"])  # type: ignore[union-attr]
                    if entry is not None:
                        entry.configure(state="disabled")  # type: ignore[union-attr]
            else:
                self.boot0_combo.state(["!disabled"])
                self.exec_combo.state(["!disabled"])
                self.logo_add_btn.configure(state="normal")
                self.logo_del_btn.configure(state="normal")
                if hasattr(self, "at32_add_btn"):
                    self.at32_add_btn.configure(state="normal")
                if hasattr(self, "at32_del_btn"):
                    self.at32_del_btn.configure(state="normal")
                if hasattr(self, "spi_size_entry"):
                    self.spi_size_entry.configure(state="normal")
                for row in self.logo_entries:
                    combo = row.get("combo")
                    entry = row.get("entry")
                    if combo is not None:
                        combo.state(["!disabled"])  # type: ignore[union-attr]
                    if entry is not None:
                        entry.configure(state="normal")  # type: ignore[union-attr]
                for row in self.at32_entries:
                    combo = row.get("combo")
                    entry = row.get("entry")
                    if combo is not None:
                        combo.state(["!disabled"])  # type: ignore[union-attr]
                    if entry is not None:
                        entry.configure(state="normal")  # type: ignore[union-attr]

        def _openocd_exec(self) -> str:
            openocd_name = "openocd.exe" if os.name == "nt" else "openocd"
            return resolve_exec(openocd_name, self.openocd_var.get())

        def _run_openocd_cmd(self, cmd: str) -> None:
            openocd_exec = self._openocd_exec()
            base_args = self.openocd_args_var.get().strip()
            extra = self.openocd_extra_var.get().strip()
            argv = [openocd_exec]
            import shlex
            if base_args:
                argv += shlex.split(base_args, posix=(os.name != "nt"))
            if extra:
                argv += shlex.split(extra, posix=(os.name != "nt"))
            argv += ["-c", cmd]
            self._log(f"调用 openocd: {' '.join(argv)}\n")
            run_command(argv, self._log)

        def _sunxi_exec(self) -> str:
            return resolve_sunxi_exec(self.sunxi_var.get())

        def _sunxi_spiflash_info(self, sunxi_exec: str) -> str:
            argv = [sunxi_exec, "-p", "spiflash-info"]
            self._log("$ " + " ".join(argv) + "\n")
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags,
            )
            assert proc.stdout is not None
            out_lines: list[str] = []
            for line in proc.stdout:
                out_lines.append(line)
                self._log(line)
            rc = proc.wait()
            if rc != 0:
                raise RuntimeError(f"命令执行失败，退出码 {rc}: {' '.join(argv)}")
            return "".join(out_lines)

        def _sunxi_chip_erase_ff(self, sunxi_exec: str) -> None:
            mib_text = self.spi_size_mib_var.get().strip()
            total_bytes: int | None = None
            if mib_text:
                try:
                    total_bytes = int(float(mib_text) * 1024 * 1024)
                except Exception:
                    raise RuntimeError(f"SPI Flash 容量(MiB)格式非法：{mib_text}")

            if total_bytes is None:
                info_out = self._sunxi_spiflash_info(sunxi_exec)
                total_bytes = parse_spiflash_size_bytes(info_out)
            if total_bytes is None or total_bytes <= 0:
                raise RuntimeError("无法识别 SPI Flash 容量；请在界面中手动填写 'SPI Flash 容量(MiB)' 后重试。")

            chunk_size = 256 * 1024
            tmp = Path(script_dir()) / "_erase_ff.tmp"
            with open(tmp, "wb") as f:
                f.write(bytes([0xFF]) * chunk_size)

            self._log(f"开始全片擦除（写0xFF）：容量 {total_bytes} bytes，块大小 {chunk_size} bytes\n")
            steps = (total_bytes + chunk_size - 1) // chunk_size
            done = 0
            self._ui(lambda: self._set_progress(0, max(1, steps)))

            try:
                addr = 0
                while addr < total_bytes:
                    remain = total_bytes - addr
                    if remain < chunk_size:
                        last = Path(script_dir()) / "_erase_ff_last.tmp"
                        with open(last, "wb") as f:
                            f.write(bytes([0xFF]) * remain)
                        run_command([sunxi_exec, "-p", "spiflash-write", hex(addr), str(last)], self._log)
                        try:
                            last.unlink()
                        except Exception:
                            pass
                        addr += remain
                    else:
                        run_command([sunxi_exec, "-p", "spiflash-write", hex(addr), str(tmp)], self._log)
                        addr += chunk_size
                    done += 1
                    self._ui(lambda ds=done, ts=steps: self._set_progress(ds, ts))
            finally:
                try:
                    tmp.unlink()
                except Exception:
                    pass

        def on_run_action(self) -> None:
            if self._worker and self._worker.is_alive():
                return

            action = self.action_var.get().strip()
            if not action:
                return

            self._set_running(True)

            def worker() -> None:
                try:
                    self._log("\n执行功能...\n")
                    self._ui(lambda: self._set_progress(0, 1))

                    if self.flasher_var.get() == "openocd-AT32":
                        if action.startswith("连接测试"):
                            self._run_openocd_cmd("init; targets; shutdown")
                        elif action.startswith("复位运行"):
                            self._run_openocd_cmd("init; reset run; shutdown")
                        elif action.startswith("复位暂停"):
                            self._run_openocd_cmd("init; reset halt; shutdown")
                        elif action.startswith("全片擦除"):
                            self._run_openocd_cmd("init; reset halt; flash erase_sector 0 0 last; reset run; shutdown")
                        else:
                            raise RuntimeError(f"未知功能：{action}")
                    else:
                        sunxi_exec = self._sunxi_exec()
                        if action.startswith("检测设备"):
                            run_command([sunxi_exec, "version"], self._log)
                        elif action.startswith("SPI 信息"):
                            run_command([sunxi_exec, "-p", "spiflash-info"], self._log)
                        elif action.startswith("全片擦除"):
                            self._sunxi_chip_erase_ff(sunxi_exec)
                        elif action.startswith("重启"):
                            run_command([sunxi_exec, "wdreset"], self._log)
                        else:
                            raise RuntimeError(f"未知功能：{action}")

                    self._log("功能执行完成。\n")
                    self.root.after(0, lambda: messagebox.showinfo("完成", "功能执行完成。"))
                except Exception as e:
                    self._log(f"\n错误：{e}\n")
                    self.root.after(0, (lambda err=e: messagebox.showerror("失败", str(err))))
                finally:
                    self._ui(lambda: self._set_progress(0, 1))
                    self.root.after(0, lambda: self._set_running(False))

            self._worker = threading.Thread(target=worker, daemon=True)
            self._worker.start()

        def on_start(self) -> None:
            if self._worker and self._worker.is_alive():
                return

            sunxi_exec = ""
            if self.flasher_var.get() == "sunxi-fel":
                try:
                    sunxi_exec = resolve_sunxi_exec(self.sunxi_var.get())
                except Exception as e:
                    messagebox.showerror("缺少工具", str(e))
                    return

            if self.flasher_var.get() == "sunxi-fel":
                boot0_path = self._selected_path(self.boot0_var.get())
                boot_addr = self.boot_addr_var.get().strip() or "0"
                exec_path = self._selected_path(self.exec_var.get())
                exec_addr = self.exec_addr_var.get().strip() or "0"

                if boot0_path and not _is_valid_addr(boot_addr):
                    messagebox.showerror("BOOT0 地址错误", f"地址格式非法：{boot_addr}\n示例：0x0")
                    return
                if exec_path and not _is_valid_addr(exec_addr):
                    messagebox.showerror("EXEC 地址错误", f"地址格式非法：{exec_addr}\n示例：0x100000")
                    return

                logo_jobs: list[tuple[str, str]] = []
                for row in self.logo_entries:
                    fv = row.get("file_var")
                    av = row.get("addr_var")
                    if not isinstance(fv, tk.StringVar) or not isinstance(av, tk.StringVar):
                        continue
                    file_name = fv.get()
                    addr = av.get().strip()
                    path = self._selected_path(file_name)
                    if path is None and (not addr):
                        continue
                    if path is None and addr:
                        messagebox.showerror("LOGO 配置错误", f"LOGO 地址已填写但未选择文件：{addr}")
                        return
                    if path is not None and not addr:
                        messagebox.showerror("LOGO 配置错误", f"已选择 LOGO 文件但地址为空：{os.path.basename(path)}")
                        return
                    if path is None:
                        continue
                    if not _is_valid_addr(addr):
                        messagebox.showerror("LOGO 地址错误", f"地址格式非法：{addr}\n示例：0x7000")
                        return
                    logo_jobs.append((addr, path))

                summary_lines = [
                    "即将下载如下内容（F1C / sunxi-fel / SPI Flash）：",
                    f"- BOOT0 @ {boot_addr} : {os.path.basename(boot0_path) if boot0_path else '跳过'}",
                    f"- LOGO  : {'跳过' if not logo_jobs else str(len(logo_jobs)) + ' 条'}",
                ]
                for idx, (addr, path) in enumerate(logo_jobs, start=1):
                    summary_lines.append(f"  - {idx}) @ {addr} : {os.path.basename(path)}")
                summary_lines.append(
                    f"- EXEC  @ {exec_addr} : {os.path.basename(exec_path) if exec_path else '跳过'}"
                )
                if not messagebox.askyesno("确认", "\n".join(summary_lines) + "\n\n确认开始下载？"):
                    self._log("已取消。\n")
                    return
            else:
                at32_jobs, err = self._collect_at32_jobs()
                if err:
                    messagebox.showerror("AT32 配置错误", err)
                    return

                summary_lines = ["即将下载如下内容（AT32 / openocd）："]
                for idx, (addr, path) in enumerate(at32_jobs, start=1):
                    extra = ""
                    if _is_hex_file(path):
                        rng = parse_intel_hex_address_range(path)
                        if rng is not None:
                            extra = f"（HEX范围 {format_hex_addr(rng[0])}..{format_hex_addr(rng[1])}）"
                    if _is_elf_file(path) and not addr:
                        summary_lines.append(f"- {idx}) @ ELF内置地址 : {os.path.basename(path)}")
                    else:
                        summary_lines.append(f"- {idx}) @ {addr} : {os.path.basename(path)}{extra}")
                if not messagebox.askyesno("确认", "\n".join(summary_lines) + "\n\n确认开始下载？"):
                    self._log("已取消。\n")
                    return

            self._set_running(True)

            def worker() -> None:
                try:
                    self._log("\n下载中...\n")

                    if self.flasher_var.get() == "sunxi-fel":
                        boot0_path = self._selected_path(self.boot0_var.get())
                        boot_addr = self.boot_addr_var.get().strip() or "0"
                        exec_path = self._selected_path(self.exec_var.get())
                        exec_addr = self.exec_addr_var.get().strip() or "0"
                        logo_jobs: list[tuple[str, str]] = []
                        for row in self.logo_entries:
                            fv = row.get("file_var")
                            av = row.get("addr_var")
                            if not isinstance(fv, tk.StringVar) or not isinstance(av, tk.StringVar):
                                continue
                            file_name = fv.get()
                            addr = av.get().strip()
                            path = self._selected_path(file_name)
                            if path is None or not addr:
                                continue
                            logo_jobs.append((addr, path))

                        total_steps = (1 if boot0_path else 0) + len(logo_jobs) + (1 if exec_path else 0)
                        done_steps = 0
                        self._ui(lambda: self._set_progress(0, max(1, total_steps)))

                        if boot0_path:
                            self._log(f"写入 BOOT0 -> {boot_addr}\n")
                            run_command([sunxi_exec, "-p", "spiflash-write", boot_addr, boot0_path], self._log)
                            done_steps += 1
                            self._ui(lambda ds=done_steps, ts=total_steps: self._set_progress(ds, ts))

                        for addr, lf in logo_jobs:
                            self._log(f"写入 LOGO -> {addr} : {os.path.basename(lf)}\n")
                            run_command([sunxi_exec, "-p", "spiflash-write", addr, lf], self._log)
                            done_steps += 1
                            self._ui(lambda ds=done_steps, ts=total_steps: self._set_progress(ds, ts))

                        if exec_path:
                            self._log(f"写入 EXEC  -> {exec_addr}\n")
                            run_command([sunxi_exec, "-p", "spiflash-write", exec_addr, exec_path], self._log)
                            done_steps += 1
                            self._ui(lambda ds=done_steps, ts=total_steps: self._set_progress(ds, ts))
                    else:
                        # openocd-AT32 模式：使用 openocd 可执行 + 用户额外参数 + -c "命令模板"
                        openocd_exec = self._openocd_exec()

                        def run_openocd_program(file_path: str, addr: str) -> None:
                            tpl = self.openocd_cmdtpl_var.get()
                            file_arg = file_path.replace("\\", "/")
                            cmdstr = tpl.replace("{file}", file_arg)
                            if "{addr}" in cmdstr:
                                if addr:
                                    cmdstr = cmdstr.replace("{addr}", addr)
                                else:
                                    # 地址为空：移除占位符及其周边空白
                                    cmdstr = re.sub(r"\s*\{addr\}\s*", " ", cmdstr)
                                    cmdstr = re.sub(r"\s+", " ", cmdstr).strip()
                            base_args = self.openocd_args_var.get().strip()
                            extra = self.openocd_extra_var.get().strip()
                            argv = [openocd_exec]
                            import shlex
                            if base_args:
                                argv += shlex.split(base_args, posix=(os.name != "nt"))
                            if extra:
                                argv += shlex.split(extra, posix=(os.name != "nt"))
                            argv += ["-c", cmdstr]
                            self._log(f"调用 openocd: {' '.join(argv)}\n")
                            run_command(argv, self._log)

                        at32_jobs, err = self._collect_at32_jobs()
                        if err:
                            raise RuntimeError(err)

                        total_steps = max(1, len(at32_jobs))
                        done_steps = 0
                        self._ui(lambda: self._set_progress(0, total_steps))
                        for addr, path in at32_jobs:
                            self._log(f"openocd 写入 AT32 -> {addr} : {os.path.basename(path)}\n")
                            run_openocd_program(path, addr)
                            done_steps += 1
                            self._ui(lambda ds=done_steps, ts=total_steps: self._set_progress(ds, ts))

                    self._log("下载完成。\n")
                    self.root.after(0, lambda: messagebox.showinfo("完成", "下载完成。"))
                except Exception as e:
                    self._log(f"\n错误：{e}\n")
                    self.root.after(0, (lambda err=e: messagebox.showerror("失败", str(err))))
                finally:
                    self._ui(lambda: self._set_progress(0, 1))
                    self.root.after(0, lambda: self._set_running(False))

            self._worker = threading.Thread(target=worker, daemon=True)
            self._worker.start()
def main() -> int:
    if tk is None or ttk is None or messagebox is None:
        err = _TK_ERROR
        print("错误：当前 Python 缺少 Tkinter/Tk 运行库，无法启动 GUI。")
        if err is not None:
            print(f"详情：{err}")
        print("\n解决方法（Ubuntu/WSL 常见）：")
        print("  sudo apt update && sudo apt install -y python3-tk tk")
        print("\n安装完成后再运行：")
        print("  python3 f1c_gui.py")
        return 1

    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    App(root)
    root.minsize(720, 520)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
