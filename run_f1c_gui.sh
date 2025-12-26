#!/usr/bin/env bash
# 使脚本可双击（设置可执行权限）：
# chmod +x run_f1c_gui.sh
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$DIR/f1c_gui.py" "$@"
