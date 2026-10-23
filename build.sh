#!/usr/bin/env bash
# 编译 deenfile.exe（MinGW，一条命令产出单文件 exe）
# MSYS2 环境： pacman -S mingw-w64-x86_64-gcc
set -e
cd "$(dirname "$0")"
gcc -O2 -s -municode -Wall -o deenfile.exe deenfile.c
echo "build ok -> $(pwd)/deenfile.exe"
