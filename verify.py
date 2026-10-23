# -*- coding: utf-8 -*-
"""
deenfile 无损校验工具（测试用，非程序依赖）
配置来源与程序一致：注册表 HKCU\\Software\\deenfile

比对维度：完整相对路径（含目录名）/ 文件大小 / 内容 MD5 / 修改时间
用法:
  python verify.py snapshot before.json   # 对已登记目录做快照
  python verify.py compare  before.json   # 与快照比对
  python verify.py list                   # 打印当前所有文件与目录名
"""
import base64
import hashlib
import json
import os
import sys
import winreg

ROOT = os.path.dirname(os.path.abspath(__file__))


def deobf(s):
    raw = base64.b64decode(s)
    return bytes(b ^ 0x5A for b in raw).decode("utf-8")


def load_dirs():
    """从注册表读目录密文列表（REG_MULTI_SZ）"""
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\deenfile") as k:
        dirs, _ = winreg.QueryValueEx(k, "dirs")
    if isinstance(dirs, str):
        dirs = [dirs]
    return [deobf(d) for d in dirs if d.strip()]


def md5_of(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def snapshot():
    """记录 文件 与 目录 的完整相对路径，文件另记大小/MD5/mtime"""
    data = {}
    for d in load_dirs():
        if not os.path.isdir(d):
            data["__MISSING__:" + d] = None
            continue
        for base, dirs, files in os.walk(d):
            for name in dirs:
                rel = os.path.relpath(os.path.join(base, name), d)
                data[d + "|DIR|" + rel] = {"kind": "dir"}
            for name in files:
                p = os.path.join(base, name)
                rel = os.path.relpath(p, d)
                st = os.stat(p)
                data[d + "|FILE|" + rel] = {
                    "kind": "file",
                    "size": st.st_size,
                    "mtime": st.st_mtime_ns,
                    "md5": md5_of(p),
                }
    return data


def cmd_list():
    for d in load_dirs():
        print("=== " + d + ("  [不存在]" if not os.path.isdir(d) else ""))
        if not os.path.isdir(d):
            continue
        for base, dirs, files in os.walk(d):
            for name in dirs:
                print("  DIR   " + os.path.relpath(os.path.join(base, name), d))
            for name in files:
                p = os.path.join(base, name)
                print("  FILE  %-60s %8d" % (os.path.relpath(p, d), os.path.getsize(p)))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]

    if cmd == "list":
        cmd_list()
        return

    path = sys.argv[2]
    if cmd == "snapshot":
        data = snapshot()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        nf = sum(1 for v in data.values() if v and v["kind"] == "file")
        nd = sum(1 for v in data.values() if v and v["kind"] == "dir")
        print("snapshot: %d 文件 + %d 目录 -> %s" % (nf, nd, path))
        return

    if cmd == "compare":
        with open(path, "r", encoding="utf-8") as f:
            before = json.load(f)
        after = snapshot()
        bad = []
        for k in sorted(set(before) | set(after)):
            b, a = before.get(k), after.get(k)
            if b is None:
                bad.append((k, "多出条目"))
                continue
            if a is None:
                bad.append((k, "条目丢失"))
                continue
            if b["kind"] != a["kind"]:
                bad.append((k, "类型变了"))
                continue
            if b["kind"] == "dir":
                continue
            if b["size"] != a["size"]:
                bad.append((k, "大小 %d -> %d" % (b["size"], a["size"])))
            elif b["md5"] != a["md5"]:
                bad.append((k, "内容MD5 不一致"))
            elif b["mtime"] != a["mtime"]:
                bad.append((k, "修改时间被改变"))
        nf = sum(1 for v in before.values() if v and v["kind"] == "file")
        nd = sum(1 for v in before.values() if v and v["kind"] == "dir")
        if not bad:
            print("PASS %d 文件 + %d 目录：路径名/大小/内容MD5/修改时间 完全一致，无损还原" % (nf, nd))
        else:
            print("FAIL %d 处差异：" % len(bad))
            for k, why in bad[:25]:
                print("  -", k, "=>", why)
        return

    print(__doc__)


if __name__ == "__main__":
    main()
