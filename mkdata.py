# -*- coding: utf-8 -*-
"""生成覆盖各种文件名边界的测试数据（写入 test_path）"""
import os
import shutil

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_path")

# 清空但保留原 test_file.txt
if os.path.isdir(ROOT):
    for e in os.listdir(ROOT):
        p = os.path.join(ROOT, e)
        if e == "test_file.txt":
            continue
        shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)

os.makedirs(ROOT, exist_ok=True)
os.makedirs(os.path.join(ROOT, "2026年度", "第三季度"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "文档 归档", "扫描件"), exist_ok=True)


def w(rel, data):
    p = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(p) else None
    with open(p, "wb") as f:
        f.write(data)


big = ("2026年度第三季度经营分析：营收同比+18.7%，毛利率41.2%。\n" * 200).encode("utf-8")
w("报告.docx", big)
w("合同 2026.pdf", b"%PDF-1.4\n" + b"x" * 3000)
w("README", b"no extension, all ascii\n" * 40)
w("a.txt", b"short\n")
w("中文 文件 名.txt", "中文内容测试\n".encode("utf-8") * 100)
w("数据-2026Q3.xlsx", b"PK\x03\x04" + b"\x00" * 2000)
w("empty.bin", b"")
w("tiny.txt", b"abc")
w("exact1024.bin", bytes((i * 7 + 3) % 256 for i in range(1024)))
w("emoji\U0001F600.txt", b"emoji name\n" * 10)
w("MixedCase-Name.TXT", b"case test\n" * 10)
w("2026年度/第三季度/经营分析会纪要.docx", b"nested 1\n" * 100)
w("2026年度/预算表.xlsx", b"nested 2\n" * 100)
w("文档 归档/扫描件/0001.jpg", b"\xff\xd8\xff\xe0" + b"J" * 900)
w("文档 归档/说明.txt", "归档说明\n".encode("utf-8") * 50)

# 长名：180 个汉字 + 扩展名（编码后 +2 仍在 255 以内）
w("长" * 180 + ".docx", b"long name\n" * 50)

print("测试数据就绪：")
for base, dirs, files in os.walk(ROOT):
    for n in dirs:
        print("  DIR   " + os.path.relpath(os.path.join(base, n), ROOT))
    for n in files:
        p = os.path.join(base, n)
        print("  FILE  %-46s %7d" % (os.path.relpath(p, ROOT), os.path.getsize(p)))
