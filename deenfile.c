/*
 * deenfile.c
 *
 * 支持的命令：
 *   deenfile                 无参数（双击）→ 交互界面
 *   deenfile add <dir>
 *   deenfile encode
 *   deenfile decode [force]
 *   deenfile pwd             修改密码（先全量解密 → 写新密码 → 重新加密）
 *   deenfile level [1|2]     安全等级：1=只改名字+隐藏目录（快），2=同时混淆文件头（慢）
 *
 * 三层处理：
 *   1) 目录隐藏：根目录改名追加 CLSID 后缀 + 隐藏/系统属性
 *   2) 文件名偏移：逐字符在同类字符环内固定偏移，长度严格不变（膨胀 1.00）
 *   3) 文件头混淆：只处理头部 1024 字节，文件尾追加 8 字节标记
 * 安全等级（level，注册表 REG_DWORD，缺省 1）：
 *   1 = 只做 1)+2)，不碰任何文件内容（快）
 *   2 = 三层全做（慢）
 *   改等级/改密码前都必须先全量解密，保证「注册表状态」与「文件实际状态」永远一致。
 *
 * 编译（MinGW，一条命令产出 deenfile.exe）：
 *   gcc -O2 -s -municode -Wall -o deenfile.exe deenfile.c
 * （MSVC: cl /O2 /W3 deenfile.c /Fe:deenfile.exe   —— 入口为 wmain）
 *
 * 输出约定：stdout 仅 ok / no pwd / decode ok；统计与提示走 stderr，不污染 stdout。
 *
 * 内部维护提示：本方案为可逆混淆而非加密，强度极低，仅防随手查看，细节见各函数注释。
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

/* 上帝模式 CLSID 后缀：资源管理器双击打不开、不显示内容 */
#define CLSID_SUFFIX L".{2559a1f2-21d7-11d4-bdaf-00c04f8b7c50}"
static const size_t SUFFIX_LEN = 39;   /* wcslen(CLSID_SUFFIX)：. + { + 36位UUID + } */

#define XOR_KEY 0x5A             /* 可逆混淆密钥（最低成本，非加密） */
#define MAXL    32768            /* 扩展路径缓冲（支持长路径） */

/* ---- 文件头混淆参数 ---- */
#define HEAD_LEN 1024            /* 只处理每个文件头部这么多字节 */
#define TAG_LEN  8               /* 追加在文件尾的标记长度 */
#define KEY_LEN  (HEAD_LEN + TAG_LEN)
static const unsigned char MAGIC[TAG_LEN] =
    { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
/* 魔数用「固定」密钥混淆：不能跟密码挂钩，否则密码不对时连魔数都认不出来 */
#define TAG_XOR 0xA5

/* ---- 注册表位置（固定） ---- */
#define REG_PATH     L"Software\\deenfile"
#define REG_PATH_OLD L"Software\\onoff"   /* 旧版路径：仅用于一次性自动迁移，迁移后不再写入 */
#define REG_PWD  L"pwd"          /* REG_SZ       : 密码密文 */
#define REG_DIRS L"dirs"         /* REG_MULTI_SZ : 目录密文，每项一个目录 */
#define REG_LEVEL L"level"       /* REG_DWORD    : 安全等级 1/2，缺省 1 */

/* ---- 退出码 ---- */
#define EXIT_PWD_ERR 1           /* 密码错误 / 密钥不匹配 */
#define EXIT_OP_ERR  2           /* 操作失败（改名失败等），不破坏原目录 */

/* ---- 单文件处理结果 ---- */
#define R_DONE        1          /* 已处理 */
#define R_SKIP_UNENC  0          /* 跳过：未加密 */
#define R_SKIP_ENC    2          /* 跳过：已是本密码加密 */
#define R_IOERR      (-1)        /* 打开/读写失败，未破坏文件 */
#define R_KEYMISMATCH (-2)       /* 魔数对但指纹不符：其它密码加密的文件 */
#define R_SMALL       3          /* 小文件：内容不碰，只改名 */

/* ---------------- 小工具 ---------------- */
static void *xmalloc(size_t n) { void *p = malloc(n); if (!p) exit(3); return p; }

static wchar_t *wdup(const wchar_t *s) {
    size_t n = wcslen(s) + 1;
    wchar_t *p = (wchar_t *)xmalloc(n * sizeof(wchar_t));
    memcpy(p, s, n * sizeof(wchar_t));
    return p;
}

static char *sdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)xmalloc(n);
    memcpy(p, s, n);
    return p;
}

/* 拼接：a + b */
static wchar_t *wcat(const wchar_t *a, const wchar_t *b) {
    size_t na = wcslen(a), nb = wcslen(b);
    wchar_t *p = (wchar_t *)xmalloc((na + nb + 1) * sizeof(wchar_t));
    memcpy(p, a, na * sizeof(wchar_t));
    memcpy(p + na, b, (nb + 1) * sizeof(wchar_t));
    return p;
}

/* ---------------- 输出（CLI 极简 / 交互中文宽字符） ---------------- */
static int g_inter = 0;          /* 1 = 交互模式（双击进入） */

/* 写宽字符串；目标是控制台时用 WriteConsoleW（中文不乱码），否则退回 UTF-8 */
static void wwrite(HANDLE h, const wchar_t *s) {
    DWORD mode = 0, n = 0;
    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, s, (DWORD)wcslen(s), &n, NULL);
    } else {
        int need = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
        if (need > 0) {
            char *u = (char *)xmalloc((size_t)need);
            WideCharToMultiByte(CP_UTF8, 0, s, -1, u, need, NULL, NULL);
            fputs(u, (h == GetStdHandle(STD_ERROR_HANDLE)) ? stderr : stdout);
            free(u);
        }
    }
}

/* 结果输出：永远走 stdout（CLI 下只有 ok / no pwd / decode ok） */
static void out(const wchar_t *s) { wwrite(GetStdHandle(STD_OUTPUT_HANDLE), s); }

/* 统计与提示：CLI 走 stderr（不污染 stdout）；交互模式直接显示在窗口里 */
static void note(const wchar_t *s) {
    wwrite(g_inter ? GetStdHandle(STD_OUTPUT_HANDLE) : GetStdHandle(STD_ERROR_HANDLE), s);
}

/* ---------------- UTF-8 <-> UTF-16 ---------------- */
static wchar_t *u8tow(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) n = 1;
    wchar_t *w = (wchar_t *)xmalloc((size_t)n * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static char *wtou8(const wchar_t *w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) n = 1;
    char *s = (char *)xmalloc((size_t)n);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

/* ---------------- Base64 ---------------- */
static const char B64T[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64enc(const unsigned char *in, size_t len) {
    size_t i = 0, o = 0;
    char *outb = (char *)xmalloc(((len + 2) / 3) * 4 + 1);
    while (i < len) {
        unsigned long v = 0;
        int got = 0, k;
        for (k = 0; k < 3 && i < len; k++) { v = (v << 8) | in[i++]; got++; }
        v <<= (3 - got) * 8;
        outb[o++] = B64T[(v >> 18) & 0x3F];
        outb[o++] = B64T[(v >> 12) & 0x3F];
        outb[o++] = (got > 1) ? B64T[(v >> 6) & 0x3F] : '=';
        outb[o++] = (got > 2) ? B64T[v & 0x3F] : '=';
    }
    outb[o] = 0;
    return outb;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static unsigned char *b64dec(const char *in, size_t *outlen) {
    size_t len = strlen(in), i = 0, o = 0;
    unsigned char *outb = (unsigned char *)xmalloc(len / 4 * 3 + 4);
    while (i + 4 <= len) {
        int c[4]; int k, ok = 1;
        for (k = 0; k < 4; k++) {                    /* '=' 填充按 0 处理，不中断 */
            char ch = in[i + k];
            if (ch == '=') c[k] = 0;
            else { c[k] = b64val(ch); if (c[k] < 0) ok = 0; }
        }
        if (!ok) break;
        unsigned long v = ((unsigned long)c[0] << 18) | ((unsigned long)c[1] << 12) |
                          ((unsigned long)c[2] << 6) | (unsigned long)c[3];
        outb[o++] = (unsigned char)(v >> 16);
        if (in[i + 2] != '=') outb[o++] = (unsigned char)((v >> 8) & 0xFF);
        if (in[i + 3] != '=') outb[o++] = (unsigned char)(v & 0xFF);
        i += 4;
    }
    *outlen = o;
    return outb;
}

/* ---------------- 混淆：obf(s) = Base64( s的各字节 ^ 0x5A ) ---------------- */
static char *obf_wstr(const wchar_t *s) {
    char *u8 = wtou8(s);
    size_t n = strlen(u8), i;
    unsigned char *tmp = (unsigned char *)xmalloc(n + 1);
    for (i = 0; i < n; i++) tmp[i] = (unsigned char)(u8[i] ^ XOR_KEY);  /* 逐字节 XOR */
    char *r = b64enc(tmp, n);
    free(tmp); free(u8);
    return r;
}

static wchar_t *deobf_str(const char *b64) {
    size_t n = 0, i;
    unsigned char *raw = b64dec(b64, &n);
    char *u8 = (char *)xmalloc(n + 1);
    for (i = 0; i < n; i++) u8[i] = (char)(raw[i] ^ XOR_KEY);           /* 逆运算 */
    u8[n] = 0;
    free(raw);
    wchar_t *w = u8tow(u8);
    free(u8);
    return w;
}

/* ---------------- 路径：转 \\?\ 扩展形式，支持长路径/中文 ---------------- */
static wchar_t *mk_ext(const wchar_t *full) {
    if (wcsncmp(full, L"\\\\?\\", 4) == 0) return wdup(full);
    if (wcsncmp(full, L"\\\\", 2) == 0) {          /* UNC -> \\?\UNC\... */
        wchar_t *r = (wchar_t *)xmalloc(MAXL * sizeof(wchar_t));
        _snwprintf(r, MAXL - 1, L"\\\\?\\UNC\\%s", full + 2);
        r[MAXL - 1] = 0;
        return r;
    }
    wchar_t *r = (wchar_t *)xmalloc(MAXL * sizeof(wchar_t));
    _snwprintf(r, MAXL - 1, L"\\\\?\\%s", full);
    r[MAXL - 1] = 0;
    return r;
}

/* 相对路径 -> 绝对路径 */
static wchar_t *to_full(const wchar_t *p) {
    DWORD need = GetFullPathNameW(p, 0, NULL, NULL);
    if (need == 0) return wdup(p);
    wchar_t *buf = (wchar_t *)xmalloc(((size_t)need + 2) * sizeof(wchar_t));
    GetFullPathNameW(p, need + 1, buf, NULL);
    return buf;
}

/* 是否磁盘根目录（禁止锁定 C:\、D:\） */
static int is_root(const wchar_t *full) {
    size_t n = wcslen(full);
    if (n == 3 && ((full[0] >= L'A' && full[0] <= L'Z') || (full[0] >= L'a' && full[0] <= L'z'))
        && full[1] == L':' && (full[2] == L'\\' || full[2] == L'/')) return 1;
    return 0;
}

static int has_suffix(const wchar_t *full) {
    size_t n = wcslen(full);
    if (n <= SUFFIX_LEN) return 0;
    return _wcsicmp(full + n - SUFFIX_LEN, CLSID_SUFFIX) == 0;
}

static int dir_exists(const wchar_t *full) {
    wchar_t *ep = mk_ext(full);
    DWORD a = GetFileAttributesW(ep);
    free(ep);
    return (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY));
}

/* ---------------- 配置：注册表 HKCU\Software\deenfile ---------------- */
typedef struct {
    char  *pwd;      /* 密码密文（Base64(XOR)） */
    char **items;    /* 目录密文，每项一个目录 */
    int    n;
    int    cap;
    int    level;    /* 安全等级：1=不改文件内容（快），2=改文件内容（慢） */
} Config;

static void cfg_add(Config *c, const char *s) {
    if (c->n + 1 > c->cap) {
        c->cap = c->cap ? c->cap * 2 : 8;
        c->items = (char **)realloc(c->items, (size_t)c->cap * sizeof(char *));
        if (!c->items) exit(3);
    }
    c->items[c->n++] = sdup(s);
}

static int cfg_save(const Config *c);   /* 前置声明：cfg_load 迁移时要用 */

/* 从指定注册表路径读配置，返回 1 = 读到密码 */
static int cfg_load_from(Config *c, const wchar_t *path) {
    memset(c, 0, sizeof(*c));
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
        return 0;

    DWORD type = 0, cb = 0;
    if (RegQueryValueExW(k, REG_PWD, NULL, &type, NULL, &cb) == ERROR_SUCCESS && cb > 2) {
        BYTE *buf = (BYTE *)xmalloc(cb + 8);
        memset(buf, 0, cb + 8);
        if (RegQueryValueExW(k, REG_PWD, NULL, &type, buf, &cb) == ERROR_SUCCESS) {
            wchar_t *w = (wchar_t *)buf;
            w[cb / 2] = 0;
            c->pwd = wtou8(w);
        }
        free(buf);
    }

    cb = 0;   /* REG_MULTI_SZ：每项 \0 分隔，整体双 \0 结束 */
    if (RegQueryValueExW(k, REG_DIRS, NULL, &type, NULL, &cb) == ERROR_SUCCESS && cb > 4) {
        BYTE *buf = (BYTE *)xmalloc(cb + 8);
        memset(buf, 0, cb + 8);
        if (RegQueryValueExW(k, REG_DIRS, NULL, &type, buf, &cb) == ERROR_SUCCESS) {
            wchar_t *p = (wchar_t *)buf;
            while (*p) {
                char *u8 = wtou8(p);
                if (u8[0]) cfg_add(c, u8);
                free(u8);
                p += wcslen(p) + 1;
            }
        }
        free(buf);
    }

    /* 安全等级：REG_DWORD，缺省 1（老用户没有这个键 → 保持最轻的行为） */
    c->level = 1;
    cb = sizeof(DWORD);
    {
        DWORD lv = 1;
        if (RegQueryValueExW(k, REG_LEVEL, NULL, &type, (BYTE *)&lv, &cb) == ERROR_SUCCESS &&
            type == REG_DWORD && (lv == 1 || lv == 2))
            c->level = (int)lv;
    }
    RegCloseKey(k);
    return (c->pwd != NULL);
}

/*
 * 读配置：优先新路径 HKCU\Software\deenfile。
 * 新路径不存在但旧路径 HKCU\Software\onoff 有数据 → 自动复制到新路径
 * （旧键保留不删，作为回滚点；程序此后只读写新路径）。
 */
static int cfg_load(Config *c) {
    if (cfg_load_from(c, REG_PATH)) return 1;

    Config old;
    if (cfg_load_from(&old, REG_PATH_OLD)) {
        *c = old;                       /* 接管旧配置 */
        cfg_save(c);                    /* 写入新路径（密码密文与目录密文原样搬运，无需重新加密文件） */
        note(L"[迁移] 注册表配置已从 HKCU\\Software\\onoff 复制到 HKCU\\Software\\deenfile\n"
             L"[迁移] 旧键保留作回滚点，程序此后只读写新键\n");
        return 1;
    }
    free(old.items);                    /* 旧路径也没有：保持空配置 */
    return 0;
}

/* 写注册表配置（密码密文 + 目录密文） */
static int cfg_save(const Config *c) {
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, NULL, 0,
                        KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &k, NULL) != ERROR_SUCCESS)
        return 0;

    wchar_t *pw = u8tow(c->pwd ? c->pwd : "");
    RegSetValueExW(k, REG_PWD, 0, REG_SZ, (const BYTE *)pw,
                   (DWORD)((wcslen(pw) + 1) * sizeof(wchar_t)));
    free(pw);

    size_t total = 2;                      /* 结尾双 \0 */
    int i;
    for (i = 0; i < c->n; i++) total += strlen(c->items[i]) + 1;
    wchar_t *ms = (wchar_t *)xmalloc(total * sizeof(wchar_t));
    wchar_t *w = ms;
    for (i = 0; i < c->n; i++) {
        wchar_t *it = u8tow(c->items[i]);
        size_t l = wcslen(it);
        memcpy(w, it, l * sizeof(wchar_t));
        w += l;
        *w++ = 0;
        free(it);
    }
    *w++ = 0;
    RegSetValueExW(k, REG_DIRS, 0, REG_MULTI_SZ, (const BYTE *)ms,
                   (DWORD)((w - ms) * sizeof(wchar_t)));
    free(ms);

    {
        DWORD lv = (c->level == 2) ? 2 : 1;    /* 归一化：只有 1/2 两个合法值 */
        RegSetValueExW(k, REG_LEVEL, 0, REG_DWORD, (const BYTE *)&lv, sizeof(lv));
    }
    RegCloseKey(k);
    return 1;
}

/* 旧版 config.ini 一次性迁移到注册表（迁移后改名 leaving 回滚点） */
static void cfg_migrate_ini(Config *c) {
    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, exe, MAX_PATH);
    if (n == 0) return;
    exe[n] = 0;
    wchar_t *slash = wcsrchr(exe, L'\\');
    if (!slash) return;
    *(slash + 1) = 0;
    wchar_t *ini = wcat(exe, L"config.ini");

    FILE *f = _wfopen(ini, L"rb");
    if (!f) { free(ini); return; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) sz = 0;
    char *buf = (char *)xmalloc((size_t)sz + 1);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = 0;
    fclose(f);

    memset(c, 0, sizeof(*c));
    char *p = buf;
    int idx = 0;
    while (p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        size_t l = strlen(p);
        while (l > 0 && (p[l - 1] == '\r' || p[l - 1] == ' ' || p[l - 1] == '\t')) p[--l] = 0;
        if (idx == 0) { if (l) c->pwd = sdup(p); }
        else if (l > 0) cfg_add(c, p);
        idx++;
        p = nl ? nl + 1 : NULL;
    }
    free(buf);

    if (c->pwd) {
        cfg_save(c);
        wchar_t *bak = wcat(exe, L"config.ini.migrated");
        MoveFileExW(ini, bak, MOVEFILE_REPLACE_EXISTING);
        free(bak);
        note(L"[迁移] config.ini 已导入注册表 HKCU\\Software\\deenfile，原文件改名为 config.ini.migrated\n");
    }
    free(ini);
}

/* ---------------- 输入（控制台不回显 / 管道回退 UTF-8） ---------------- */
static wchar_t *read_line(int hide) {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {                        /* 交互控制台 */
        DWORD old = mode;
        if (hide) SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);   /* 关闭回显 */
        wchar_t buf[1024];
        DWORD rd = 0;
        DWORD ok = ReadConsoleW(h, buf, 1023, &rd, NULL);
        if (hide) SetConsoleMode(h, old);
        if (!ok) return NULL;                              /* Ctrl+Z / 输入被关闭 */
        buf[rd] = 0;
        size_t l = wcslen(buf);
        while (l > 0 && (buf[l - 1] == L'\r' || buf[l - 1] == L'\n')) buf[--l] = 0;
        return wdup(buf);
    }
    /* 管道 / 重定向：按 UTF-8 读取一行 */
    char line[1024];
    int i = 0, ch = 0;
    while ((ch = fgetc(stdin)) != EOF && ch != '\n') {
        if (ch != '\r' && i < 1023) line[i++] = (char)ch;
    }
    line[i] = 0;
    if (ch == EOF && i == 0) return NULL;
    return u8tow(line);
}

/* 读密码：交互模式提示写在窗口里，CLI 写 stderr */
static wchar_t *read_pwd(const wchar_t *prompt) {
    if (prompt) {
        if (g_inter) out(prompt);
        else wwrite(GetStdHandle(STD_ERROR_HANDLE), prompt);
    }
    wchar_t *r = read_line(1);
    if (g_inter) out(L"\n");
    else wwrite(GetStdHandle(STD_ERROR_HANDLE), L"\n");
    return r ? r : wdup(L"");
}

/* ---------------- 目录隐藏 / 还原 ---------------- */

/* 隐藏一个目录：改名 + 隐藏/系统属性。返回 1=成功 0=跳过 -1=失败 */
static int hide_dir(const wchar_t *full) {
    if (has_suffix(full)) return 0;                        /* 已带 CLSID 后缀，禁止重复上锁 */
    wchar_t *ef = mk_ext(full);
    DWORD attr = GetFileAttributesW(ef);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {  /* 不存在则静默跳过 */
        free(ef);
        return 0;
    }
    wchar_t *neu = wcat(full, CLSID_SUFFIX);
    wchar_t *en  = mk_ext(neu);
    if (GetFileAttributesW(en) != INVALID_FILE_ATTRIBUTES) { free(ef); free(neu); free(en); return 0; }
    if (!MoveFileW(ef, en)) { free(ef); free(neu); free(en); return -1; }         /* 改名失败：不破坏原目录 */
    DWORD a2 = GetFileAttributesW(en);
    if (a2 != INVALID_FILE_ATTRIBUTES)
        SetFileAttributesW(en, a2 | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    free(ef); free(neu); free(en);
    return 1;
}

/* 恢复一个目录：清属性 + 改名还原。返回 1=成功 0=跳过 -1=失败 */
static int show_dir(const wchar_t *full) {
    wchar_t *neu = wcat(full, CLSID_SUFFIX);
    wchar_t *en  = mk_ext(neu);
    DWORD attr = GetFileAttributesW(en);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        free(neu); free(en);
        return 0;
    }
    DWORD keep = attr & ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    if (keep == 0) keep = FILE_ATTRIBUTE_NORMAL;
    SetFileAttributesW(en, keep);                          /* 先清隐藏/系统属性 */
    wchar_t *ef = mk_ext(full);
    if (!MoveFileW(en, ef)) { free(neu); free(en); free(ef); return -1; }
    free(neu); free(en); free(ef);
    return 1;
}

/* ---------------- 文件头混淆核心 ---------------- */

/*
 * 由密码派生 XOR 密钥流（1032 字节）。
 * 注意：这是「混淆」不是「加密」——FNV-1a 哈希做种子 + LCG 展开，强度极低，
 * 目的只是让不同密码产生不同的头部乱码，不提供任何真实的密码学保护。
 */
static void derive_key(const wchar_t *pwd, unsigned char *K) {
    char *u8 = wtou8(pwd);
    size_t n = strlen(u8), i;
    unsigned long long h = 1469598103934665603ULL;              /* FNV-1a 64 初值 */
    for (i = 0; i < n; i++) { h ^= (unsigned char)u8[i]; h *= 1099511628211ULL; }
    if (h == 0) h = 0x9E3779B97F4A7C15ULL;
    unsigned long long s = h;
    for (i = 0; i < KEY_LEN; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL; /* LCG */
        K[i] = (unsigned char)((s >> 33) ^ (s >> 21) ^ (s >> 13));
    }
    free(u8);
}

/* 密钥指纹（2 字节）：区分「本密码加密」与「其它密码加密」 */
static void key_fp(const unsigned char *K, unsigned char fp[2]) {
    unsigned long h = 2166136261u;                             /* FNV-1a 32 */
    int i;
    for (i = 0; i < HEAD_LEN; i++) { h ^= K[i]; h *= 16777619u; }
    fp[0] = (unsigned char)(h & 0xFF);
    fp[1] = (unsigned char)((h >> 8) & 0xFF);
}

/* 生成标记：魔数 6 字节（固定密钥混淆）+ 指纹 2 字节（密码密钥混淆） */
static void make_tag(const unsigned char *K, unsigned char tag[TAG_LEN]) {
    unsigned char fp[2];
    size_t i;
    key_fp(K, fp);
    for (i = 0; i < 6; i++) tag[i] = (unsigned char)(MAGIC[i] ^ TAG_XOR);
    tag[6] = (unsigned char)(fp[0] ^ K[HEAD_LEN + 6]);
    tag[7] = (unsigned char)(fp[1] ^ K[HEAD_LEN + 7]);
}

/* 读文件尾 8 字节判定：0=未加密 1=本密码加密 2=其它密码加密 */
static int classify_tail(HANDLE h, const unsigned char *K, LONGLONG size) {
    if (size < TAG_LEN) return 0;
    unsigned char tail[TAG_LEN], fp[2];
    DWORD rd = 0;
    LARGE_INTEGER li; li.QuadPart = -(LONGLONG)TAG_LEN;
    if (!SetFilePointerEx(h, li, NULL, FILE_END)) return 0;
    if (!ReadFile(h, tail, TAG_LEN, &rd, NULL) || rd != TAG_LEN) return 0;

    size_t i;
    int newm = 1, oldm = 1;
    for (i = 0; i < 6; i++) {
        if ((unsigned char)(tail[i] ^ TAG_XOR) != MAGIC[i]) newm = 0;   /* 新格式：固定密钥 */
        if ((unsigned char)(tail[i] ^ K[HEAD_LEN + i]) != MAGIC[i]) oldm = 0;  /* 旧格式：密码密钥 */
        if (!newm && !oldm) break;
    }

    if (newm) {
        key_fp(K, fp);
        if ((unsigned char)(tail[6] ^ K[HEAD_LEN + 6]) == fp[0] &&
            (unsigned char)(tail[7] ^ K[HEAD_LEN + 7]) == fp[1]) return 1;  /* 魔数对 + 指纹对 */
        return 2;                                                          /* 魔数对 + 指纹错 → 别的密码 */
    }
    if (oldm) return 1;   /* 兼容旧版（魔数也走密码 XOR，无指纹）：只当是同一密码 */
    return 0;             /* 两套都对不上 → 不是本程序加密的 */
}

/*
 * 单个文件的头混淆 / 还原。只读写 [0, n) 与文件尾 8 字节，其余部分一律不碰。
 * enc=1 加密，enc=0 解密；force=1 时忽略「未加密 / 密钥不符」判定（仅用于异常恢复）
 */
static int xor_one_file(const wchar_t *path, const unsigned char *K, int enc, int force) {
    wchar_t *ep = mk_ext(path);
    HANDLE h = CreateFileW(ep, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(ep);
    if (h == INVALID_HANDLE_VALUE) return R_IOERR;   /* 占用/只读/无权限 → 跳过，绝不破坏 */

    FILETIME ct, at, wt;
    int has_t = GetFileTime(h, &ct, &at, &wt);       /* 记录原时间，结束后原样恢复 */

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return R_IOERR; }

    int st = classify_tail(h, K, sz.QuadPart);       /* 三态判定 */
    unsigned char tag[TAG_LEN];
    make_tag(K, tag);
    int r = R_DONE;

    if (enc) {
        /* 已是本密码加密 → 跳过；是别的密码加密 → 绝不二次 XOR（会彻底毁数据） */
        if (st == 1) { r = R_SKIP_ENC; goto done; }
        if (st == 2) { r = R_KEYMISMATCH; goto done; }

        /* 小于 1024 字节的文件：整份内容都落在「头部」范围内，一旦处理就等于整个文件被重写。
         * 为了让「绝不破坏源文件」有绝对保证，这类文件的内容一律不碰（不 XOR、不加标记），
         * 只由 rename_tree 改文件名。解码时它没有标记 → 自动跳过，不会报错。 */
        if (sz.QuadPart < (LONGLONG)HEAD_LEN) { r = R_SMALL; goto done; }

        size_t n = (sz.QuadPart > (LONGLONG)HEAD_LEN) ? HEAD_LEN : (size_t)sz.QuadPart;
        if (n > 0) {
            unsigned char *buf = (unsigned char *)xmalloc(n);
            DWORD rd = 0, wr = 0;
            LARGE_INTEGER li; li.QuadPart = 0;
            SetFilePointerEx(h, li, NULL, FILE_BEGIN);
            if (!ReadFile(h, buf, (DWORD)n, &rd, NULL) || rd != (DWORD)n) { free(buf); r = R_IOERR; goto done; }
            size_t i;
            for (i = 0; i < n; i++) buf[i] ^= K[i];                 /* 仅头部 XOR */
            SetFilePointerEx(h, li, NULL, FILE_BEGIN);
            if (!WriteFile(h, buf, (DWORD)n, &wr, NULL) || wr != (DWORD)n) { free(buf); r = R_IOERR; goto done; }
            free(buf);
        }
        /* 再追加标记：若中途崩溃，最坏结果是「没加密成功」，原始数据仍完好 */
        LARGE_INTEGER li; li.QuadPart = 0;
        DWORD wr = 0;
        if (!SetFilePointerEx(h, li, NULL, FILE_END) ||
            !WriteFile(h, tag, TAG_LEN, &wr, NULL) || wr != TAG_LEN) { r = R_IOERR; goto done; }
        r = R_DONE;
    } else {
        if (st == 0 && !force) { r = R_SKIP_UNENC; goto done; }     /* 未加密 → 不动 */
        if (st == 2 && !force) { r = R_KEYMISMATCH; goto done; }    /* 别的密码 → 不动，避免解出垃圾 */

        LONGLONG body = sz.QuadPart - ((st != 0) ? TAG_LEN : 0);
        size_t n = (body > (LONGLONG)HEAD_LEN) ? HEAD_LEN : (size_t)body;
        if (n > 0) {
            unsigned char *buf = (unsigned char *)xmalloc(n);
            DWORD rd = 0, wr = 0;
            LARGE_INTEGER z; z.QuadPart = 0;
            SetFilePointerEx(h, z, NULL, FILE_BEGIN);
            if (!ReadFile(h, buf, (DWORD)n, &rd, NULL) || rd != (DWORD)n) { free(buf); r = R_IOERR; goto done; }
            size_t i;
            for (i = 0; i < n; i++) buf[i] ^= K[i];                 /* XOR 自逆 → 逐字节还原 */
            SetFilePointerEx(h, z, NULL, FILE_BEGIN);
            if (!WriteFile(h, buf, (DWORD)n, &wr, NULL) || wr != (DWORD)n) { free(buf); r = R_IOERR; goto done; }
            free(buf);
        }
        /* 头部已还原后再截断标记：崩溃最坏结果是多留 8 字节尾部，主体数据无损 */
        if (st != 0) {
            LARGE_INTEGER e; e.QuadPart = -(LONGLONG)TAG_LEN;
            if (!SetFilePointerEx(h, e, NULL, FILE_END) || !SetEndOfFile(h)) { r = R_IOERR; goto done; }
        }
        r = R_DONE;
    }

done:
    if (has_t) SetFileTime(h, &ct, &at, &wt);   /* 时间原样恢复，做到「无痕」 */
    CloseHandle(h);
    return r;
}

typedef struct { long done, skip, km, fail; long ren, rnskip, rnfail; long small; } Stats;

/* 递归处理目录下所有文件（子目录照常进入，重解析点不跟进） */
static void xor_tree(const wchar_t *dir, const unsigned char *K, int enc, int force, Stats *s) {
    wchar_t *pat = wcat(dir, L"\\*");
    wchar_t *ep  = mk_ext(pat);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(ep, &fd);
    free(pat); free(ep);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;   /* 符号链接/挂载点：不跟进 */
        wchar_t *tmp = wcat(dir, L"\\");
        wchar_t *child = wcat(tmp, fd.cFileName);
        free(tmp);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            xor_tree(child, K, enc, force, s);
        } else {
            if (_wcsicmp(fd.cFileName, L"config.ini") == 0 ||
                _wcsicmp(fd.cFileName, L"config.ini.migrated") == 0) { free(child); continue; }
            int r = xor_one_file(child, K, enc, force);
            if (r == R_DONE) s->done++;
            else if (r == R_KEYMISMATCH) s->km++;
            else if (r == R_IOERR) s->fail++;
            else if (r == R_SMALL) s->small++;
            else s->skip++;
        }
        free(child);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

/* ---------------- 文件名码点偏移 ----------------
 *
 * 目的：文件名本身是最大的信息泄露点（「2026年度考核方案.docx」看一眼就知道内容），
 *       而且比文件内容更容易被随手看到、被搜索、被同步工具索引。
 *
 * 规则：逐字符在「同类字符环」内做固定偏移，**长度严格不变**。
 *   汉字  U+4E00–U+9FA5 (20902 字)   偏移 7919
 *   大写  A-Z (26)                    偏移 17
 *   小写  a-z (26)                    偏移 17
 *   数字  0-9 (10)                    偏移 7
 *   其它  符号 / 空格 / 全角 / 假名 / 韩文 / emoji / 代理对 → 原样不动
 *
 * 为什么必须分环：NTFS 大小写不敏感（实测 ABC.txt 与 abc.txt 是同一个文件），
 *   若把 A-Z 与 a-z 混成一个 52 字环，偏移后可能撞成同一个名字 → 吞文件。
 *   分环后大小写形态严格不变，绝不撞名。
 *
 * 为什么是双射：每个环内取模回绕，映射是一一对应，
 *   所以逆变换必然逐字符还原，长度不变、一个字符都不会丢 → 文件名的无损性有数学保证。
 *
 * 状态标记：处理过的名字前加 ".."（2 字符）。
 *   实测 ".." 后还有字符时是合法的普通名字（目录也行），Windows 不当作父目录，
 *   GetFullPathNameW / FindFirstFileW 均正常。于是「是否已处理」直接写在名字里：
 *     - 幂等：已带 ".." 的跳过，不会二次偏移
 *     - 无状态：不需要任何清单，复制/移动/打包/换机器状态都跟着名字走
 *     - 可判定：看名字就知道，崩溃中断后重跑天然收敛
 *   代价：每个名字 +2 字符，短名膨胀约 1.2，长名接近 1.0（与名字长度无关的固定 +2）。
 *
 * 安全性：这是「可预测的字符置换」，不提供任何密码学保护，拿到程序就能反推。
 *   设计目标是「防随手看见」+ 绝对可逆，不是加密。
 */

#define FNAME_TAG   L".."                 /* 状态前缀：已处理 */
#define FNAME_TAGL  2

#define CJK_LO 0x4E00                     /* 汉字环下界 */
#define CJK_HI 0x9FA5                     /* 汉字环上界（CJK 基本区，20902 字） */
#define CJK_N  20902                      /* CJK_HI - CJK_LO + 1 */
#define CJK_K  7919                       /* 汉字偏移量（大素数，肉眼完全无法还原） */
#define ALP_K  17                         /* 字母偏移量 */
#define DIG_K  7                          /* 数字偏移量 */

/* 单字符偏移。dec=1 为逆变换。环外字符原样返回（含代理对，emoji 不会被打散） */
static wchar_t shift_one(wchar_t c, int dec) {
    int v;
    if (c >= CJK_LO && c <= CJK_HI) {
        v = (int)(c - CJK_LO);
        v = dec ? (v - CJK_K % CJK_N + CJK_N) % CJK_N : (v + CJK_K) % CJK_N;
        return (wchar_t)(CJK_LO + v);
    }
    if (c >= L'A' && c <= L'Z') {
        v = (int)(c - L'A');
        v = dec ? (v + 26 - ALP_K) % 26 : (v + ALP_K) % 26;
        return (wchar_t)(L'A' + v);
    }
    if (c >= L'a' && c <= L'z') {
        v = (int)(c - L'a');
        v = dec ? (v + 26 - ALP_K) % 26 : (v + ALP_K) % 26;
        return (wchar_t)(L'a' + v);
    }
    if (c >= L'0' && c <= L'9') {
        v = (int)(c - L'0');
        v = dec ? (v + 10 - DIG_K) % 10 : (v + DIG_K) % 10;
        return (wchar_t)(L'0' + v);
    }
    return c;
}

static wchar_t *name_shift(const wchar_t *s, int dec) {
    size_t n = wcslen(s), i;
    wchar_t *r = (wchar_t *)xmalloc((n + 1) * sizeof(wchar_t));
    for (i = 0; i < n; i++) r[i] = shift_one(s[i], dec);
    r[n] = 0;
    return r;
}

/*
 * 目标名是否命中 Windows 保留设备名。
 * 必须自己拦：程序全程用 \\?\ 前缀，而 \\?\ 会「绕过」保留名检查
 * （实测能创建出名为 NUL 的文件，之后普通方式删不掉）。命中则整个条目跳过不改名。
 */
static int name_reserved(const wchar_t *name) {
    static const wchar_t *R[] = {
        L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$",
        L"COM0", L"COM1", L"COM2", L"COM3", L"COM4",
        L"COM5", L"COM6", L"COM7", L"COM8", L"COM9",
        L"LPT0", L"LPT1", L"LPT2", L"LPT3", L"LPT4",
        L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9"
    };
    wchar_t base[16];
    size_t i = 0, k;
    /* 取第一个点之前的部分（Windows 对 con.txt 同样判为设备）*/
    while (name[i] && name[i] != L'.' && i < 15) { base[i] = name[i]; i++; }
    while (i > 0 && base[i - 1] == L' ') i--;     /* 去掉尾部空格 */
    base[i] = 0;
    for (k = 0; k < sizeof(R) / sizeof(R[0]); k++)
        if (_wcsicmp(base, R[k]) == 0) return 1;
    return 0;
}

/* 名字是否带 ".." 状态前缀（".." 本身不可能是合法文件名，故 2 字符以上才算） */
static int name_tagged(const wchar_t *n) {
    return wcslen(n) > FNAME_TAGL && wcsncmp(n, FNAME_TAG, FNAME_TAGL) == 0;
}

/* 计算目标名。返回 NULL = 无需处理（未加密的不动，已处理后不再动） */
static wchar_t *name_target(const wchar_t *n, int enc) {
    if (!n || !*n) return NULL;
    if (enc) {
        if (name_tagged(n)) return NULL;              /* 已处理 → 幂等跳过，绝不二次偏移 */
        wchar_t *sh = name_shift(n, 0);
        wchar_t *t = wcat(FNAME_TAG, sh);
        free(sh);
        return t;
    }
    if (!name_tagged(n)) return NULL;                 /* 未处理 → 一个字符都不动 */
    return name_shift(n + FNAME_TAGL, 1);
}

/*
 * 递归改名。顺序：先递归子目录内部，再改本层名字 —— 这样每一层的路径在处理期间都稳定：
 *   若先改父目录名，父目录改名后子项路径全部失效；反过来先处理子项则不受影响。
 *
 * 不需要「临时名两阶段」：偏移是双射，同一批里目标名互不相同；
 * 而 MoveFileW 目标已存在时会返回 183 拒绝覆盖 —— 撞名只会失败、绝不会丢文件。
 * 每个条目是独立的单次原子改名，崩溃中断后靠 ".." 前缀天然收敛。
 */
static void rename_tree(const wchar_t *dir, int enc, Stats *s) {
    typedef struct { wchar_t *name; int isdir; } Ent;

    wchar_t *pat = wcat(dir, L"\\*");
    wchar_t *ep  = mk_ext(pat);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(ep, &fd);
    free(pat); free(ep);
    if (h == INVALID_HANDLE_VALUE) return;

    Ent *v = NULL;
    int n = 0, cap = 0;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;   /* 链接/挂载点：不跟进也不改名 */
        if (_wcsicmp(fd.cFileName, L"config.ini") == 0 ||
            _wcsicmp(fd.cFileName, L"config.ini.migrated") == 0) continue;
        if (n + 1 > cap) {
            cap = cap ? cap * 2 : 64;
            v = (Ent *)realloc(v, (size_t)cap * sizeof(Ent));
            if (!v) exit(3);
        }
        v[n].name  = wdup(fd.cFileName);
        v[n].isdir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        n++;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (!n) { free(v); return; }

    /* 1) 递归子目录（用当前名字，本层名字还没动） */
    for (int i = 0; i < n; i++) {
        if (!v[i].isdir) continue;
        wchar_t *t1 = wcat(dir, L"\\");
        wchar_t *cd = wcat(t1, v[i].name);
        free(t1);
        rename_tree(cd, enc, s);
        free(cd);
    }

    /* 2) 改本层名字 */
    for (int i = 0; i < n; i++) {
        wchar_t *tgt = name_target(v[i].name, enc);
        if (!tgt) continue;
        /* NTFS 单名上限 255 个 UTF-16 码元；超限或命中保留名 → 跳过，原名保留 */
        if (wcslen(tgt) > 255 || name_reserved(tgt)) { s->rnskip++; free(tgt); continue; }

        wchar_t *t1 = wcat(dir, L"\\");
        wchar_t *from = wcat(t1, v[i].name);
        free(t1);
        wchar_t *t2 = wcat(dir, L"\\");
        wchar_t *to = wcat(t2, tgt);
        free(t2);
        wchar_t *ef = mk_ext(from), *et = mk_ext(to);
        if (MoveFileW(ef, et)) s->ren++;
        else s->rnfail++;                    /* 占用/撞名：只记失败，原名不受影响 */
        free(ef); free(et); free(from); free(to); free(tgt);
    }

    for (int i = 0; i < n; i++) free(v[i].name);
    free(v);
}

/* ---------------- 命令实现 ---------------- */

/*
 * 密码校验：所有需要密码的命令统一走这里。
 * 空/未设置密码一律判失败 —— 防止「注册表里密码为空时，输入空串就能通过」的绕过。
 */
static int verify_pwd(const Config *c, const wchar_t *in) {
    if (!c->pwd || c->pwd[0] == 0) return 0;      /* 未设密码 → 任何操作都不许 */
    if (!in || in[0] == 0) return 0;              /* 空密码 → 直接拒绝 */
    char *enc = obf_wstr(in);
    int ok = (strcmp(enc, c->pwd) == 0);
    free(enc);
    return ok;
}

/* 统一的密码门：提示输入 → 校验。
 * 成功返回密码明文（调用方用完必须 wipe_pwd），失败输出 no pwd 并返回 NULL。
 * 所有需要密码的命令都必须先过这道门，没密码什么都不做。 */
static wchar_t *ask_pwd(const Config *c) {
    wchar_t *in = read_pwd(g_inter ? L"请输入密码: " : L"password: ");
    if (!in) return NULL;
    if (!verify_pwd(c, in)) {
        SecureZeroMemory(in, wcslen(in) * sizeof(wchar_t));
        free(in);
        out(L"no pwd\n");
        return NULL;
    }
    return in;
}

/* 用完立即抹掉内存里的密码明文 */
static void wipe_pwd(wchar_t *p) {
    if (!p) return;
    SecureZeroMemory(p, wcslen(p) * sizeof(wchar_t));
    free(p);
}

static void report(const wchar_t *verb, Stats *s) {
    wchar_t b[384];
    _snwprintf(b, 383, L"files: %ld %s, %ld skip, %ld small, %ld key-mismatch, %ld fail\n"
                        L"names: %ld %s, %ld skip, %ld fail\n",
               s->done, verb, s->skip, s->small, s->km, s->fail,
               s->ren, verb, s->rnskip, s->rnfail);
    b[383] = 0;
    note(b);
}

/* ---------------- 全量编解码（encode / decode / pwd / level 共用） ---------------- */

/* decode_all 返回值 */
#define DEC_OK   0              /* 全部成功 */
#define DEC_KM   1              /* 有其它密钥加密的文件 */
#define DEC_ERR  2              /* 有失败（改名/还原目录失败等） */

/*
 * 对所有登记路径执行解码（目录名还原 + 文件内容还原）。
 * 与安全等级无关：解码永远按「文件实际状态」来（有没有标记决定动不动内容），
 * 否则等级 1 下加密的文件在等级 2 时就解不掉了。
 * force 透传给 xor_tree。返回 DEC_OK / DEC_KM / DEC_ERR。
 */
static int decode_all(const Config *c, const unsigned char *K, int force, Stats *s) {
    int bad = 0;
    for (int i = 0; i < c->n; i++) {
        wchar_t *p = deobf_str(c->items[i]);
        Stats d = { 0 };
        wchar_t *hp = wcat(p, CLSID_SUFFIX);
        int hidden = dir_exists(hp);
        /* 先还原名字、再还原内容：内容处理期间用原名，更接近「正常状态」 */
        if (hidden) { rename_tree(hp, 0, &d); xor_tree(hp, K, 0, force, &d); }
        else        { rename_tree(p,  0, &d); xor_tree(p,  K, 0, force, &d); }
        free(hp);
        /* 只有密钥都对上才还原目录名：密码不匹配时保持目录隐藏，不留「开着门却是密文」的半成品 */
        if (d.km == 0) {
            if (show_dir(p) < 0) bad = 1;
        }
        s->done += d.done; s->skip += d.skip; s->km += d.km; s->fail += d.fail;
        s->ren += d.ren; s->rnskip += d.rnskip; s->rnfail += d.rnfail;
        s->small += d.small;
        free(p);
    }
    if (s->km) return DEC_KM;
    if (bad || s->fail) return DEC_ERR;
    return DEC_OK;
}

/*
 * 对所有登记路径执行编码（先混淆文件、再改名字、最后隐藏目录）。
 * 等级 1：跳过 xor_tree，只改文件名 + 隐藏目录，不碰任何文件内容（快）；
 * 等级 2：三层全做（慢）。
 */
static int encode_all(const Config *c, const unsigned char *K, Stats *s) {
    int bad = 0;
    for (int i = 0; i < c->n; i++) {
        wchar_t *p = deobf_str(c->items[i]);
        Stats d = { 0 };
        /* 先混淆文件、再改名字：
         * 内容处理期间路径保持原名，改名放在最后，避免处理途中路径失效 */
        if (dir_exists(p)) {
            if (c->level >= 2) xor_tree(p, K, 1, 0, &d);
            rename_tree(p, 1, &d);
        } else {
            wchar_t *hp = wcat(p, CLSID_SUFFIX);
            if (dir_exists(hp)) {
                if (c->level >= 2) xor_tree(hp, K, 1, 0, &d);
                rename_tree(hp, 1, &d);
            }
            free(hp);
        }
        /* 目录里混着「其它密码」加密的文件时先不隐藏，避免做出半成品 */
        if (d.km == 0) {
            if (hide_dir(p) < 0) bad = 1;
        } else {
            note(L"警告：存在其它密钥的文件，本次跳过\n");
        }
        s->done += d.done; s->skip += d.skip; s->km += d.km; s->fail += d.fail;
        s->ren += d.ren; s->rnskip += d.rnskip; s->rnfail += d.rnfail;
        s->small += d.small;
        free(p);
    }
    report(L"enc", s);
    if (s->km) note(L"警告：检测到其它密钥的文件，已跳过\n");
    if (bad || s->fail || s->km) return EXIT_OP_ERR;
    return 0;
}

/* encode：从注册表密文反解密码派生密钥 → 混淆文件 → 隐藏目录 */
static int do_encode(const Config *c) {
    unsigned char K[KEY_LEN];
    if (!c->pwd) { out(L"ok\n"); return 0; }
    wchar_t *pw = deobf_str(c->pwd);
    derive_key(pw, K);
    free(pw);

    Stats s = { 0 };
    int r = encode_all(c, K, &s);
    if (r == 0) out(L"ok\n");
    return r;
}

/* decode：校验密码 → 还原目录 → 还原文件 */
static int do_decode(const Config *c, int force) {
    wchar_t *in = ask_pwd(c);              /* 没有正确密码 → 直接退出，不做任何事 */
    if (!in) return EXIT_PWD_ERR;

    unsigned char K[KEY_LEN];
    derive_key(in, K);
    wipe_pwd(in);

    Stats s = { 0 };
    int st = decode_all(c, K, force, &s);
    report(L"dec", &s);

    /* 兜底：有文件是别的密码加密的 → 明确报错，不再假成功 */
    if (st == DEC_KM) {
        note(L"错误：密钥不匹配，未做任何修改\n");
        out(L"no pwd\n");
        return EXIT_PWD_ERR;
    }
    if (st == DEC_ERR) return EXIT_OP_ERR;
    out(L"decode ok\n");
    return 0;
}

/* add：校验密码 → 混淆文件 → 隐藏目录 → 登记注册表 */
static int do_add(Config *c, const wchar_t *path) {
    wchar_t *in = ask_pwd(c);              /* 没有正确密码 → 直接退出，不做任何事 */
    if (!in) return EXIT_PWD_ERR;

    wchar_t *full = to_full(path);
    size_t l = wcslen(full);
    while (l > 1 && full[l - 1] == L'\\') { full[--l] = 0; }    /* 去掉尾部反斜杠 */
    if (is_root(full) || has_suffix(full) || !dir_exists(full)) { free(full); wipe_pwd(in); return EXIT_OP_ERR; }

    unsigned char K[KEY_LEN];
    derive_key(in, K);
    wipe_pwd(in);

    Stats s = { 0 };
    if (c->level >= 2) xor_tree(full, K, 1, 0, &s);     /* 先混淆内容（原名路径）；等级 1 不碰内容 */
    rename_tree(full, 1, &s);                           /* 再改名字（内容已处理完） */
    if (hide_dir(full) <= 0) { free(full); return EXIT_OP_ERR; }   /* 改名失败：不写配置 */
    report(L"enc", &s);

    char *rec = obf_wstr(full);
    int dup = 0;
    for (int i = 0; i < c->n; i++) if (strcmp(c->items[i], rec) == 0) dup = 1;
    if (!dup) cfg_add(c, rec);
    free(rec);
    cfg_save(c);
    free(full);
    out(L"ok\n");
    return 0;
}

/*
 * pwd：修改密码。
 *
 * 顺序是硬约束：必须先用「旧密码」把全部登记路径解密成功，才能写新密码。
 * 否则注册表是新密码、文件还是旧密码加密，两边对不上，谁也解不开。
 * 解密全部成功后：写新密码 → 用新密码重新加密全部路径（恢复保护状态）。
 */
static int do_pwd(Config *c) {
    wchar_t *in = ask_pwd(c);                 /* 先验旧密码 */
    if (!in) return EXIT_PWD_ERR;

    wchar_t *p1 = read_pwd(g_inter ? L"请输入新密码: " : L"new password: ");
    wchar_t *p2 = read_pwd(g_inter ? L"请再输入一次: " : L"confirm: ");
    if (!p1 || !p2 || wcscmp(p1, p2) != 0 || wcslen(p1) == 0) {
        note(L"两次输入不一致或为空，已取消\n");
        wipe_pwd(in); wipe_pwd(p1); wipe_pwd(p2);
        return EXIT_OP_ERR;
    }

    unsigned char K[KEY_LEN];
    derive_key(in, K);

    /* 1) 旧密码全量解密：不完全成功就整体放弃，注册表一个字都不改 */
    Stats s = { 0 };
    int st = decode_all(c, K, 0, &s);
    report(L"dec", &s);
    if (st != DEC_OK) {
        note(L"错误：解密未完全成功，已取消修改密码（注册表未改动）\n");
        wipe_pwd(in); wipe_pwd(p1); wipe_pwd(p2);
        return (st == DEC_KM) ? EXIT_PWD_ERR : EXIT_OP_ERR;
    }

    /* 2) 写新密码：先保证全部文件已回到明文，再动注册表 */
    char *np  = obf_wstr(p1);
    char *old = c->pwd;
    c->pwd = np;
    if (!cfg_save(c)) {
        c->pwd = old;                          /* 回滚内存状态，与注册表保持一致 */
        free(np);
        note(L"错误：注册表写入失败，密码未修改（文件已全部解密，可重试）\n");
        wipe_pwd(in); wipe_pwd(p1); wipe_pwd(p2);
        return EXIT_OP_ERR;
    }
    free(old);

    /* 3) 新密码重新加密，恢复保护状态 */
    derive_key(p1, K);
    Stats s2 = { 0 };
    int r = encode_all(c, K, &s2);
    wipe_pwd(in); wipe_pwd(p1); wipe_pwd(p2);
    if (r != 0) {
        note(L"警告：重新加密未完全成功，请重试 encode\n");
        return r;
    }
    out(L"ok\n");
    return 0;
}

/*
 * level：修改安全等级。
 *   1 = 只改文件名 + 隐藏目录，不碰任何文件内容（快）
 *   2 = 同时混淆文件头（慢）
 * 与 pwd 同理：必须先把全部路径解密成功（文件内容回到明文），
 * 才能改等级并按新等级重新保护，避免「注册表等级」与「文件实际状态」不一致。
 */
static int do_level(Config *c, int lv) {
    wchar_t *in = ask_pwd(c);
    if (!in) return EXIT_PWD_ERR;

    unsigned char K[KEY_LEN];
    derive_key(in, K);

    /* 1) 全量解密：不完全成功就整体放弃，注册表一个字都不改 */
    Stats s = { 0 };
    int st = decode_all(c, K, 0, &s);
    report(L"dec", &s);
    if (st != DEC_OK) {
        note(L"错误：解密未完全成功，已取消修改等级（注册表未改动）\n");
        wipe_pwd(in);
        return (st == DEC_KM) ? EXIT_PWD_ERR : EXIT_OP_ERR;
    }

    /* 2) 写等级 */
    int old = c->level;
    c->level = lv;
    if (!cfg_save(c)) {
        c->level = old;
        note(L"错误：注册表写入失败，等级未修改\n");
        wipe_pwd(in);
        return EXIT_OP_ERR;
    }

    /* 3) 按新等级重新保护（等级 1 不碰内容，等级 2 混淆文件头） */
    Stats s2 = { 0 };
    int r = encode_all(c, K, &s2);
    wipe_pwd(in);
    if (r != 0) {
        note(L"警告：重新加密未完全成功，请重试 encode\n");
        return r;
    }
    out(L"ok\n");
    return 0;
}

/* list：查看已登记目录（交互模式用）—— 需要密码，否则不显示任何内容 */
static int do_list(const Config *c) {
    wchar_t *in = ask_pwd(c);              /* 没有正确密码 → 直接退出，不输出任何列表 */
    if (!in) return EXIT_PWD_ERR;
    wipe_pwd(in);

    wchar_t b[512];
    _snwprintf(b, 511, L"已登记 %d 个目录：\n", c->n);
    b[511] = 0;
    out(b);
    for (int i = 0; i < c->n; i++) {
        wchar_t *p = deobf_str(c->items[i]);
        int hidden = 0;
        wchar_t *hp = wcat(p, CLSID_SUFFIX);
        if (dir_exists(hp)) hidden = 1;
        free(hp);
        /* 状态只用符号：√ = 已处理，× = 未处理（不写任何文字，避免暴露含义） */
        _snwprintf(b, 511, L"  %d) %s  %s\n", i + 1, p, hidden ? L"√" : L"×");
        b[511] = 0;
        out(b);
        free(p);
    }
    return 0;
}

/* ---------------- 交互模式（双击 exe 进入） ---------------- */
/* 界面只列命令，不写任何功能说明 */
static void banner(void) {
    out(L"============================================================\n");
    out(L" deenfile\n");
    out(L"============================================================\n");
    out(L" 1  encode\n");
    out(L" 2  decode\n");
    out(L" 3  add <dir>\n");
    out(L" 4  list\n");
    out(L" 5  pwd\n");
    out(L" 6  level\n");
    out(L" 0  exit\n");
    out(L"------------------------------------------------------------\n");
}

/* 去掉首尾空白与引号（拖拽文件夹进窗口会带双引号） */
static wchar_t *clean_input(wchar_t *s) {
    size_t l = wcslen(s);
    while (l && (s[l - 1] == L' ' || s[l - 1] == L'\t' || s[l - 1] == L'"')) s[--l] = 0;
    while (*s == L' ' || *s == L'\t' || *s == L'"') s++;
    return s;
}

static int interactive(void) {
    g_inter = 1;
    SetConsoleTitleW(L"deenfile");

    Config c;
    int has = cfg_load(&c);
    if (!has) {
        banner();
        out(L"首次使用，请先设置密码\n");
        wchar_t *p1 = read_pwd(L"请输入新密码: ");
        wchar_t *p2 = read_pwd(L"请再输入一次: ");
        if (!p1 || !p2 || wcscmp(p1, p2) != 0 || wcslen(p1) == 0) {
            out(L"两次输入不一致或为空，已取消\n按回车退出...\n");
            read_line(0);
            return EXIT_OP_ERR;
        }
        memset(&c, 0, sizeof(c));
        c.pwd = obf_wstr(p1);
        c.level = 1;
        free(p1); free(p2);
        cfg_save(&c);
        out(L"ok\n");
        has = 1;
    }
    (void)has;

    for (;;) {
        out(L"\n");
        banner();
        out(L"命令 > ");
        wchar_t *line = read_line(0);
        if (!line) break;
        wchar_t *cmd = clean_input(line);
        if (!*cmd) { free(line); continue; }

        if (wcscmp(cmd, L"0") == 0 || _wcsicmp(cmd, L"exit") == 0 || _wcsicmp(cmd, L"quit") == 0) {
            free(line);
            break;
        } else if (wcscmp(cmd, L"1") == 0 || _wcsicmp(cmd, L"encode") == 0) {
            do_encode(&c);                     /* 唯一不需要密码的命令 */
        } else if (wcscmp(cmd, L"2") == 0 || _wcsicmp(cmd, L"decode") == 0) {
            do_decode(&c, 0);
        } else if (wcscmp(cmd, L"4") == 0 || _wcsicmp(cmd, L"list") == 0) {
            out(L"\n");
            do_list(&c);
        } else if (wcscmp(cmd, L"5") == 0 || _wcsicmp(cmd, L"pwd") == 0) {
            out(L"\n");
            do_pwd(&c);
        } else if (wcscmp(cmd, L"6") == 0 || _wcsicmp(cmd, L"level") == 0 ||
                   _wcsnicmp(cmd, L"level ", 6) == 0) {
            out(L"\n");
            if (wcscmp(cmd, L"6") == 0 || _wcsicmp(cmd, L"level") == 0) {
                /* 无参数：显示当前等级并询问新等级 */
                wchar_t b[112];
                _snwprintf(b, 111, L"当前安全等级: %d（1=不改文件内容，较快；2=改文件内容，较慢）\n", c.level);
                b[111] = 0;
                out(b);
                out(L"新等级(1/2，直接回车取消): ");
                wchar_t *lv = read_line(0);
                if (!lv) { free(line); break; }
                wchar_t *t = clean_input(lv);
                if (*t == L'1') do_level(&c, 1);
                else if (*t == L'2') do_level(&c, 2);
                else if (*t) out(L"已取消\n");
                free(lv);
            } else {
                wchar_t *t = clean_input(cmd + 6);
                if (*t == L'1') do_level(&c, 1);
                else if (*t == L'2') do_level(&c, 2);
                else out(L"用法: level 1 或 level 2\n");
            }
        } else if (wcscmp(cmd, L"3") == 0 || _wcsicmp(cmd, L"add") == 0 ||
                   _wcsnicmp(cmd, L"add ", 4) == 0) {
            wchar_t *ds = cmd;
            if (wcscmp(cmd, L"3") == 0 || _wcsicmp(cmd, L"add") == 0) {
                out(L"目录: ");
                wchar_t *d = read_line(0);
                if (!d) { free(line); break; }
                ds = clean_input(d);
                if (*ds) do_add(&c, ds);
                free(d);
            } else {
                ds = clean_input(cmd + 4);
                if (*ds) do_add(&c, ds);
            }
        } else {
            out(L"1 / 2 / 3 / 4 / 5 / 6 / 0, encode / decode / add / list / pwd / level / exit\n");
        }
        free(line);
    }

    out(L"\n已退出\n");
    return 0;
}

/* ---------------- 入口 ---------------- */
static void usage(void) {
    printf("deenfile add <dir>\n");
    printf("deenfile encode\n");
    printf("deenfile decode [force]\n");
    printf("deenfile pwd\n");
    printf("deenfile level [1|2]\n");
}

/* 测试钩子：设置环境变量 DEENFILE_TUI=1 可强制进入交互模式（方便管道自动化回归）
 * 兼容旧变量名 ONOFF_TUI，便于沿用旧脚本 */
static int force_tui(void) {
    wchar_t b[8];
    return GetEnvironmentVariableW(L"DEENFILE_TUI", b, 8) > 0 ||
           GetEnvironmentVariableW(L"ONOFF_TUI", b, 8) > 0;
}

int wmain(int argc, wchar_t *argv[]) {
    Config c;
    int has = cfg_load(&c);
    if (!has) cfg_migrate_ini(&c);          /* 旧版 config.ini 一次性迁移到注册表 */
    has = (c.pwd != NULL);

    if (argc < 2) {
        /* 双击 exe：stdin 是控制台 → 弹出窗口进入交互菜单 */
        HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode) || force_tui()) return interactive();

        /* 无参 + 管道：首次设置密码（读两行）*/
        if (!has) {
            wchar_t *p1 = read_pwd(L"new password: ");
            wchar_t *p2 = read_pwd(L"confirm: ");
            if (!p1 || !p2 || wcscmp(p1, p2) != 0 || wcslen(p1) == 0) return EXIT_OP_ERR;
            Config nc; memset(&nc, 0, sizeof(nc));
            nc.pwd = obf_wstr(p1);
            nc.level = 1;
            cfg_save(&nc);
            printf("ok\n");
            return 0;
        }
        usage();
        return 0;
    }

    const wchar_t *cmd = argv[1];

    if (_wcsicmp(cmd, L"encode") == 0) {
        if (!has) { printf("ok\n"); return 0; }
        return do_encode(&c);
    }

    if (_wcsicmp(cmd, L"decode") == 0) {
        if (!has) { printf("no pwd\n"); return EXIT_PWD_ERR; }
        int force = (argc >= 3 && _wcsicmp(argv[2], L"force") == 0);
        return do_decode(&c, force);
    }

    if (_wcsicmp(cmd, L"add") == 0) {
        if (!has || argc < 3) { printf("no pwd\n"); return EXIT_PWD_ERR; }
        return do_add(&c, argv[2]);
    }

    if (_wcsicmp(cmd, L"pwd") == 0) {
        if (!has) { printf("no pwd\n"); return EXIT_PWD_ERR; }
        return do_pwd(&c);
    }

    if (_wcsicmp(cmd, L"level") == 0) {
        if (argc < 3) {                       /* 无参数：显示当前等级 */
            wchar_t b[32];
            _snwprintf(b, 31, L"level %d\n", c.level);
            b[31] = 0;
            out(b);
            return 0;
        }
        if (!has) { printf("no pwd\n"); return EXIT_PWD_ERR; }
        if (_wcsicmp(argv[2], L"1") != 0 && _wcsicmp(argv[2], L"2") != 0) {
            usage();
            return 0;
        }
        return do_level(&c, argv[2][0] - L'0');
    }

    usage();
    return 0;
}
