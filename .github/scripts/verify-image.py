#!/usr/bin/env python3
# =============================================================================
# verify-image.py —— 刷机前的镜像自检
#
# 在把 boot-vermeer.img 刷进手机之前跑一遍，确认它至少"结构上是对的"：
#   · Android boot header 合法
#   · kernel 段里确实由 gzip(UEFI FD) + DTB 拼成
#   · gzip 能解压，且解压结果里能找到 EDK2 的 _FVH 签名
#   · 尾部的 DTB 是 vermeer 的、且 magic 正确
#   · 总体积没有超过 boot 分区
#
# 用法：
#   python3 verify-image.py boot-vermeer.img
#   python3 verify-image.py boot-vermeer.img --partition-size 192MiB
#
# 退出码：0 = 通过，1 = 有致命问题（别刷），2 = 有警告（可刷但注意）
# =============================================================================
import struct
import sys
import zlib
import os
import re

OK, WARN, ERR = "OK", "WARN", "FAIL"
results = []


def add(level, msg):
    results.append((level, msg))


def parse_boot_header(d, fname):
    if d[:8] != b"ANDROID!":
        add(ERR, "不是 Android boot image（magic 不是 ANDROID!）")
        return None

    hv = struct.unpack_from("<I", d, 40)[0]

    if hv in (0, 1, 2):
        page = struct.unpack_from("<I", d, 36)[0]
        ks = struct.unpack_from("<I", d, 8)[0]
        rs = struct.unpack_from("<I", d, 16)[0]
        kaddr = struct.unpack_from("<I", d, 12)[0]
        raddr = struct.unpack_from("<I", d, 20)[0]
        cmdline = d[64:64 + 512].split(b"\x00")[0].decode("utf-8", "replace")
        hdr_size = page
        sig = 0
    elif hv in (3, 4):
        hdr_size = struct.unpack_from("<I", d, 20)[0]
        ks = struct.unpack_from("<I", d, 8)[0]
        rs = struct.unpack_from("<I", d, 12)[0]
        kaddr = raddr = 0
        cmdline = d[44:44 + 1536].split(b"\x00")[0].decode("utf-8", "replace")
        sig = 4096 if hv >= 4 else 0
        page = 4096
    else:
        add(ERR, f"不支持的 header version {hv}")
        return None

    add(OK, f"header version = {hv}，page_size = {page}，header_size = {hdr_size}")
    add(OK, f"kernel = {ks} B ({ks/1048576:.1f} MiB)，ramdisk = {rs} B ({rs/1024:.0f} KiB)")
    if cmdline.strip():
        add(OK, f"cmdline = {cmdline[:100]}")
    if rs == 0:
        add(WARN, "ramdisk 为空 —— 没有 SimpleInit rootfs，UEFI 只能进内置 Shell")

    koff = (hdr_size + sig + page - 1) // page * page
    kern = d[koff:koff + ks]
    if len(kern) < ks:
        add(ERR, f"文件被截断：kernel 段期望 {ks} B，实际只有 {len(kern)} B")
    return dict(hv=hv, page=page, ks=ks, rs=rs, koff=koff, kern=kern, sig=sig,
                kaddr=kaddr, raddr=raddr)


def split_kernel_gzip_dtb(kern):
    gz = kern.find(b"\x1f\x8b\x08")
    if gz < 0:
        add(ERR, "kernel 段里找不到 gzip 魔数 —— UEFI 镜像没有压缩？")
        return None, None
    if gz > 0:
        add(WARN, f"gzip 之前有 {gz} B 的填充数据")

    dtb_pos = -1
    # 从尾部往前找 DTB magic，避开内核数据里的偶然巧合
    for m in re.finditer(b"\xd0\x0d\xfe\xed", kern):
        dtb_pos = m.start()
    if dtb_pos < 0:
        add(ERR, "kernel 段尾部没有 DTB —— 拼接步骤可能失败了")
        dtb_pos = len(kern)
    else:
        add(OK, f"DTB 位于 kernel 段偏移 {dtb_pos}（共 {len(kern)-dtb_pos} B）")

    return kern[gz:dtb_pos], kern[dtb_pos:]


def check_uefi_fv(gzdata):
    try:
        obj = zlib.decompressobj(31)
        raw = obj.decompress(gzdata) + obj.flush()
    except zlib.error as e:
        add(ERR, f"gzip 解压失败：{e}")
        return None

    add(OK, f"gzip 解压成功 → {len(raw)} B ({len(raw)/1048576:.2f} MiB)")

    idx = raw.find(b"_FVH")
    if idx < 0:
        add(ERR, "解压结果里找不到 EDK2 的 _FVH 签名 —— 不是有效的 UEFI 固件")
        return raw

    fv_start = idx - 40
    if fv_start < 0:
        add(WARN, f"_FVH 出现在偏移 {idx}，前面不足 40 B，FV 起点存疑")
        fv_start = 0
    add(OK, f"找到 EDK2 固件卷，_FVH @ {idx}，BootShim 占前 {fv_start} B")

    if fv_start > 0:
        shim = raw[:fv_start]
        if len(shim) < 1024:
            add(WARN, f"BootShim 只有 {len(shim)} B，偏小，可能不正常")
        else:
            add(OK, f"BootShim 长度 {len(shim)} B")

    if len(raw) - fv_start > 32 * 1024 * 1024:
        add(WARN, "固件卷超过 32 MiB（FD_SIZE = 0x02000000），可能越界")
    else:
        add(OK, f"固件卷大小 {len(raw)-fv_start} B，在 32 MiB 限制内")
    return raw


def check_dtb(dtb):
    if len(dtb) < 40:
        add(ERR, "DTB 段太短，无法解析")
        return
    magic = struct.unpack_from(">I", dtb, 0)[0]
    if magic != 0xD00DFEED:
        add(ERR, f"DTB magic = 0x{magic:08x}，不是 0xd00dfeed")
        return

    totalsize = struct.unpack_from(">I", dtb, 4)[0]
    add(OK, f"DTB magic 正确，totalsize = {totalsize} B")

    if totalsize > len(dtb):
        add(WARN, f"DTB 声明 {totalsize} B，实际只有 {len(dtb)} B（可能被截断）")

    # 粗暴地找 model 字符串，够用
    m = re.search(rb"vermeer", dtb)
    if m:
        add(OK, "DTB 内含 'vermeer' 标识 —— 机型号匹配")
    else:
        add(ERR, "DTB 里找不到 'vermeer'，可能拿错了设备树")

    if re.search(rb"kalama", dtb):
        add(OK, "DTB 内含 'kalama' —— SM8550 平台标识正确")
    else:
        add(WARN, "DTB 里找不到 'kalama'，平台可能不对")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    path = sys.argv[1]
    part_size = None
    if "--partition-size" in sys.argv:
        v = sys.argv[sys.argv.index("--partition-size") + 1]
        m = re.match(r"(\d+)\s*([KM]i?B?)?", v, re.I)
        if m:
            n = int(m.group(1))
            unit = (m.group(2) or "").upper()
            part_size = n * (1024 ** 2 if unit.startswith("M") else 1024) if unit else n

    if not os.path.exists(path):
        print(f"文件不存在: {path}")
        return 1

    size = os.path.getsize(path)
    d = open(path, "rb").read()

    print("=" * 66)
    print(f" 镜像自检: {path}")
    print(f" 文件大小: {size} B ({size/1048576:.2f} MiB)")
    print("=" * 66)

    hdr = parse_boot_header(d, path)
    if hdr is None:
        report()
        return 1

    gzdata, dtb = split_kernel_gzip_dtb(hdr["kern"])
    if gzdata is None:
        report()
        return 1

    raw = check_uefi_fv(gzdata)
    check_dtb(dtb)

    # 体积检查
    if part_size:
        if size > part_size:
            add(ERR, f"镜像 {size} B 超过分区 {part_size} B，刷不进去")
        else:
            add(OK, f"体积 {size} B < 分区 {part_size} B，余量 {(part_size-size)/1048576:.1f} MiB")
    else:
        add(WARN, "未指定分区大小，跳过体积检查（K70 的 boot 分区是 192 MiB）")

    return report()


def report():
    print()
    icons = {OK: " ✓ ", WARN: " ! ", ERR: " ✗ "}
    for lvl, msg in results:
        print(f"[{lvl:4}]{icons[lvl]} {msg}")
    print()
    errs = sum(1 for l, _ in results if l == ERR)
    warns = sum(1 for l, _ in results if l == WARN)
    if errs:
        print(f"结论: 有 {errs} 项致命问题，{warns} 项警告 —— 不要刷这个镜像。")
        return 1
    if warns:
        print(f"结论: 结构可用，有 {warns} 项警告 —— 可以刷，但留意对应风险。")
        return 2
    print("结论: 全部检查通过，结构上是一个正常的 vermeer UEFI 镜像。")
    return 0


if __name__ == "__main__":
    sys.exit(report() if False else main())
