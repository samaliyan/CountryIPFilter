#!/usr/bin/env python3
"""Build a Windows resource .syso (icon, manifest, version info) for the Go linker.

usage: mksyso.py --arch 386|amd64 --ico app.ico --manifest app.manifest \
                 --version 1.0.0 --desc "..." --product "..." --name X.exe --out rsrc.syso
"""
import argparse, struct

RT_ICON, RT_GROUP_ICON, RT_VERSION, RT_MANIFEST = 3, 14, 16, 24
LANG = 0x0409


def utf16z(s):
    return s.encode('utf-16-le') + b'\0\0'


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def vs_block(key, value=b'', value_len_words=None, is_text=False, children=b''):
    # wLength, wValueLength, wType, szKey, pad, Value, pad, Children
    head_key = utf16z(key)
    body = struct.pack('<HHH', 0, 0, 1 if is_text else 0) + head_key
    body = pad4(body)
    if value:
        body += value
        body = pad4(body)
    body += children
    vlen = value_len_words if value_len_words is not None else len(value)
    return struct.pack('<HHH', len(body), vlen, 1 if is_text else 0) + body[6:]


def version_resource(ver, desc, product, name, company):
    parts = [int(x) for x in (ver.split('.') + ['0', '0', '0'])[:4]]
    ms = (parts[0] << 16) | parts[1]
    ls = (parts[2] << 16) | parts[3]
    ffi = struct.pack('<13I', 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x40004, 1, 0, 0, 0)
    strings = [
        ('CompanyName', company), ('FileDescription', desc), ('FileVersion', ver),
        ('InternalName', name.rsplit('.', 1)[0]), ('LegalCopyright', company),
        ('OriginalFilename', name), ('ProductName', product), ('ProductVersion', ver),
    ]
    st_children = b''
    for k, v in strings:
        val = utf16z(v)
        st_children = pad4(st_children) + vs_block(k, val, value_len_words=len(val) // 2, is_text=True)
    string_table = vs_block('040904b0', children=pad4(st_children), is_text=True)
    sfi = vs_block('StringFileInfo', children=string_table, is_text=True)
    var = vs_block('Translation', struct.pack('<HH', 0x0409, 1200), is_text=False)
    vfi = vs_block('VarFileInfo', children=var, is_text=True)
    return vs_block('VS_VERSION_INFO', ffi, children=pad4(sfi) + vfi, is_text=False)


def parse_ico(data):
    _, typ, count = struct.unpack('<HHH', data[:6])
    assert typ == 1
    imgs = []
    for i in range(count):
        w, h, cc, _, planes, bpp, size, off = struct.unpack('<BBBBHHII', data[6 + 16 * i:22 + 16 * i])
        imgs.append((w, h, cc, planes, bpp, data[off:off + size]))
    return imgs


def build(arch, ico, manifest, ver, desc, product, name, company):
    res = {}  # type -> {id: bytes}
    imgs = parse_ico(open(ico, 'rb').read())
    res[RT_ICON] = {}
    grp = struct.pack('<HHH', 0, 1, len(imgs))
    for i, (w, h, cc, planes, bpp, blob) in enumerate(imgs, start=1):
        res[RT_ICON][i] = blob
        grp += struct.pack('<BBBBHHIH', w, h, cc, 0, planes or 1, bpp or 32, len(blob), i)
    res[RT_GROUP_ICON] = {1: grp}
    res[RT_VERSION] = {1: version_resource(ver, desc, product, name, company)}
    res[RT_MANIFEST] = {1: open(manifest, 'rb').read()}

    # --- resource directory: type -> id -> lang -> data entry ---
    types = sorted(res)
    dir_size = lambda n: 16 + 8 * n
    # layout: root dir, type dirs, name dirs (lang), data entries, then data
    root_len = dir_size(len(types))
    type_dirs_len = sum(dir_size(len(res[t])) for t in types)
    lang_dirs_len = sum(dir_size(1) for t in types for _ in res[t])
    n_entries = sum(len(res[t]) for t in types)
    data_entries_off = root_len + type_dirs_len + lang_dirs_len
    data_off = data_entries_off + 16 * n_entries

    out = bytearray()
    relocs = []

    def dir_hdr(n_ids):
        return struct.pack('<IIHHHH', 0, 0, 0, 0, 0, n_ids)

    # root
    out += dir_hdr(len(types))
    off = root_len
    type_offsets = []
    for t in types:
        type_offsets.append(off)
        off += dir_size(len(res[t]))
    for t, to in zip(types, type_offsets):
        out += struct.pack('<II', t, 0x80000000 | to)
    # type dirs
    lang_off = root_len + type_dirs_len
    lang_offsets = []
    for t in types:
        out += dir_hdr(len(res[t]))
        for rid in sorted(res[t]):
            out += struct.pack('<II', rid, 0x80000000 | lang_off)
            lang_offsets.append((t, rid, lang_off))
            lang_off += dir_size(1)
    # lang dirs
    de_off = data_entries_off
    entry_list = []
    for t, rid, _ in lang_offsets:
        out += dir_hdr(1)
        out += struct.pack('<II', LANG, de_off)
        entry_list.append((t, rid, de_off))
        de_off += 16
    # data entries
    blobs = bytearray()
    cur = data_off
    for t, rid, eo in entry_list:
        blob = res[t][rid]
        assert len(out) == eo
        relocs.append(len(out))
        out += struct.pack('<IIII', cur, len(blob), 0, 0)
        padded = bytes(blob) + b'\0' * ((8 - len(blob) % 8) % 8)
        blobs += padded
        cur += len(padded)
    assert len(out) == data_off
    out += blobs

    machine = 0x14c if arch == '386' else 0x8664
    rel_type = 7 if arch == '386' else 3  # IMAGE_REL_I386_DIR32NB / IMAGE_REL_AMD64_ADDR32NB
    raw_off = 20 + 40
    rel_off = raw_off + len(out)
    sym_off = rel_off + 10 * len(relocs)
    hdr = struct.pack('<HHIIIHH', machine, 1, 0, sym_off, 1, 0, 0)
    sec = struct.pack('<8sIIIIIIHHI', b'.rsrc\0\0\0', 0, 0, len(out), raw_off, rel_off, 0, len(relocs), 0, 0x40000040)
    rel = b''.join(struct.pack('<IIH', r, 0, rel_type) for r in relocs)
    sym = struct.pack('<8sIhHBB', b'.rsrc\0\0\0', 0, 1, 0, 3, 0)
    strtab = struct.pack('<I', 4)
    return hdr + sec + bytes(out) + rel + sym + strtab


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--arch', required=True)
    ap.add_argument('--ico', required=True)
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--version', required=True)
    ap.add_argument('--desc', required=True)
    ap.add_argument('--product', required=True)
    ap.add_argument('--name', required=True)
    ap.add_argument('--company', default='')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    open(a.out, 'wb').write(build(a.arch, a.ico, a.manifest, a.version, a.desc, a.product, a.name, a.company))
