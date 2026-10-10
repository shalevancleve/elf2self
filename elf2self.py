#!/usr/bin/env python3
"""Wrap a decrypted PS4 ELF (as Itemzflow dumps it) in a plaintext SELF container.

Layout: 32-byte SELF header, one 32-byte entry per program header with file data,
the ELF header + program headers, then each segment's bytes, unencrypted and
uncompressed. Only reads the input; writes only the given output path.
"""
import struct
import sys

SELF_MAGIC = b'\x4f\x15\x3d\x1d'


def wrap(elf):
    if elf[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('input is not an x86-64 little-endian ELF')
    e = struct.unpack_from('<16sHHIQQQIHHHHHH', elf, 0)
    phoff, phnum = e[5], e[10]
    ph = [struct.unpack_from('<IIQQQQQQ', elf, phoff + i * 56) for i in range(phnum)]
    header_end = phoff + phnum * 56
    entries = [(i, p) for i, p in enumerate(ph) if p[5]]
    count = len(entries)
    base = 32 + count * 32
    pos = base + header_end
    table, blobs = [], []
    for i, p in entries:
        pos = (pos + 15) & ~15
        off, size = p[2], p[5]
        if off + size > len(elf):
            raise ValueError(f'segment {i} runs past end of file')
        flags = 0x800 | (i << 20)          # blocked, plaintext (no 0x2/0x8 bits)
        table.append(struct.pack('<QQQQ', flags, pos, size, size))
        blobs.append((pos, elf[off:off + size]))
        pos += size
    out = bytearray(pos)
    struct.pack_into('<4sBBBBIHHQHHI', out, 0, SELF_MAGIC, 0, 1, 1, 0x12, 0x101,
                     base + header_end, 0, pos, count, 0x22, 0)
    out[32:base] = b''.join(table)
    out[base:base + header_end] = elf[:header_end]
    for at, data in blobs:
        out[at:at + len(data)] = data
    return bytes(out)


if __name__ == '__main__':
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, 'rb').read()
    open(dst, 'wb').write(wrap(data))