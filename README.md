# elf2self
Wrap a decrypted PS4 ELF (as Itemzflow dumps it) in a plaintext SELF container.

Layout: 32-byte SELF header, one 32-byte entry per program header with file data,
the ELF header + program headers, then each segment's bytes, unencrypted and
uncompressed. Only reads the input; writes only the given output path.