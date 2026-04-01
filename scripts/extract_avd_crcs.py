#!/usr/bin/env python3
"""Extract symbol CRCs from an AVD kernel for kmod_loader.

For AVDs where kmod_loader's built-in CRC resolution fails (no vendor .ko,
no /proc/kcore, no __crc_* in kallsyms).

Reads ksymtab/kcrctab addresses from the device via kallsyms, then extracts
CRC values from the host-side kernel-ranchu image.

Usage:
  extract_avd_crcs.py -s emulator-5554
  extract_avd_crcs.py -s emulator-5554 module_layout printk memcpy memset

Output: --crc arguments for kmod_loader
"""
import gzip, struct, sys, os, subprocess, argparse


def decompress_kernel(path):
    with open(path, 'rb') as f:
        magic = f.read(2)
    if magic == b'\x1f\x8b':
        return gzip.open(path, 'rb').read()
    with open(path, 'rb') as f:
        return f.read()


def adb(serial, cmd):
    r = subprocess.run(['adb', '-s', serial, 'shell', cmd],
                       capture_output=True, text=True, timeout=10)
    return r.stdout.strip()


def adb_ksym(serial, name):
    out = adb(serial, f'grep " {name}$" /proc/kallsyms')
    if out:
        return int(out.split()[0], 16)
    return 0


def find_kernel_for_avd(serial):
    """Find host-side kernel-ranchu matching the running AVD."""
    sdk = os.path.expanduser('~/Library/Android/sdk')
    if not os.path.isdir(sdk):
        sdk = os.path.expandvars('$ANDROID_HOME')

    device_release = adb(serial, 'uname -r')

    for api in range(36, 27, -1):
        for variant in ['google_apis', 'google_apis_playstore', 'default']:
            path = f'{sdk}/system-images/android-{api}/{variant}/arm64-v8a/kernel-ranchu'
            if not os.path.exists(path):
                continue
            # Verify kernel version matches by checking the decompressed image
            data = decompress_kernel(path)
            if device_release.encode() in data:
                return path, data
    return None, None


def extract_crcs(data, text_base, sym_start, sym_stop, crc_start, crc_stop, targets):
    """Extract CRCs via ksymtab (12-byte prel32 entries) + parallel kcrctab."""
    sym_off = sym_start - text_base
    sym_size = sym_stop - sym_start
    crc_off = crc_start - text_base
    n = sym_size // 12
    fsz = len(data)
    target_set = set(targets)
    results = {}

    for i in range(n):
        off = sym_off + i * 12
        if off + 12 > fsz:
            break
        entry_va = sym_start + i * 12
        _, name_prel, _ = struct.unpack_from('<iii', data, off)

        name_foff = (entry_va + 4 + name_prel) - text_base
        if not (0 <= name_foff < fsz - 1):
            continue
        end = data.find(b'\x00', name_foff, name_foff + 64)
        if end <= name_foff:
            continue
        name = data[name_foff:end].decode('ascii', errors='replace')

        if name in target_set:
            c_off = crc_off + i * 4
            if c_off + 4 <= fsz:
                results[name] = struct.unpack_from('<I', data, c_off)[0]

    return results


def main():
    p = argparse.ArgumentParser(description='Extract AVD kernel CRCs')
    p.add_argument('-s', '--serial', required=True, help='ADB serial')
    p.add_argument('symbols', nargs='*',
                   default=['module_layout', 'printk', '_printk', 'memcpy', 'memset'])
    args = p.parse_args()

    s = args.serial
    adb(s, 'echo 0 > /proc/sys/kernel/kptr_restrict')

    text_base = adb_ksym(s, '_text')
    if not text_base:
        sys.exit("ERROR: cannot read _text from kallsyms")

    kernel_path, data = find_kernel_for_avd(s)
    if not data:
        sys.exit("ERROR: cannot find matching kernel-ranchu on host")
    print(f"# kernel: {kernel_path}", file=sys.stderr)

    crcs = {}
    # Non-GPL ksymtab
    for prefix in ['', '_gpl']:
        start = adb_ksym(s, f'__start___ksymtab{prefix}')
        stop = adb_ksym(s, f'__stop___ksymtab{prefix}')
        crc_start = adb_ksym(s, f'__start___kcrctab{prefix}')
        crc_stop = adb_ksym(s, f'__stop___kcrctab{prefix}')
        if start and crc_start:
            missing = [sym for sym in args.symbols if sym not in crcs]
            if missing:
                crcs.update(extract_crcs(data, text_base,
                                         start, stop, crc_start, crc_stop, missing))

    parts = []
    for sym in args.symbols:
        if sym in crcs:
            parts.append(f"--crc {sym}=0x{crcs[sym]:08x}")
        else:
            print(f"# WARNING: {sym} not found", file=sys.stderr)

    if parts:
        print(" ".join(parts))
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
