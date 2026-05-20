"""Manage Windows hosts file entries for HSQSL mock backend.

Usage:
  python manage_hosts.py add       # Add SDK redirect entries
  python manage_hosts.py remove    # Remove SDK redirect entries
  python manage_hosts.py show      # Show current hosts entries

Requires administrator privileges for add/remove.
"""

import sys
import os
import tempfile
import shutil

HOSTS_PATH = r'C:\Windows\System32\drivers\etc\hosts'

ENTRIES = {
    'mgbsdk.matrix.netease.com': 'NetEase SDK gateway',
    'unisdk.update.easebar.com': 'NetEase SDK update',
    'applog.matrix.easebar.com': 'NetEase SDK logging',
    'h62.update.netease.com': 'HSQSL patch hotfix CDN (mainland)',
    'h62tw.update.easebar.com': 'HSQSL patch hotfix CDN (tw)',
    'h62na.update.easebar.com': 'HSQSL patch hotfix CDN (other)',
    'h62.gph.netease.com': 'HSQSL game server GPH CDN',
    'update.netease.com': 'NetEase CDN update',
    'update.easebar.com': 'NetEase CDN update (alt)',
}

REDIRECT_IP = '127.0.0.1'
MARKER_BEGIN = '# >>> HSQSL mock backend BEGIN'
MARKER_END = '# <<< HSQSL mock backend END'


def is_admin():
    """Check if running with admin privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return os.getuid() == 0  # Unix fallback


def read_hosts():
    with open(HOSTS_PATH, 'r', encoding='utf-8', errors='replace') as f:
        return f.read().splitlines()


def write_hosts(lines):
    """Write hosts file. Tries temp+replace first, falls back to direct write."""
    content = '\r\n'.join(lines) + '\r\n'

    # Method 1: temp file + replace (atomic on POSIX, may trigger AV on Windows)
    tmp = HOSTS_PATH + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8', newline='') as f:
            f.write(content)
        os.replace(tmp, HOSTS_PATH)
        return
    except PermissionError:
        pass

    # Method 2: direct write
    try:
        with open(HOSTS_PATH, 'w', encoding='utf-8', newline='') as f:
            f.write(content)
        return
    except PermissionError:
        pass

    # Method 3: try writing to a temp file in the same directory and renaming
    import tempfile
    tmp2 = os.path.join(os.path.dirname(HOSTS_PATH), 'hosts_new.tmp')
    try:
        with open(tmp2, 'w', encoding='utf-8', newline='') as f:
            f.write(content)
        os.replace(tmp2, HOSTS_PATH)
        return
    except PermissionError:
        if os.path.exists(tmp2):
            os.remove(tmp2)
        pass

    raise PermissionError(
        f'Cannot write to {HOSTS_PATH}.\n'
        'Make sure to run as Administrator and temporarily disable '
        'antivirus real-time protection if needed.'
    )


def add_entries():
    lines = read_hosts()

    # Check if already added
    if MARKER_BEGIN in lines:
        print('Entries already present. Remove first with: python manage_hosts.py remove')
        return

    # Remove trailing empty lines
    while lines and lines[-1] == '':
        lines.pop()

    # Ensure a blank line before our block
    if lines and lines[-1] != '':
        lines.append('')

    lines.append(MARKER_BEGIN)
    for domain, desc in ENTRIES.items():
        lines.append(f'{REDIRECT_IP}  {domain}  #{desc}')
    lines.append(MARKER_END)
    lines.append('')

    try:
        write_hosts(lines)
    except PermissionError:
        print('Automatic write failed. Copy the following lines into your hosts file:')
        print(f'  {HOSTS_PATH}')
        print()
        print('  ' + MARKER_BEGIN)
        for domain, desc in ENTRIES.items():
            print(f'  {REDIRECT_IP}  {domain}  #{desc}')
        print('  ' + MARKER_END)
        print()
        print('Open Notepad as Administrator, then paste the above lines into the file.')
        return


def remove_entries():
    lines = read_hosts()

    if MARKER_BEGIN not in lines:
        print('Entries not found. Nothing to remove.')
        return

    start = lines.index(MARKER_BEGIN)
    end = lines.index(MARKER_END, start) if MARKER_END in lines[start:] else start

    # Remove block including surrounding blanks
    # Remove blank line before marker if present
    if start > 0 and lines[start - 1] == '':
        start -= 1
    # Remove blank line after marker if present
    if end + 1 < len(lines) and lines[end + 1] == '':
        end += 1

    new_lines = lines[:start] + lines[end + 1:]
    write_hosts(new_lines)
    print('Hosts entries removed.')


def show_entries():
    lines = read_hosts()
    in_block = False
    found = False
    for line in lines:
        if line == MARKER_BEGIN:
            in_block = True
            found = True
            continue
        if line == MARKER_END:
            in_block = False
            continue
        if in_block:
            print(line)
    if not found:
        print('No HSQSL mock entries found.')
    else:
        print(f'\nTo remove: python manage_hosts.py remove')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == 'show':
        show_entries()
        return

    if cmd in ('add', 'remove'):
        if not is_admin():
            print('ERROR: Administrator privileges required.')
            print('Re-run from an admin terminal, or right-click → "Run as administrator".')
            sys.exit(1)

        if cmd == 'add':
            add_entries()
        else:
            remove_entries()
    else:
        print(f'Unknown command: {cmd}')
        print('Use: add | remove | show')
        sys.exit(1)


if __name__ == '__main__':
    main()
