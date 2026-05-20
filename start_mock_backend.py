"""Start all mock backend servers for HSQSL.

Launches:
  1. Mock HTTP server (ports 8080, 80, 443) - SDK URL interception
  2. Mock Gate server (TCP ports 9090,9180,9200,9230) - Gate protocol handshake
  3. Mock Game server (TCP port 9091) - Entity RPC handling

Usage:
  python start_mock_backend.py                    # Start all
  python start_mock_backend.py --gate-only        # Gate only
  python start_mock_backend.py --http-only        # HTTP only
"""

import sys
import os
import time
import threading
import signal
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'mock_server'))

from mock_gate import MockGateServer
from mock_game import MockGameServer
from mock_http import create_sdk_mock


def check_port(port, proto='TCP'):
    """Check if a port is in use. Returns (pid, exe_name) or None."""
    try:
        result = subprocess.check_output(
            f'netstat -ano -p {proto} 2>&1',
            shell=True, text=True, timeout=5
        )
        for line in result.split('\n'):
            parts = line.split()
            if len(parts) >= 5 and parts[1].endswith(f':{port}'):
                state = parts[3] if len(parts) > 3 else ''
                if proto == 'TCP' and state != 'LISTENING':
                    continue
                pid = int(parts[4])
                try:
                    tasklist = subprocess.check_output(
                        f'tasklist /FI "PID eq {pid}" /FO CSV 2>&1',
                        shell=True, text=True, timeout=5
                    )
                    lines = tasklist.strip().split('\n')
                    exe = lines[1].split(',')[0].strip('"') if len(lines) >= 2 else 'unknown'
                except:
                    exe = 'unknown'
                return pid, exe
    except:
        pass
    return None


def check_all_ports(ports):
    """Check multiple ports (both TCP and UDP). Returns {port: (pid, exe, proto)}."""
    in_use = {}
    for port in ports:
        for proto in ('TCP', 'UDP'):
            result = check_port(port, proto)
            if result:
                pid, exe = result
                in_use[port] = (pid, exe, proto)
                break
    return in_use


def kill_process(pid):
    """Kill a process by PID."""
    try:
        subprocess.check_call(f'taskkill /PID {pid} /F 2>&1',
                              shell=True, timeout=10)
        return True
    except:
        return False


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Start HSQSL mock backend')
    ap.add_argument('--gate-only', action='store_true')
    ap.add_argument('--game-only', action='store_true')
    ap.add_argument('--http-only', action='store_true')
    ap.add_argument('--http-port', type=int, default=8080)
    ap.add_argument('--gate-port', type=int, default=9090)
    ap.add_argument('--game-port', type=int, default=9091)

    args = ap.parse_args()

    servers = []
    threads = []

    if args.http_only:
        run_http = True
        run_gate = False
        run_game = False
    elif args.gate_only:
        run_http = False
        run_gate = True
        run_game = False
    elif args.game_only:
        run_http = False
        run_gate = False
        run_game = True
    else:
        run_http = True
        run_gate = True
        run_game = True

    # --- Port conflict check ---
    ports_to_check = []
    if run_http:
        ports_to_check.extend([80, 443, args.http_port])
    if run_gate:
        ports_to_check.append(args.gate_port)
    if run_game:
        ports_to_check.append(args.game_port)

    conflicts = check_all_ports(ports_to_check)
    if conflicts:
        print('=' * 60)
        print('WARNING: 以下端口已被占用，自动终止:')
        print('=' * 60)
        for port, (pid, exe, proto) in sorted(conflicts.items()):
            print(f'  端口 {port}/{proto} — PID {pid} ({exe})')
            print(f'  正在终止 PID {pid}...')
            if kill_process(pid):
                print(f'    已终止')
            else:
                print(f'    终止失败，请手动处理')
        time.sleep(1)
        remaining = check_all_ports(ports_to_check)
        if remaining:
            print('仍有端口被占用，退出。请手动关闭占用程序后重试。')
            for port, (pid, exe, proto) in sorted(remaining.items()):
                print(f'  端口 {port}/{proto} — PID {pid} ({exe})')
            sys.exit(1)

    print('=' * 60)
    print('HSQSL Mock Backend')
    print('=' * 60)

    if run_http:
        http_server = create_sdk_mock(args.http_port)
        t = threading.Thread(target=http_server.run, daemon=True,
                             name='MockHTTP')
        t.start()
        servers.append(('HTTP (SDK mock)', args.http_port))
        threads.append(t)

    if run_gate:
        # Port formula: base + n*10 for n=1..16 (9100-9250), plus base port
        gate_ports = [args.gate_port] + [args.gate_port + n * 10 for n in range(1, 17)]
        gate_server = MockGateServer(ports=gate_ports, game_port=args.game_port)
        t = threading.Thread(target=gate_server.run, daemon=True,
                             name='MockGate')
        t.start()
        servers.append(('Gate (TCP)', f'{args.gate_port}+n*10 (n=0..16)'))
        threads.append(t)

    if run_game:
        game_server = MockGameServer(
            host='127.0.0.1',
            port=args.game_port
        )
        t = threading.Thread(target=game_server.run, daemon=True,
                             name='MockGame')
        t.start()
        servers.append(('Game (TCP)', args.game_port))
        threads.append(t)

    time.sleep(0.5)

    print()
    print('Running servers:')
    for name, port in servers:
        print(f'  {name} : {port}')
    print()
    print('To use with the game client:')
    print('  1. Add to hosts file:')
    print('     127.0.0.1 mgbsdk.matrix.netease.com')
    print('     127.0.0.1 unisdk.update.easebar.com')
    print('     127.0.0.1 applog.matrix.easebar.com')
    print('     127.0.0.1 update.netease.com')
    print('     127.0.0.1 update.easebar.com')
    print(f'  2. Run patch_client.py to modify dev_server_list')
    print(f'  3. Replace script.npk with patched version')
    print()
    print('Press Ctrl+C to stop all servers.')
    print('=' * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\nShutting down all servers...')
        if run_gate:
            gate_server.stop()
        if run_game:
            game_server.stop()
        if run_http:
            http_server.stop()
        print('Done.')


if __name__ == '__main__':
    main()
