"""Simple packet sniffer to confirm game CDN requests.

Monitors ports 8080 and 443 for incoming connections and logs
the source process (via netstat lookup).
"""

import socket
import threading
import subprocess
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from logger import setup_logger

_log = setup_logger('Sniffer')


def get_process_by_port(port, proto='TCP'):
    """Find which process is listening on a port."""
    try:
        result = subprocess.check_output(
            f'netstat -ano -p {proto} | findstr :{port}',
            shell=True, text=True, timeout=5
        )
        return result.strip()
    except:
        return None


def sniff_port(port, label=''):
    """Listen on a port and log every connection attempt with raw data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    sock.settimeout(2.0)
    _log(f'{label} sniffer on port {port}')

    while True:
        try:
            conn, addr = sock.accept()
            _log(f'*** CONNECTION on port {port} from {addr[0]}:{addr[1]} ***')
            try:
                conn.settimeout(3.0)
                data = conn.recv(4096)
                if data:
                    preview = data[:200]
                    text = ''
                    try:
                        text = data.decode('utf-8', errors='replace')
                    except:
                        text = repr(data)
                    _log(f'  Data ({len(data)} bytes): {text[:200]}')
                else:
                    _log(f'  No data received')
            except socket.timeout:
                _log(f'  Timeout waiting for data')
            finally:
                conn.close()
        except socket.timeout:
            continue
        except Exception as e:
            _log(f'  Error: {e}')
            break


def main():
    _log('=== Packet sniffer started ===')
    _log('Monitoring ports 8080 and 443 for CDN requests from the game')
    _log('')

    # Sniff on port 8080 in background
    t1 = threading.Thread(target=sniff_port, args=(18080, 'HTTP-8080'), daemon=True)
    t1.start()

    # Sniff on port 8443 in background
    t2 = threading.Thread(target=sniff_port, args=(18443, 'HTTPS-8443'), daemon=True)
    t2.start()

    _log('Sniffers ready. Launch hsqsl.exe now.')
    _log('Press Ctrl+C to stop.')

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        _log('Stopped.')


if __name__ == '__main__':
    main()
