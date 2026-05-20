"""Mock HTTP server for NetEase SDK endpoints.

Intercepts requests to:
  - mgbsdk.matrix.netease.com
  - unisdk.update.easebar.com
  - applog.matrix.easebar.com
  - *.update.netease.com (server list CDN)
  - *.update.easebar.com

Returns minimal valid responses to prevent SDK from erroring out.
"""

import socket
import threading
import json
import sys
import os
import re
import base64
import ssl
import tempfile
import datetime

sys.path.insert(0, os.path.dirname(__file__))
from logger import setup_logger

_log = setup_logger('MockHTTP')


# Simple threaded HTTP server
class MockHTTPServer:
    """Minimal HTTP server for mocking SDK endpoints."""

    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.sock = None
        self._running = False
        self.routes = {}
        self._log = _log

    def route(self, path_pattern, handler):
        """Register a route handler. Handler receives (method, path, headers, body)
        and returns (status_code, content_type, response_body)."""
        self.routes[path_pattern] = handler

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(10)
        self.sock.settimeout(1.0)
        self._running = True
        self._log(f'Listening on {self.host}:{self.port}')

    def stop(self):
        self._running = False
        if self.sock:
            self.sock.close()

    def _parse_request(self, data):
        """Parse HTTP request. Returns (method, path, headers, body)."""
        try:
            text = data.decode('utf-8', errors='replace')
        except:
            text = data.decode('latin-1', errors='replace')

        lines = text.split('\r\n')
        if not lines:
            return None, None, {}, b''

        # Request line
        parts = lines[0].split(' ')
        method = parts[0] if len(parts) > 0 else 'GET'
        path = parts[1] if len(parts) > 1 else '/'

        # Headers
        headers = {}
        i = 1
        while i < len(lines) and lines[i]:
            if ':' in lines[i]:
                key, val = lines[i].split(':', 1)
                headers[key.strip().lower()] = val.strip()
            i += 1

        # Body
        if '\r\n\r\n' in text:
            body_start = text.index('\r\n\r\n') + 4
            body = data[body_start:]
        else:
            body = b''

        return method, path, headers, body

    def _build_response(self, status, content_type, body,
                        extra_headers=None):
        """Build an HTTP response."""
        if isinstance(body, str):
            body = body.encode('utf-8')

        response = f'HTTP/1.1 {status}\r\n'
        response += f'Content-Type: {content_type}\r\n'
        response += f'Content-Length: {len(body)}\r\n'
        response += 'Access-Control-Allow-Origin: *\r\n'
        response += 'Connection: close\r\n'
        if extra_headers:
            for k, v in extra_headers.items():
                response += f'{k}: {v}\r\n'
        response += '\r\n'

        return response.encode('utf-8') + body

    def _find_handler(self, path):
        """Find a matching route handler."""
        for pattern, handler in self.routes.items():
            if re.match(pattern, path):
                return handler
        return None

    def _handle_client(self, conn, addr):
        """Handle a single client connection."""
        try:
            conn.settimeout(5.0)
            data = conn.recv(65536)
            if not data:
                return

            method, path, headers, body = self._parse_request(data)

            if method is None:
                conn.close()
                return

            self._log(f'{method} {path} from {addr[0]}:{addr[1]}')
            if headers:
                host = headers.get('host', '')
                self._log(f'  Host: {host} | Body: {len(body)} bytes')

            # Handle CORS preflight
            if method == 'OPTIONS':
                response = self._build_response(
                    '200 OK', 'text/plain', b'',
                    extra_headers={
                        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type',
                    })
                conn.send(response)
                conn.close()
                return

            # Find handler
            handler = self._find_handler(path)
            if handler:
                result = handler(method, path, headers, body)
                if len(result) == 4:
                    status, content_type, resp_body, extra_headers = result
                else:
                    status, content_type, resp_body = result
                    extra_headers = None
                response = self._build_response(status, content_type, resp_body,
                                                extra_headers=extra_headers)
            else:
                # Default: return empty JSON
                self._log(f'No handler for {path}, returning empty JSON')
                response = self._build_response(
                    '200 OK', 'application/json', json.dumps({}))

            conn.send(response)

        except socket.timeout:
            pass
        except Exception as e:
            self._log(f'Error handling {addr}: {e}')
        finally:
            conn.close()

    def run(self):
        """Main loop."""
        self.start()
        self._log('Server running. Press Ctrl+C to stop.')
        try:
            while self._running:
                try:
                    conn, addr = self.sock.accept()
                    t = threading.Thread(target=self._handle_client,
                                         args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        self._log(f'Accept error: {e}')
        except KeyboardInterrupt:
            self._log('Shutting down...')
        finally:
            self.stop()


def create_sdk_mock(port=8080):
    """Create a mock HTTP server configured for HSQSL SDK endpoints."""

    server = MockHTTPServer(port=port)

    # SDK init endpoint
    def handle_sdk(method, path, headers, body):
        _log(f'SDK request: {method} {path}')
        return '200 OK', 'application/json', json.dumps({
            'code': 0,
            'msg': 'ok',
            'data': {
                'token': 'mock_token_000000',
                'uin': 'mock_uin_000000',
                'channel': 'netease',
            }
        })

    # SDK update/config endpoint
    def handle_config(method, path, headers, body):
        return '200 OK', 'application/json', json.dumps({
            'code': 0,
            'data': {
                'latest_version': '1.0.0',
                'update_url': '',
                'force_update': False,
            }
        })

    # SDK log endpoint (just accept and ignore)
    def handle_log(method, path, headers, body):
        return '200 OK', 'application/json', json.dumps({'code': 0})

    # Server list CDN endpoint — serve real pre-downloaded CDN data
    _server_list_cache = None

    def handle_server_list(method, path, headers, body):
        nonlocal _server_list_cache
        if _server_list_cache is None:
            list_path = os.path.join(os.path.dirname(__file__), 'cdn_server_list.txt')
            if os.path.exists(list_path):
                with open(list_path, 'r', encoding='utf-8') as f:
                    _server_list_cache = f.read()
                _log(f'Loaded CDN server list: {len(_server_list_cache)} bytes')
            else:
                _log('WARNING: cdn_server_list.txt not found, using fallback')
                _server_list_cache = '127.0.0.1\t9090\tLOCAL\t0\t1\t0\tNETEASE\n'
        return '200 OK', 'text/plain', _server_list_cache

    # Patch hotfix data endpoint — return base64-encoded empty JSON dict.
    # on_get_hotfix_data base64-decodes the body, then JSON-parses it.
    # An empty dict means "no hotfix to apply", game proceeds normally.
    def handle_patch_hotfix(method, path, headers, body):
        _log(f'Patch hotfix request: {method} {path}')
        # Empty hotfix dict: base64("{}") = "e30="
        return '200 OK', 'text/plain', 'e30='

    # Patch hotfix data pub endpoint — returns actual hotfix code for versions 1.0.1/3/7/9
    _hotfix_pub_cache = None

    def handle_patch_hotfix_pub(method, path, headers, body):
        nonlocal _hotfix_pub_cache
        _log(f'Patch hotfix pub request: {method} {path}')
        if _hotfix_pub_cache is None:
            hotfix_path = os.path.join(os.path.dirname(__file__), 'patch_hotfix_data_pub.json')
            if os.path.exists(hotfix_path):
                with open(hotfix_path, 'r', encoding='utf-8') as f:
                    hotfix_json = f.read()
                _hotfix_pub_cache = base64.b64encode(hotfix_json.encode('utf-8')).decode('ascii')
                _log(f'Loaded hotfix pub data: {len(_hotfix_pub_cache)} chars base64')
            else:
                _log('WARNING: patch_hotfix_data_pub.json not found, using empty dict')
                _hotfix_pub_cache = 'e30='
        return '200 OK', 'text/plain', _hotfix_pub_cache

    # Patch list pub win endpoint — returns patch metadata for the win platform
    _patch_list_cache = None

    def handle_patch_list_pub_win(method, path, headers, body):
        nonlocal _patch_list_cache
        _log(f'Patch list pub win request: {method} {path}')
        if _patch_list_cache is None:
            list_path = os.path.join(os.path.dirname(__file__), 'patch_list_pub_win.txt')
            if os.path.exists(list_path):
                with open(list_path, 'r', encoding='utf-8') as f:
                    _patch_list_cache = f.read()
                _log(f'Loaded patch list pub win: {len(_patch_list_cache)} bytes')
            else:
                _log('WARNING: patch_list_pub_win.txt not found')
                _patch_list_cache = '{}'
        return '200 OK', 'application/json', _patch_list_cache

    # Game notice endpoint — serve real XML notice data
    _game_notice_cache = None

    def handle_game_notice(method, path, headers, body):
        nonlocal _game_notice_cache
        _log(f'Game notice request: {method} {path}')
        if _game_notice_cache is None:
            notice_path = os.path.join(os.path.dirname(__file__), 'game_notice.xml')
            if os.path.exists(notice_path):
                with open(notice_path, 'r', encoding='utf-8') as f:
                    _game_notice_cache = f.read()
                _log(f'Loaded game notice: {len(_game_notice_cache)} bytes')
            else:
                _log('WARNING: game_notice.xml not found')
                _game_notice_cache = '<?xml version="1.0" ?><root/>'
        return '200 OK', 'text/xml', _game_notice_cache

    # CDN patch file download — return zero-filled body with correct size.
    # The game downloads npkhead files via Range requests. We return dummy data
    # so the size check passes. parse_npkhead_filedata will fail to parse, the
    # exception is caught, and an empty dict is used → skips NPK verification.
    _CDN_FILE_TOTAL_SIZE = 3125684  # From observed Range requests

    def handle_cdn_patch(method, path, headers, body):
        _log(f'CDN patch request: {method} {path}')
        is_txt = '.txt' in path.split('?')[0]
        content_type = 'text/plain' if is_txt else 'application/octet-stream'
        range_header = headers.get('range', '')
        if range_header.startswith('bytes='):
            range_spec = range_header[6:]
            parts = range_spec.split('-')
            range_start = int(parts[0])
            range_end = int(parts[1]) if parts[1] else _CDN_FILE_TOTAL_SIZE - 1
            chunk_size = range_end - range_start + 1
            if is_txt:
                dummy_data = b'dummy 0 0\n' * ((chunk_size // 11) + 1)
                dummy_data = dummy_data[:chunk_size]
            else:
                dummy_data = b'\x00' * chunk_size
            return ('206 Partial Content', content_type, dummy_data,
                    {'Content-Range': f'bytes {range_start}-{range_end}/{_CDN_FILE_TOTAL_SIZE}',
                     'Accept-Ranges': 'bytes'})
        else:
            if is_txt:
                dummy_data = b'dummy 0 0\n'
            else:
                dummy_data = b'\x00' * _CDN_FILE_TOTAL_SIZE
            return '200 OK', content_type, dummy_data

    # Register routes — specific routes first, then CDN patterns, catch-all last
    server.route(r'^/pl/patch_hotfix_data_pub$', handle_patch_hotfix_pub)
    server.route(r'^/pl/patch_hotfix_data$', handle_patch_hotfix)
    server.route(r'^/pl/patch_list_pub_win\.txt$', handle_patch_list_pub_win)
    server.route(r'^/serverlist', handle_server_list)
    server.route(r'^/h62/serverlist', handle_server_list)
    server.route(r'^/server_list_public\.txt', handle_server_list)
    server.route(r'^/server_list\.txt', handle_server_list)
    server.route(r'^/server_list_pre\.txt', handle_server_list)
    server.route(r'^/server_list_mirror\.txt', handle_server_list)
    server.route(r'^/game_notice/notice_formal$', handle_game_notice)

    # CDN patch file downloads — return empty binary for all CDN file types
    server.route(r'\.(npkhead|npk|zip|dat|bin|json|txt)(\?|$)', handle_cdn_patch)
    server.route(r'/patch_pub\.', handle_cdn_patch)
    server.route(r'/h62/', handle_cdn_patch)
    server.route(r'/cdn/', handle_cdn_patch)

    server.route(r'.*', handle_sdk)  # Catch-all for all SDK requests

    # Also start HTTPS server on 443 for hotfix download
    _start_https_server(server, 443)

    # Also start HTTP on port 80 for SDK requests that use HTTP
    _start_extra_http(server, 80)

    return server


def _generate_self_signed_cert(cert_file, key_file):
    """Generate a self-signed certificate for HTTPS interception."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(key_file, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'h62.update.netease.com')])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    with open(cert_file, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _start_https_server(server, port=443):
    """Start an HTTPS wrapper sharing the same route handlers."""
    cert_file = os.path.join(tempfile.gettempdir(), 'mock_https.crt')
    key_file = os.path.join(tempfile.gettempdir(), 'mock_https.key')
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        _generate_self_signed_cert(cert_file, key_file)

    def run_https():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_file, key_file)
            sock.bind(('0.0.0.0', port))
            sock.listen(10)
            sock.settimeout(1.0)
            _log(f'HTTPS listening on port {port}')
            while server._running:
                try:
                    conn, addr = sock.accept()
                    ssl_conn = ctx.wrap_socket(conn, server_side=True)
                    threading.Thread(target=server._handle_client,
                                     args=(ssl_conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except PermissionError:
            _log(f'HTTPS port {port} requires Administrator. Skipping HTTPS.')
        except Exception as e:
            _log(f'HTTPS Error: {e}')

    threading.Thread(target=run_https, daemon=True).start()


def _start_extra_http(server, port=80):
    """Start an extra HTTP server on an additional port sharing same routes."""
    def run_http():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(10)
            sock.settimeout(1.0)
            _log(f'HTTP extra listening on port {port}')
            while server._running:
                try:
                    conn, addr = sock.accept()
                    threading.Thread(target=server._handle_client,
                                     args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except PermissionError:
            _log(f'HTTP port {port} requires Administrator. Skipping.')
        except Exception as e:
            _log(f'HTTP extra Error: {e}')

    threading.Thread(target=run_http, daemon=True).start()


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = create_sdk_mock(port)
    _start_https_server(server, 443)
    _start_extra_http(server, 80)  # SDK uses HTTP on port 80 too
    server.run()
