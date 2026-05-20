"""Mock Gate Server for HSQSL — handshake ONLY, delegates entity lifecycle to Game Server.

Architecture (IDA-verified from real client, updated 2026-05-17):
  TCP #1 (Gate, port 9090+):
    Client → seed_request (cmd=0) → Server
    Client ← seed_reply (cmd=0) ← Server
    Client → session_key (cmd=1) → Server
    Client ← session_key_ok (cmd=1) ← Server  (DIRECT handler, bypasses oneof)
    Client → connect_server (cmd=2) → Server
    Client ← connect_reply (cmd=2, GateClientMsg oneof wrapped) ← Server
      routes field contains ClientBindMsg{ServerInfo{ip, port}}
      → C++ protobuf parser triggers bind_client_to_game() → TCP #2 connection
      extramsg field also contains ClientBindMsg for Python handler fallback

  TCP #2 (Game, port 9091):
    Second handshake (seed→session_key→connect_server)
    Server → create_entity Account (cmd=3)
    Server → become_player (cmd=5)
    Client → quick_login (cmd=3)
    Server ← login_result, on_hotfix_when_login, on_get_all_avatars (cmd=5)

Key insight: bind_client_to_game() is a C++ protobuf-level side effect triggered
by parsing field 1 (routes) of ConnectServerReply. It is NOT triggered by the
Python handler. The sub_ECA810 C++ handler ignores routes completely.
"""

import socket
import struct
import random
import sys
import os
import select
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from logger import setup_logger
from marshal_dump_py3 import dump_marshal
from proto_utils import (
    ARC4Cipher, parse_proto, hexdump,
    build_session_seed, build_void,
    build_connect_server_reply, build_gate_client_msg,
    build_server_info_wire, build_client_info_wire, build_client_bind_msg_wire,
    build_frame, parse_frame,
    rsa_decrypt_session_key,
    encode_bson_document,
    build_entity_info, build_entity_message,
    C_IN_SEED_REQUEST, C_IN_SESSION_KEY, C_IN_CONNECT_SERVER,
    C_IN_ENTITY_MESSAGE,
    C_OUT_SEED_REPLY, C_OUT_SESSION_KEY_OK, C_OUT_CONNECT_REPLY,
    C_OUT_CREATE_ENTITY, C_OUT_ENTITY_MESSAGE,
    GATE_MSG_CONNECT_REPLY, GATE_MSG_CREATE_ENTITY, GATE_MSG_ENTITY_MESSAGE,
    REPLY_CONNECTED, REQUEST_NEW_CONNECTION,
    GATE_STATE, GAME_PENDING_QUEUE,
)


# Diagnostic flag: send connect_reply as PLAINTEXT (PATCH_LOG planned test)
# Hypothesis: sub_EC2580 encryption flag at *((_BYTE *)this + 512) may be FALSE,
# causing encrypted path (vtable[5] → sub_ECAEC0 → sub_E99240) to be bypassed.
# If TRUE: connect_reply goes through plaintext path (sub_E68530) which may work.
DIAG_PLAINTEXT = False  # PLAINTEXT test done: encryption NOT the issue. Root cause: missing entity_msg_guard EXE patches

class MockGateServer:
    """TCP mock gate server — handshake + entity lifecycle on single connection."""

    ENTITY_CREATE_DELAY = 0.5     # seconds after connect_reply before create_entity
    BECOME_PLAYER_DELAY = 0.5     # seconds after create_entity before become_player
    AUTO_AVATAR_DELAY = 1.0       # seconds after login_result before auto-creating avatar

    def __init__(self, host='0.0.0.0', ports=None, game_port=9091, game_host='127.0.0.1'):
        self.host = host
        self.ports = ports or [9090]
        self.game_port = game_port
        self.game_host = game_host
        self.sockets = []
        self._udp_sockets = []  # UDP sockets to prevent ICMP port unreachable for KCP
        self._running = False
        self._log = setup_logger('MockGate')
        self._client_buf = {}   # (ip, port) -> bytearray
        self._conn = {}         # (ip, port) -> {entity_id, arc4_enc, arc4_dec, encrypted, arc4_key, phase}
        self._addr_port = {}    # (ip, port) -> gate_port

        # RPC dispatch: method_name -> handler
        self.RPC_DISPATCH = {
            'quick_login': self._handle_quick_login,
            'sdk_login': self._handle_quick_login,
            'select_avatar': self._handle_select_avatar,
            'keep_alive': self._handle_keep_alive,
            'ping': self._handle_keep_alive,
        }

    def start(self):
        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                sock.listen(5)
                sock.setblocking(False)
                self.sockets.append(sock)
                self._log(f'TCP listening on {self.host}:{port}')
            except OSError as e:
                self._log(f'Failed to bind {self.host}:{port}: {e}')

            # UDP socket to prevent ICMP port-unreachable for KCP connections
            try:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp_sock.bind((self.host, port))
                udp_sock.setblocking(False)
                self._udp_sockets.append(udp_sock)
            except OSError as e:
                self._log(f'UDP bind failed {self.host}:{port}: {e}')

        if not self.sockets:
            raise RuntimeError('No ports could be bound')
        self._running = True

    def stop(self):
        self._running = False
        for sock in self.sockets:
            try:
                sock.close()
            except Exception:
                pass
        self.sockets.clear()
        for sock in self._udp_sockets:
            try:
                sock.close()
            except Exception:
                pass
        self._udp_sockets.clear()

    # ------------------------------------------------------------------
    # ARC4-aware frame send
    # ------------------------------------------------------------------
    def _send_frame(self, client_sock, addr, cmd, payload, force_plaintext=False):
        try:
            key = (addr[0], addr[1])
            conn = self._conn.get(key, {})
            frame = build_frame(cmd, payload)
            if not force_plaintext and conn.get('encrypted') and conn.get('arc4_enc'):
                frame = conn['arc4_enc'].crypt(frame)
            self._log(hexdump(frame, f'[{addr[0]}:{addr[1]}] TX cmd={cmd} ({len(frame)}b):'))
            client_sock.sendall(frame)
        except Exception as e:
            self._log(f'send error to {addr}: {e}')

    def _send_gate_msg(self, client_sock, addr, oneof_field, inner_msg):
        """Send a message wrapped in GateClientMsg oneof via cmd=2.

        IDA-verified: ALL server→client messages on TCP #1 MUST go through
        cmd=2 + GateClientMsg oneof. The dispatcher sub_E99240 routes to
        the correct handler based on the oneof field number found in the
        wire format. Sending entity msgs via cmd=3/5 bypasses this dispatch.
        """
        wrapped = build_gate_client_msg(oneof_field, inner_msg)
        self._send_frame(client_sock, addr, 2, wrapped)

    # ------------------------------------------------------------------
    # Handshake steps
    # ------------------------------------------------------------------
    def _send_seed_reply(self, client_sock, addr):
        seed_msg = build_session_seed(random.randint(1, 2**63 - 1))
        self._send_frame(client_sock, addr, C_OUT_SEED_REPLY, seed_msg)
        self._log(f'<- seed_reply')

    def _send_session_key_ok(self, client_sock, addr):
        self._send_frame(client_sock, addr, C_OUT_SESSION_KEY_OK, build_void())
        self._log(f'<- session_key_ok')

    def _handle_connect(self, client_sock, addr, payload):
        """Parse connect_server, build valid routes, share ARC4 state, send connect_reply.

        IDA-verified: bind_client_to_game() parses the routes field (field 1)
        from ConnectServerReply to extract ClientBindMsg → ServerInfo → TCP #2.

        The extramsg field (field 4) is passed to the Python connect_reply handler
        but does NOT trigger TCP #2 establishment.
        """
        parsed = {}
        if payload:
            parsed = parse_proto(payload)
        request_type = parsed.get(2, REQUEST_NEW_CONNECTION)
        client_entity_id = parsed.get(3, b'')  # raw 12 bytes or 24-byte hex
        extra_msg = parsed.get(4, b'')

        type_names = {0: 'NEW_CONNECTION', 1: 'RE_CONNECTION', 2: 'BIND_AVATAR', 3: 'BIND_SOUL'}
        self._log(f'connect_server: type={type_names.get(request_type, request_type)} '
                  f'entity_id={client_entity_id.hex() if client_entity_id else "none"} '
                  f'len={len(client_entity_id)} extra={len(extra_msg)}b')

        # Convert entity_id: 24-byte ASCII hex → 12 raw bytes (for C++ wire format)
        entity_id = None
        if len(client_entity_id) == 24:
            try:
                entity_id = bytes.fromhex(client_entity_id.decode('ascii'))
                self._log(f'entity_id hex→raw: {client_entity_id.decode()} → {entity_id.hex()}')
            except (ValueError, UnicodeDecodeError):
                pass
        if not entity_id and len(client_entity_id) == 12:
            entity_id = client_entity_id
        if not entity_id:
            self._log(f'WARNING: entity_id is {len(client_entity_id)}B, using as-is')
            entity_id = client_entity_id if client_entity_id else b'\x00' * 12

        key = (addr[0], addr[1])
        conn = self._conn.setdefault(key, {})
        conn['entity_id'] = entity_id

        # Share ARC4 state with Game Server (used for TCP #2 encryption sync)
        if conn.get('arc4_key'):
            GATE_STATE[entity_id] = {
                'arc4_key': conn['arc4_key'],
                'arc4_enc': conn['arc4_enc'],
                'arc4_dec': conn['arc4_dec'],
            }
            GAME_PENDING_QUEUE.append((
                entity_id,
                conn['arc4_key'],
                conn['arc4_enc'],
                conn['arc4_dec'],
            ))
            self._log(f'ARC4 state queued for game server, entity={entity_id.hex()}')

        # Build ClientBindMsg → routes field (triggers bind_client_to_game → TCP #2)
        # Try NPK-verified C++ field numbers (from protobuf definitions in bytecode)
        server_info = build_server_info_wire(
            servername=self.game_host,
            dport=self.game_port,
            use_ida_fields=False,
        )
        self._log(hexdump(server_info, f'ServerInfo NPK wire ({len(server_info)}B):'))

        # Build ClientInfo with required fields (NPK-verified from D7A991AF.py)
        # Use entity_id bytes as client_id; ARC4 key as session_id (or fallback)
        session_id = conn.get('arc4_key', b'\x01\x02\x03\x04')[:4]
        client_info = build_client_info_wire(
            client_id=entity_id,
            session_id=session_id,
            gate_id=b'\x05\x06\x07\x08',
        )
        self._log(hexdump(client_info, f'ClientInfo NPK wire ({len(client_info)}B):'))

        client_bind = build_client_bind_msg_wire(entity_id, server_info,
                                                  use_ida_fields=False,
                                                  client_info_wire=client_info)
        self._log(hexdump(client_bind, f'ClientBindMsg NPK wire ({len(client_bind)}B):'))

        # Build ConnectServerReply with ClientBindMsg in routes field.
        # IDA-verified: The C++ protobuf parser triggers bind_client_to_game()
        # ONLY when parsing field 1 (routes). The sub_ECA810 C++ handler ignores
        # routes and passes extramsg to Python, but the protobuf-level side effect
        # (TCP #2 establishment) happens during parsing, BEFORE sub_ECA810 runs.
        # We put ClientBindMsg in BOTH fields: routes for C++ trigger, extramsg for Python.
        reply_inner = build_connect_server_reply(
            con_type=REPLY_CONNECTED,
            entityid=client_entity_id,   # preserve original format for Python handler
            routes=client_bind,           # ← C++ protobuf parser → bind_client_to_game → TCP #2
            extramsg=client_bind,         # ← Python handler receives this too
        )
        self._log(hexdump(reply_inner, f'ConnectServerReply inner ({len(reply_inner)}B):'))

        # Send via GateClientMsg field 3 (connect_reply) wrapped in cmd=2.
        # IDA-verified dispatch: cmd=2 → sub_EC2580 → sub_ECAEC0 → sub_E99240
        # (GateClientMsg oneof dispatcher). Field 3 → case 2 → sub_ECA810 → Python.
        if DIAG_PLAINTEXT:
            wrapped = build_gate_client_msg(GATE_MSG_CONNECT_REPLY, reply_inner)
            self._send_frame(client_sock, addr, C_OUT_CONNECT_REPLY, wrapped, force_plaintext=True)
            self._log(f'<- connect_reply (PLAINTEXT DIAG, GateClientMsg field {GATE_MSG_CONNECT_REPLY}) → {self.game_host}:{self.game_port}, '
                      f'entity={entity_id.hex()}, routes={len(client_bind)}B ClientBindMsg')
        else:
            self._send_gate_msg(client_sock, addr, GATE_MSG_CONNECT_REPLY, reply_inner)
            self._log(f'<- connect_reply (GateClientMsg field {GATE_MSG_CONNECT_REPLY}) → {self.game_host}:{self.game_port}, '
                      f'entity={entity_id.hex()}, routes={len(client_bind)}B ClientBindMsg')
        self._log('Gate handshake complete — starting entity lifecycle on gate connection')

        # v14+: Entity lifecycle is hardcoded in bytecode (DCE9232F_ENTITY_V15).
        # Bytecode creates Account+Avatar, sets up server_proxy, calls on_become_player.
        # We skip entity creation (duplicate conflict) BUT still send
        # on_avatar_enter_world to trigger the C++ scene transition handler.
        avatar_eid = bytearray(entity_id)
        avatar_eid[-1] = (avatar_eid[-1] + 1) & 0xFF
        avatar_eid = bytes(avatar_eid)
        enter_world_delay = 2.5  # seconds for bytecode entity creation + scene preloading
        self._log(f'v14+: skipping entity creation, scheduling on_avatar_enter_world for '
                  f'Avatar={avatar_eid.hex()} in {enter_world_delay}s')
        conn['avatar_entity_id'] = avatar_eid
        conn['phase'] = 'awaiting_enter_world'
        timer = threading.Timer(enter_world_delay,
                                lambda: self._send_enter_world(client_sock, addr, avatar_eid))
        timer.daemon = True
        timer.start()

    # ------------------------------------------------------------------
    # Command dispatch (handshake + entity lifecycle on gate connection)
    # ------------------------------------------------------------------
    def _handle_cmd(self, cmd, payload, client_sock, addr):
        if cmd == C_IN_SEED_REQUEST:
            self._log(f'-> seed_request from {addr}')
            self._send_seed_reply(client_sock, addr)

        elif cmd == C_IN_SESSION_KEY:
            self._log(f'-> session_key from {addr}')
            key = (addr[0], addr[1])
            conn = self._conn.setdefault(key, {})

            if payload:
                self._log(hexdump(payload, 'session_key payload:'))
                parsed = parse_proto(payload)
                ciphertext = parsed.get(1, b'')
                if ciphertext:
                    plaintext, arc4_key = rsa_decrypt_session_key(ciphertext)
                    if plaintext:
                        self._log(f'RSA decrypt OK: {len(plaintext)} random bytes, '
                                  f'ARC4 key: {arc4_key.hex()[:16]}...')
                        conn['arc4_enc'] = ARC4Cipher(arc4_key)
                        conn['arc4_dec'] = ARC4Cipher(arc4_key)
                        conn['arc4_key'] = arc4_key
                        conn['encrypted'] = True
                        conn['_arc4_pending'] = True
                        self._log(f'ARC4 ciphers stored (send encrypted, recv auto-detect)')
                    else:
                        self._log(f'RSA decrypt FAILED')
            self._send_session_key_ok(client_sock, addr)

        elif cmd == C_IN_CONNECT_SERVER:
            self._log(f'-> connect_server from {addr}')
            if payload:
                self._log(hexdump(payload, 'connect_server payload:'))
            self._handle_connect(client_sock, addr, payload)

        elif cmd == C_IN_ENTITY_MESSAGE and len(payload) >= 2:
            self._handle_entity_message(client_sock, addr, payload)

        else:
            self._log(f'Unknown cmd={cmd} from {addr}')
            if payload:
                self._log(hexdump(payload, f'Unknown cmd={cmd} payload:'))

    # ------------------------------------------------------------------
    # Entity lifecycle (on gate connection since TCP #2 never establishes)
    # ------------------------------------------------------------------
    def _start_entity_lifecycle(self, client_sock, addr):
        """Step 1: create_entity Account on gate connection."""
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        entity_id = conn.get('entity_id')
        if not entity_id:
            self._log(f'[{addr}] _start_entity_lifecycle: no entity_id, aborting')
            return

        self._log(f'[{addr}] Entity lifecycle START for entity={entity_id.hex()}')
        conn['phase'] = 'creating_entity'

        account_bson = encode_bson_document({
            'entity_id': entity_id,
            'account': 'player1',
            'server_id': 10018,
            'check_cards': [2403, 4501, 2201, 4601, 5601, 2501, 4202, 3504, 1205, 4404,
                            2203, 3404, 5411, 5311, 5511, 2503, 3403, 1203, 1502, 2202,
                            4401, 3202, 4411, 2405, 1202, 2301, 2402, 4101, 4, 3401,
                            1303, 3102, 5101, 5211, 5201, 5301, 2101, 4502, 2302, 3402,
                            5112, 3406, 4406, 1302, 1201, 3201, 4602, 5501, 4409, 1204,
                            3101, 5222, 2407, 5401, 3501, 1101, 3405, 3502, 2102, 2504, 4410],
            'cards_intimacy_level': {2403: 2, 4501: 3, 2201: 3, 4601: 3,
                                     2501: 2, 4202: 4, 3504: 2, 1205: 1, 4404: 3,
                                     2203: 5, 3404: 4, 3403: 3, 1203: 4, 1502: 5,
                                     2202: 5, 4401: 4, 3202: 3, 4411: 3, 2405: 3,
                                     3401: 5, 4502: 3, 3402: 4, 1201: 2, 2407: 5, 4410: 2},
        })
        entity_info = build_entity_info(b'Account', entity_id, bson_info=account_bson)
        self._send_gate_msg(client_sock, addr, GATE_MSG_CREATE_ENTITY, entity_info)
        self._log(f'[{addr}] -> create_entity Account id={entity_id.hex()}')
        conn['phase'] = 'entity_create_sent'

        timer = threading.Timer(self.BECOME_PLAYER_DELAY, self._send_become_player,
                                args=(client_sock, addr))
        timer.daemon = True
        timer.start()

    def _send_become_player(self, client_sock, addr):
        """Step 2: send become_player to trigger Account.on_become_player()."""
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        entity_id = conn.get('entity_id')
        if not entity_id:
            return

        conn['phase'] = 'sending_become_player'
        msg = build_entity_message(entity_id, b'become_player')
        self._send_gate_msg(client_sock, addr, GATE_MSG_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] -> become_player for Account id={entity_id.hex()}')
        conn['phase'] = 'awaiting_quick_login'

    def _auto_create_avatar(self, client_sock, addr):
        """After login, auto-create an Avatar entity and enter world."""
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        account_entity_id = conn.get('entity_id')
        if not account_entity_id:
            return

        avatar_eid = bytearray(account_entity_id)
        if len(avatar_eid) >= 4:
            avatar_eid[-1] = (avatar_eid[-1] + 1) & 0xFF
        avatar_eid = bytes(avatar_eid)
        conn['avatar_entity_id'] = avatar_eid

        conn['phase'] = 'creating_avatar'
        self._log(f'[{addr}] Auto-creating Avatar entity={avatar_eid.hex()}')

        avatar_bson = encode_bson_document({
            'name': '永恒',
            'level': 60,
            'sex': 1,
            'career': 1,
            'server_id': 10018,
            'server_name': 'LocalTest',
            'head_id': 2,
            'head_box_id': 1027,
        })
        entity_info = build_entity_info(b'Avatar', avatar_eid, bson_info=avatar_bson)
        self._send_gate_msg(client_sock, addr, GATE_MSG_CREATE_ENTITY, entity_info)
        self._log(f'[{addr}] -> create_entity Avatar id={avatar_eid.hex()}')

        timer = threading.Timer(self.BECOME_PLAYER_DELAY,
                                lambda: self._send_avatar_become_player(client_sock, addr))
        timer.daemon = True
        timer.start()

    def _send_avatar_become_player(self, client_sock, addr):
        """Send become_player for the Avatar entity."""
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        avatar_eid = conn.get('avatar_entity_id')
        if not avatar_eid:
            return

        conn['phase'] = 'avatar_become_player'
        msg = build_entity_message(avatar_eid, b'become_player')
        self._send_gate_msg(client_sock, addr, GATE_MSG_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] -> become_player for Avatar id={avatar_eid.hex()}')

        timer = threading.Timer(0.3,
                                lambda: self._send_enter_world(client_sock, addr, avatar_eid))
        timer.daemon = True
        timer.start()

    def _send_enter_world(self, client_sock, addr, avatar_eid):
        """v17: on_avatar_enter_world is now sent by mock_game via game connection.

        Gate connection (TCP#1) cannot dispatch entity messages (cmd=5) because
        its protobuf parser only handles GateClientMsg (cmd=0-2). The game
        connection (TCP#2) natively supports EntityMessage dispatch via
        handler_table[5] = sub_EC2AF0 → "game_callback" → Python.
        """
        self._log(f'[{addr}] v17: on_avatar_enter_world for Avatar={avatar_eid.hex()} '
                  f'→ delegated to game connection')

    # ------------------------------------------------------------------
    # RPC handlers
    # ------------------------------------------------------------------
    def _handle_quick_login(self, client_sock, addr, entity_id, rpc_payload, reliable, localid):
        """Handle quick_login/sdk_login: send login_result + hotfix + avatars."""
        self._log(f'[{addr}] RPC quick_login from entity={entity_id.hex()}')
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        conn['phase'] = 'processing_login'

        login_params = dump_marshal((0, 'ok', 0))
        msg = build_entity_message(entity_id, b'login_result', login_params,
                                   reliable=reliable, localid=localid)
        self._send_gate_msg(client_sock, addr, GATE_MSG_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] <- login_result (success)')

        hotfix_params = dump_marshal(('', 0))
        msg2 = build_entity_message(entity_id, b'on_hotfix_when_login', hotfix_params)
        self._send_gate_msg(client_sock, addr, GATE_MSG_ENTITY_MESSAGE, msg2)
        self._log(f'[{addr}] <- on_hotfix_when_login (empty)')

        avatar_list = [{
            'hostnum': 0,
            'avatar_info': {
                'hostnum': 0,
                'name': '永恒',
                'level': 60,
                'sex': 1,
                'career': 1,
                'server_id': 10018,
                'server_name': 'LocalTest',
                'head_id': 2,
                'head_box_id': 1027,
                'create_time': 1700000000,
                'last_login_time': 1700000000,
            }
        }]
        avatar_params = dump_marshal((avatar_list,))
        msg3 = build_entity_message(entity_id, b'on_get_all_avatars', avatar_params)
        self._send_gate_msg(client_sock, addr, GATE_MSG_ENTITY_MESSAGE, msg3)
        self._log(f'[{addr}] <- on_get_all_avatars ({len(avatar_list)} avatars)')

        conn['phase'] = 'login_done'
        self._log(f'[{addr}] Login complete — auto-creating avatar')

        timer = threading.Timer(self.AUTO_AVATAR_DELAY,
                                lambda: self._auto_create_avatar(client_sock, addr))
        timer.daemon = True
        timer.start()

    def _handle_select_avatar(self, client_sock, addr, entity_id, rpc_payload, reliable, localid):
        """Handle select_avatar RPC."""
        self._log(f'[{addr}] RPC select_avatar from entity={entity_id.hex()}')
        self._auto_create_avatar(client_sock, addr)

    def _handle_keep_alive(self, client_sock, addr, entity_id, rpc_payload, reliable, localid):
        """Handle keep_alive/ping — heartbeat ACK."""
        self._log(f'[{addr}] RPC keep_alive/ping from entity={entity_id.hex()} — ACK')

    # ------------------------------------------------------------------
    # Entity message parser
    # ------------------------------------------------------------------
    def _handle_entity_message(self, client_sock, addr, payload):
        """Parse EntityMessage and dispatch to RPC handler.

        Fields: 1=routes, 2=entity_id, 3=method(Md5OrIndex), 4=parameters,
                5=reliable, 6=localid
        """
        parsed = parse_proto(payload)
        entity_id = parsed.get(2, b'')
        method_data = parsed.get(3, b'')
        rpc_payload = parsed.get(4, b'')
        reliable = parsed.get(5, 0)
        localid = parsed.get(6, 0)

        method_parsed = parse_proto(method_data) if method_data else {}
        method_md5 = method_parsed.get(1, b'')
        method_name = method_md5.decode(errors='replace') if isinstance(method_md5, bytes) else 'unknown'

        self._log(f'[{addr}] entity RPC: entity={entity_id.hex() if entity_id else "??"} '
                  f'method={method_name} reliable={reliable} localid={localid}')

        if not entity_id:
            return

        handler = self.RPC_DISPATCH.get(method_name)
        if handler:
            handler(client_sock, addr, entity_id, rpc_payload, reliable, localid)
        else:
            self._log(f'[{addr}] Unhandled RPC: {method_name} '
                      f'(payload={len(rpc_payload)}b)')

    # ------------------------------------------------------------------
    # Client handler with ARC4 auto-detection
    # ------------------------------------------------------------------
    def handle_client(self, client_sock, addr):
        """Handle TCP client connection. Returns True if connection closed."""
        try:
            data = client_sock.recv(65536)
            if not data:
                self._log(f'{addr[0]}:{addr[1]} disconnected')
                self._conn.pop((addr[0], addr[1]), None)
                self._addr_port.pop((addr[0], addr[1]), None)
                return True
        except BlockingIOError:
            return False
        except ConnectionResetError:
            self._log(f'{addr[0]}:{addr[1]} connection reset')
            self._conn.pop((addr[0], addr[1]), None)
            self._addr_port.pop((addr[0], addr[1]), None)
            return True

        self._log(hexdump(data, f'[{addr[0]}:{addr[1]}] RAW RX ({len(data)}b):'))

        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        orig_data = data

        # Pre-decrypt: when encryption is confirmed active and _arc4_pending is cleared,
        # try ARC4 decrypt first. If it produces garbage, revert and try plaintext.
        if conn.get('encrypted') and conn.get('arc4_dec') and not conn.get('_arc4_pending'):
            saved_state = conn['arc4_dec'].save_state()
            data = conn['arc4_dec'].crypt(data)
            # Sanity check: if decoded frame header looks bad, revert
            test_buf = self._client_buf.get(key, b'') + data
            if len(test_buf) >= 4:
                raw_len = struct.unpack_from('<I', test_buf, 0)[0]
                if raw_len > 10_000_000 or raw_len == 0:
                    self._log(f'[ARC4] pre-decrypt produced bad frame (len=0x{raw_len:08X}), reverting')
                    conn['arc4_dec'].restore_state(saved_state)
                    data = orig_data
            self._log(hexdump(data, f'[{addr[0]}:{addr[1]}] DECRYPTED:'))

        buf = self._client_buf.get(key, b'') + data
        orig_buf = self._client_buf.get(key, b'') + orig_data

        while len(buf) >= 6:
            parsed = parse_frame(buf)
            if parsed is None:
                # Try ARC4 auto-detection for first encrypted message
                if conn.get('_arc4_pending') and conn.get('arc4_dec'):
                    self._log(f'[{addr[0]}:{addr[1]}] Plaintext parse failed, trying ARC4...')
                    decrypted_buf = conn['arc4_dec'].crypt(buf)
                    decrypted_parsed = parse_frame(decrypted_buf)
                    if decrypted_parsed is not None:
                        cmd, payload, remaining = decrypted_parsed
                        self._log(f'[{addr[0]}:{addr[1]}] ARC4 auto-detected! Encryption active.')
                        self._log(hexdump(decrypted_buf, 'DECRYPTED (auto):'))
                        conn['_arc4_pending'] = False
                        self._client_buf[key] = remaining
                        self._handle_cmd(cmd, payload, client_sock, addr)
                        return False

                    # ARC4 decrypt failed too — try brute-force keystream positions
                    arc4_key = conn.get('arc4_key')
                    if arc4_key:
                        self._log(f'[{addr[0]}:{addr[1]}] Brute-forcing ARC4 keystream position...')
                        for try_pos in range(0, min(500, len(orig_buf) + 200)):
                            test_cipher = ARC4Cipher(arc4_key)
                            if try_pos > 0:
                                test_cipher.crypt(b'\x00' * try_pos)
                            test_dec = test_cipher.crypt(orig_buf)
                            test_parsed = parse_frame(test_dec)
                            if test_parsed is not None:
                                cmd, payload, remaining = test_parsed
                                if 0 <= cmd < 20:
                                    self._log(f'[ARC4] FOUND at keystream offset={try_pos}: '
                                              f'cmd={cmd} payload={len(payload)}b')
                                    self._log(hexdump(test_dec[:min(80, len(test_dec))],
                                              f'Decrypted at pos={try_pos}:'))
                                    # Sync decryption to found position
                                    conn['arc4_dec'] = ARC4Cipher(arc4_key)
                                    if try_pos > 0:
                                        conn['arc4_dec'].crypt(b'\x00' * try_pos)
                                    conn['_arc4_pending'] = False
                                    conn['encrypted'] = True
                                    self._client_buf[key] = remaining
                                    self._handle_cmd(cmd, payload, client_sock, addr)
                                    return False
                        self._log(f'[ARC4] No valid frame at any keystream offset 0-499')
                break

            cmd, payload, buf = parsed
            if conn.get('_arc4_pending'):
                self._log(f'[{addr[0]}:{addr[1]}] Client sent PLAINTEXT cmd={cmd} — ARC4 not active yet')
                conn['_arc4_pending'] = False
            self._handle_cmd(cmd, payload, client_sock, addr)

        self._client_buf[key] = buf
        return False

    # ------------------------------------------------------------------
    # Event loop
    # ------------------------------------------------------------------
    def run(self):
        self.start()
        self._log('Gate Server running. Press Ctrl+C to stop.')

        clients = {}
        sock_to_port = {sock: port for sock, port in zip(self.sockets, self.ports)}

        try:
            while self._running:
                all_socks = self.sockets + self._udp_sockets + list(clients.keys())
                readable, _, _ = select.select(all_socks, [], [], 1.0)

                for sock in readable:
                    if sock in self._udp_sockets:
                        # Absorb KCP/UDP packets to prevent ICMP port-unreachable
                        try:
                            sock.recvfrom(65536)
                        except Exception:
                            pass
                    elif sock in self.sockets:
                        try:
                            client_sock, addr = sock.accept()
                            client_sock.setblocking(False)
                            clients[client_sock] = addr
                            port = sock_to_port.get(sock, '?')
                            self._addr_port[(addr[0], addr[1])] = port
                            self._log(f'New connection from {addr[0]}:{addr[1]} on port {port}')
                        except BlockingIOError:
                            pass
                    else:
                        addr = clients.get(sock)
                        if addr:
                            closed = self.handle_client(sock, addr)
                            if closed:
                                try:
                                    sock.close()
                                except Exception:
                                    pass
                                del clients[sock]
                                self._client_buf.pop((addr[0], addr[1]), None)
                                self._addr_port.pop((addr[0], addr[1]), None)

        except KeyboardInterrupt:
            self._log('Shutting down...')
        finally:
            for sock in clients:
                try:
                    sock.close()
                except Exception:
                    pass
            self.stop()


if __name__ == '__main__':
    ports = [int(a) for a in sys.argv[1:]] if len(sys.argv) > 1 else [9090]
    server = MockGateServer(ports=ports)
    server.run()
