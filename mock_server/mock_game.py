"""Mock Game Server for HSQSL — handshake + entity lifecycle + RPC dispatch.

After the Gate handshake completes, the client's bind_client_to_game() parses
the routes field from connect_reply, opens TCP #2 to this server, and performs
a SECOND handshake (seed→session_key→connect_server).

After the second handshake, this server drives the entity lifecycle:
  1. create_entity Account (cmd=3) — spawn the player's Account entity
  2. become_player (cmd=5) — trigger Account.on_become_player()
  3. RPC: quick_login → login_result + on_hotfix_when_login + on_get_all_avatars
  4. RPC: select_avatar → create_entity Avatar → become_player → on_enter_world

Protocol: MobileRPC frames over TCP
  [4 bytes LE: total_length] [2 bytes LE: cmd_index] [protobuf payload]

NOTE: cmd=3/cmd=5 are the game-connection command indices for entity ops.
GateClientMsg wrapping (cmd=2) is for the GATE connection only — game
connection uses a different IGameService dispatch table.
"""

import socket
import struct
import sys
import os
import select
import threading
import random
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from logger import setup_logger
from marshal_dump_py3 import dump_marshal
from proto_utils import (
    ARC4Cipher, parse_proto, hexdump,
    build_entity_info, build_entity_message,
    build_frame, parse_frame, build_void,
    encode_bson_document, build_session_seed,
    rsa_decrypt_session_key, build_connect_server_reply,
    C_IN_SEED_REQUEST, C_IN_SESSION_KEY, C_IN_CONNECT_SERVER,
    C_IN_ENTITY_MESSAGE,
    C_OUT_SEED_REPLY, C_OUT_SESSION_KEY_OK, C_OUT_CONNECT_REPLY,
    C_OUT_CREATE_ENTITY, C_OUT_ENTITY_MESSAGE,
    REPLY_CONNECTED,
    GATE_STATE, GAME_PENDING_QUEUE,
)


class MockGameServer:
    """Mock game server — handshake + entity lifecycle + RPC dispatch.

    Phase transitions:
      awaiting_handshake → handshake_done → entity_created → become_player
      → awaiting_quick_login → login_done → awaiting_avatar_select
      → avatar_created → in_world
    """

    # Config
    ENTITY_CREATE_DELAY = 0.3     # seconds after handshake before create_entity
    BECOME_PLAYER_DELAY = 0.5     # seconds after create_entity before become_player
    AUTO_AVATAR_DELAY = 1.0       # seconds after login_result before auto-creating avatar
    SESSION_TIMEOUT = 300.0       # seconds before stale session cleanup (5 min)

    def __init__(self, host='127.0.0.1', port=9091):
        self.host = host
        self.port = port
        self.sock = None
        self._running = False
        self._log = setup_logger('MockGame')
        self._client_buf = {}  # (ip, port) -> bytearray
        self._conn = {}        # (ip, port) -> connection state
        self._last_active = {} # (ip, port) -> timestamp

        # RPC dispatch: method_name -> handler
        self.RPC_DISPATCH = {
            'quick_login': self._handle_quick_login,
            'sdk_login': self._handle_quick_login,
            'send_connect_server': self._handle_send_connect_server,
            'select_avatar': self._handle_select_avatar,
            'keep_alive': self._handle_keep_alive,
            'ping': self._handle_keep_alive,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.sock.setblocking(False)
        self._running = True
        self._log(f'Listening on {self.host}:{self.port}')

    def stop(self):
        self._running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------
    def _set_phase(self, key, phase):
        if key in self._conn:
            old = self._conn[key].get('phase', '?')
            self._conn[key]['phase'] = phase
            self._conn[key]['phase_ts'] = time.time()
            self._log(f'[{key}] Phase: {old} → {phase}')

    # ------------------------------------------------------------------
    # Frame send (ARC4 encrypted on game connection)
    # ------------------------------------------------------------------
    def _send_frame(self, client_sock, addr, cmd, payload):
        try:
            key = (addr[0], addr[1])
            conn = self._conn.get(key, {})
            frame = build_frame(cmd, payload)
            if conn.get('encrypted') and conn.get('arc4_enc'):
                frame = conn['arc4_enc'].crypt(frame)
            self._log(hexdump(frame, f'[{addr[0]}:{addr[1]}] TX cmd={cmd} ({len(frame)}b):'))
            client_sock.sendall(frame)
        except Exception as e:
            self._log(f'send error to {addr}: {e}')

    # ------------------------------------------------------------------
    # Entity lifecycle (game connection — TCP#2)
    # ------------------------------------------------------------------
    def _start_entity_lifecycle(self, client_sock, addr):
        """Step 1: send create_entity Account, then become_player, then login flow.

        After gate bind_client_to_game completes, the game server drives
        entity initialization on TCP#2. This mirrors what the bytecode
        injection does on the gate connection, but on the game channel.
        """
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        entity_id = conn.get('entity_id')
        if not entity_id:
            self._log(f'[{addr}] _start_entity_lifecycle: no entity_id, aborting')
            return

        self._set_phase(key, 'game_connected')

        # Step 1: create_entity Account
        account_bson = encode_bson_document({
            'account': 'player1',
            'server_id': 10018,
            'server_name': 'LocalTest',
            'check_cards': [2403, 4501, 2201, 4601, 5601, 2501, 4202, 3504, 1205, 4404,
                            2203, 3404, 5411, 5311, 5511, 2503, 3403, 1203, 1502, 2202,
                            4401, 3202, 4411, 2405, 1202, 2301, 2402, 4101, 4, 3401,
                            1303, 3102, 5101, 5211, 5201, 5301, 2101, 4502, 2302, 3402,
                            5112, 3406, 4406, 1302, 1201, 3201, 4602, 5501, 4409, 1204,
                            3101, 5222, 2407, 5401, 3501, 1101, 3405, 3502, 2102, 2504, 4410],
            'cards_intimacy_level': {2403: 2, 4501: 3, 2201: 3, 4601: 3, 5601: 0,
                                     2501: 2, 4202: 4, 3504: 2, 1205: 1, 4404: 3,
                                     2203: 5, 3404: 4, 3403: 3, 1203: 4, 1502: 5,
                                     2202: 5, 4401: 4, 3202: 3, 4411: 3, 2405: 3,
                                     3401: 5, 4502: 3, 3402: 4, 1201: 2, 2407: 5, 4410: 2},
        })
        entity_info = build_entity_info(b'Account', entity_id, bson_info=account_bson)
        self._send_frame(client_sock, addr, C_OUT_CREATE_ENTITY, entity_info)
        self._log(f'[{addr}] -> create_entity Account id={entity_id.hex()}')

        # Step 2: become_player after delay
        timer = threading.Timer(self.BECOME_PLAYER_DELAY,
                                lambda: self._send_become_player(client_sock, addr))
        timer.daemon = True
        timer.start()

    def _send_become_player(self, client_sock, addr):
        """Step 2: send become_player to trigger Account.on_become_player()."""
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        entity_id = conn.get('entity_id')
        if not entity_id:
            return

        self._set_phase(key, 'sending_become_player')
        msg = build_entity_message(entity_id, b'become_player')
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] -> become_player for Account id={entity_id.hex()}')

    def _send_enter_world_via_game(self, client_sock, addr, avatar_eid):
        """Send on_avatar_enter_world via game connection (cmd=5).

        Uses the game connection's native entity message dispatch:
        handler_table[5] = sub_EC2AF0 → "game_callback" → Python.
        This bypasses entity_msg_guard entirely.
        """
        self._log(f'[{addr}] -> on_avatar_enter_world (game conn, cmd=5) for Avatar={avatar_eid.hex()}')
        world_params = dump_marshal((avatar_eid,))
        msg = build_entity_message(avatar_eid, b'on_avatar_enter_world', world_params)
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] *** Avatar in world via game connection! ***')

        # v17: Bytecode now handles login_result locally (patch DCE9232F_ENTITY_V15).
        # quick_login RPC is skipped (patch B9F5C696). Do NOT auto-send
        # login_result/avatars/create_entity — that would create a duplicate Avatar.
        # self._set_phase(key, 'in_world')

    def _auto_send_login_result(self, client_sock, addr):
        """Auto-send login_result + on_get_all_avatars after become_player.

        The gate-side entity already completed the login flow; the game
        connection's entity does NOT send quick_login RPC. Instead, we
        proactively push the login response so the session doesn't time out.
        """
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        entity_id = conn.get('entity_id')
        if not entity_id:
            return

        self._set_phase(key, 'auto_sending_login')
        self._log(f'[{addr}] Auto: sending login_result + avatars')

        # login_result(ret_code=0, reason='ok', conn_type=0)
        login_params = dump_marshal((0, 'ok', 0))
        msg = build_entity_message(entity_id, b'login_result', login_params)
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] <- login_result (auto)')

        # on_hotfix_when_login(hotfix_script='', hfindex=0)
        hotfix_params = dump_marshal(('', 0))
        msg2 = build_entity_message(entity_id, b'on_hotfix_when_login', hotfix_params)
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg2)
        self._log(f'[{addr}] <- on_hotfix_when_login (auto)')

        # on_get_all_avatars
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
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg3)
        self._log(f'[{addr}] <- on_get_all_avatars (auto, {len(avatar_list)} avatars)')

        self._set_phase(key, 'login_done')

        # Auto-create avatar after delay
        timer = threading.Timer(self.AUTO_AVATAR_DELAY,
                                lambda: self._auto_create_avatar(client_sock, addr))
        timer.daemon = True
        timer.start()

    def _auto_create_avatar(self, client_sock, addr):
        """After login, auto-create an Avatar entity and enter world."""
        key = (addr[0], addr[1])
        conn = self._conn.get(key, {})
        account_entity_id = conn.get('entity_id')
        if not account_entity_id:
            return

        # Generate a new entity_id for the avatar (derived from account entity)
        avatar_eid = bytearray(account_entity_id)
        if len(avatar_eid) >= 4:
            # Flip last byte to make it distinct
            avatar_eid[-1] = (avatar_eid[-1] + 1) & 0xFF
        avatar_eid = bytes(avatar_eid)
        conn['avatar_entity_id'] = avatar_eid

        self._set_phase(key, 'creating_avatar')
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
        self._send_frame(client_sock, addr, C_OUT_CREATE_ENTITY, entity_info)
        self._log(f'[{addr}] -> create_entity Avatar id={avatar_eid.hex()}')

        # become_player for Avatar after delay
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

        self._set_phase(key, 'avatar_become_player')
        msg = build_entity_message(avatar_eid, b'become_player')
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] -> become_player for Avatar id={avatar_eid.hex()}')

        # Send on_enter_world
        timer = threading.Timer(0.3,
                                lambda: self._send_enter_world(client_sock, addr, avatar_eid))
        timer.daemon = True
        timer.start()

    def _send_enter_world(self, client_sock, addr, avatar_eid):
        """Send on_avatar_enter_world to transition the client into the game world."""
        key = (addr[0], addr[1])
        self._set_phase(key, 'in_world')
        self._log(f'[{addr}] -> on_avatar_enter_world for Avatar={avatar_eid.hex()}')

        # This is sent as an entity message to the Avatar entity
        world_params = dump_marshal((avatar_eid,))
        msg = build_entity_message(avatar_eid, b'on_avatar_enter_world', world_params)
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] *** Avatar in world! Game world should load now. ***')

    # ------------------------------------------------------------------
    # RPC handlers
    # ------------------------------------------------------------------
    def _handle_send_connect_server(self, client_sock, addr, entity_id, rpc_payload, reliable, localid):
        """Handle send_connect_server RPC — handshake confirmation."""
        self._log(f'[{addr}] RPC send_connect_server from entity={entity_id.hex()}')

    def _handle_quick_login(self, client_sock, addr, entity_id, rpc_payload, reliable, localid):
        """Handle quick_login/sdk_login: send login_result + hotfix + avatars."""
        self._log(f'[{addr}] RPC quick_login from entity={entity_id.hex()}')
        key = (addr[0], addr[1])
        self._set_phase(key, 'processing_login')

        # login_result(ret_code=0, reason='ok', conn_type=0)
        login_params = dump_marshal((0, 'ok', 0))
        msg = build_entity_message(entity_id, b'login_result', login_params,
                                   reliable=reliable, localid=localid)
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg)
        self._log(f'[{addr}] <- login_result (success)')

        # on_hotfix_when_login(hotfix_script='', hfindex=0)
        hotfix_params = dump_marshal(('', 0))
        msg2 = build_entity_message(entity_id, b'on_hotfix_when_login', hotfix_params)
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg2)
        self._log(f'[{addr}] <- on_hotfix_when_login (empty)')

        # on_get_all_avatars — list of avatar dicts
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
        self._send_frame(client_sock, addr, C_OUT_ENTITY_MESSAGE, msg3)
        self._log(f'[{addr}] <- on_get_all_avatars ({len(avatar_list)} avatars)')

        self._set_phase(key, 'login_done')
        self._log(f'[{addr}] Login complete — client should show avatar selection UI')

        # Auto-create avatar after delay (skip manual selection for testing)
        timer = threading.Timer(self.AUTO_AVATAR_DELAY,
                                lambda: self._auto_create_avatar(client_sock, addr))
        timer.daemon = True
        timer.start()

    def _handle_select_avatar(self, client_sock, addr, entity_id, rpc_payload, reliable, localid):
        """Handle select_avatar RPC — user picked an avatar from the list."""
        self._log(f'[{addr}] RPC select_avatar from entity={entity_id.hex()}')
        self._auto_create_avatar(client_sock, addr)

    def _handle_keep_alive(self, client_sock, addr, entity_id, rpc_payload, reliable, localid):
        """Handle keep_alive/ping — heartbeat response."""
        self._log(f'[{addr}] RPC keep_alive/ping from entity={entity_id.hex()} — ACK')

    # ------------------------------------------------------------------
    # Handshake (same protocol as gate)
    # ------------------------------------------------------------------
    def _send_seed_reply(self, client_sock, addr):
        seed_msg = build_session_seed(random.randint(1, 2**63 - 1))
        self._send_frame(client_sock, addr, C_OUT_SEED_REPLY, seed_msg)
        self._log(f'[{addr}] <- seed_reply')

    def _send_session_key_ok(self, client_sock, addr):
        self._send_frame(client_sock, addr, C_OUT_SESSION_KEY_OK, build_void())
        self._log(f'[{addr}] <- session_key_ok')

    def _handle_session_key(self, client_sock, addr, payload):
        key = (addr[0], addr[1])
        conn = self._conn.setdefault(key, {})

        if payload:
            parsed = parse_proto(payload)
            ciphertext = parsed.get(1, b'')
            if ciphertext:
                plaintext, arc4_key = rsa_decrypt_session_key(ciphertext)
                if plaintext:
                    self._log(f'[{addr}] RSA decrypt OK, ARC4 key: {arc4_key.hex()[:16]}...')
                    conn['arc4_enc'] = ARC4Cipher(arc4_key)
                    conn['arc4_dec'] = ARC4Cipher(arc4_key)
                    conn['arc4_key'] = arc4_key
                    conn['encrypted'] = True
                else:
                    self._log(f'[{addr}] RSA decrypt FAILED')
        self._send_session_key_ok(client_sock, addr)

    def _handle_connect_server(self, client_sock, addr, payload):
        """Handle connect_server on game connection (BIND_SOUL type).

        IDA-verified: This is a SECOND handshake on TCP #2, triggered by
        bind_client_to_game() after receiving routes in the gate connect_reply.
        """
        key = (addr[0], addr[1])
        conn = self._conn.setdefault(key, {})

        parsed = {}
        if payload:
            parsed = parse_proto(payload)
        request_type = parsed.get(2, 0)
        client_entity_id = parsed.get(3, b'')
        extra_msg = parsed.get(4, b'')
        type_names = {0: 'NEW_CONNECTION', 1: 'RE_CONNECTION', 2: 'BIND_AVATAR', 3: 'BIND_SOUL'}

        # Convert entity_id: 24-byte hex → 12 raw bytes
        entity_id = None
        if len(client_entity_id) == 24:
            try:
                entity_id = bytes.fromhex(client_entity_id.decode('ascii'))
            except (ValueError, UnicodeDecodeError):
                pass
        if not entity_id and len(client_entity_id) == 12:
            entity_id = client_entity_id
        if not entity_id:
            # Fallback: use entity_id from Gate's pending queue
            for eid, ak, ae, ad in GAME_PENDING_QUEUE:
                entity_id = eid
                break
        if not entity_id:
            entity_id = conn.get('entity_id') or client_entity_id or b'\x00' * 12

        self._log(f'[{addr}] connect_server: type={type_names.get(request_type, request_type)} '
                  f'entity={entity_id.hex()} extra={len(extra_msg)}b')
        conn['entity_id'] = entity_id
        conn['handshake_done'] = True
        self._set_phase(key, 'handshake_done')

        # Reply with connect_reply (no routes — we ARE the game server)
        reply = build_connect_server_reply(
            con_type=REPLY_CONNECTED,
            entityid=entity_id,
        )
        self._send_frame(client_sock, addr, C_OUT_CONNECT_REPLY, reply)
        self._log(f'[{addr}] <- connect_reply CONNECTED, entity={entity_id.hex()}')

        # v12→v17: Entity creation is hardcoded in bytecode (DCE9232F_ENTITY_V15).
        # Bytecode creates Account+Avatar, calls on_become_player, triggers preload.
        #
        # We send on_avatar_enter_world via the GAME connection (cmd=5) because:
        # - Game connection's rpc_service natively supports entity messages (cmd=5)
        # - handler_table[5] = sub_EC2AF0 (original, no patch needed)
        # - sub_EC2AF0 bypasses entity_msg_guard, calls Python "game_callback" directly
        # - Gate connection's cmd=5 dispatch fails (no EntityMessage parser)
        #
        # Avatar entity_id = game_entity_id - 1 (bytecode calls _renew_device_id
        # once before creating Avatar, so Avatar gets ID N-1 relative to game conn).
        avatar_eid = bytearray(entity_id)
        avatar_eid[-1] = (avatar_eid[-1] - 1) & 0xFF
        avatar_eid = bytes(avatar_eid)
        enter_world_delay = 3.0  # seconds for bytecode entity creation + preload
        self._log(f'[{addr}] v17: scheduling on_avatar_enter_world (cmd=5) for '
                  f'Avatar={avatar_eid.hex()} in {enter_world_delay}s')
        timer = threading.Timer(enter_world_delay,
                                lambda: self._send_enter_world_via_game(
                                    client_sock, addr, avatar_eid))
        timer.daemon = True
        timer.start()

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------
    def _handle_cmd(self, cmd, payload, client_sock, addr):
        if cmd == C_IN_SEED_REQUEST:
            self._log(f'[{addr}] -> seed_request')
            self._send_seed_reply(client_sock, addr)

        elif cmd == C_IN_SESSION_KEY:
            self._log(f'[{addr}] -> session_key ({len(payload)}b)')
            self._handle_session_key(client_sock, addr, payload)

        elif cmd == C_IN_CONNECT_SERVER:
            self._log(f'[{addr}] -> connect_server ({len(payload)}b)')
            self._handle_connect_server(client_sock, addr, payload)

        elif cmd == C_IN_ENTITY_MESSAGE and len(payload) >= 2:
            self._handle_entity_message(client_sock, addr, payload)

        else:
            self._log(f'[{addr}] Unknown cmd={cmd} payload={len(payload)}b')

    def _handle_entity_message(self, client_sock, addr, payload):
        """Parse entity message and dispatch to RPC handler.

        EntityMessage protobuf fields (IDA-verified):
          1=routes, 2=entity_id, 3=method(Md5OrIndex), 4=parameters,
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
    # Connection setup
    # ------------------------------------------------------------------
    def on_new_connection(self, client_sock, addr):
        """Client opened TCP #2 — set up initial state and link Gate session."""
        key = (addr[0], addr[1])
        self._conn[key] = {'phase': 'awaiting_handshake', 'phase_ts': time.time()}
        self._last_active[key] = time.time()

        # Try to pop ARC4 state from Gate's pending queue
        if GAME_PENDING_QUEUE:
            entity_id, arc4_key, arc4_enc, arc4_dec = GAME_PENDING_QUEUE.popleft()
            self._conn[key].update({
                'entity_id': entity_id,
                'arc4_key': arc4_key,
                'arc4_enc': arc4_enc,
                'arc4_dec': arc4_dec,
            })
            self._log(f'[{addr}] Session linked from Gate: entity={entity_id.hex()} '
                      f'key={arc4_key.hex()[:16]}...')
        else:
            self._log(f'[{addr}] No pending session from Gate — will use new handshake')

    # ------------------------------------------------------------------
    # Client handler
    # ------------------------------------------------------------------
    def handle_client(self, client_sock, addr):
        try:
            data = client_sock.recv(65536)
            if not data:
                self._log(f'{addr[0]}:{addr[1]} disconnected')
                self._conn.pop((addr[0], addr[1]), None)
                self._last_active.pop((addr[0], addr[1]), None)
                return True
        except BlockingIOError:
            return False
        except ConnectionResetError:
            self._log(f'{addr[0]}:{addr[1]} connection reset')
            self._conn.pop((addr[0], addr[1]), None)
            self._last_active.pop((addr[0], addr[1]), None)
            return True

        key = (addr[0], addr[1])
        self._last_active[key] = time.time()
        conn = self._conn.get(key, {})

        if conn.get('encrypted') and conn.get('arc4_dec'):
            self._log(hexdump(data, f'[{addr}] RAW RX ({len(data)}b):'))
            data = conn['arc4_dec'].crypt(data)
            self._log(hexdump(data, f'[{addr}] DECRYPTED:'))

        buf = self._client_buf.get(key, b'') + data

        while len(buf) >= 6:
            parsed = parse_frame(buf)
            if parsed is None:
                # Auto-detect ARC4 activation
                if not conn.get('encrypted') and conn.get('arc4_dec') and len(buf) >= 6:
                    decrypted_buf = conn['arc4_dec'].crypt(buf)
                    decrypted_parsed = parse_frame(decrypted_buf)
                    if decrypted_parsed is not None:
                        self._log(f'[{addr}] ARC4 auto-detected, enabling encryption')
                        conn['encrypted'] = True
                        cmd, payload, buf = decrypted_parsed
                        self._handle_cmd(cmd, payload, client_sock, addr)
                        continue
                break

            cmd, payload, buf = parsed
            self._handle_cmd(cmd, payload, client_sock, addr)

        self._client_buf[key] = buf
        return False

    # ------------------------------------------------------------------
    # Event loop
    # ------------------------------------------------------------------
    def run(self):
        self.start()
        self._log('Game Server running. Press Ctrl+C to stop.')

        clients = {}
        last_cleanup = time.time()

        try:
            while self._running:
                readable, _, _ = select.select(
                    [self.sock] + list(clients.keys()), [], [], 1.0)

                # Periodic stale session cleanup
                now = time.time()
                if now - last_cleanup > 10.0:
                    last_cleanup = now
                    stale = []
                    for sock, addr in clients.items():
                        key = (addr[0], addr[1])
                        ts = self._last_active.get(key, 0)
                        if now - ts > self.SESSION_TIMEOUT:
                            stale.append(sock)
                    for sock in stale:
                        addr = clients[sock]
                        self._log(f'[{addr[0]}:{addr[1]}] Session timeout, cleaning up')
                        try:
                            sock.close()
                        except Exception:
                            pass
                        del clients[sock]
                        self._client_buf.pop((addr[0], addr[1]), None)
                        self._conn.pop((addr[0], addr[1]), None)
                        self._last_active.pop((addr[0], addr[1]), None)

                for sock in readable:
                    if sock is self.sock:
                        try:
                            client_sock, addr = sock.accept()
                            client_sock.setblocking(False)
                            clients[client_sock] = addr
                            self._log(f'New connection from {addr[0]}:{addr[1]}')
                            self.on_new_connection(client_sock, addr)
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
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9091
    server = MockGameServer(port=port)
    server.run()
