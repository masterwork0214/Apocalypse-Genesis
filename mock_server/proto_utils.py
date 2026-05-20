"""Shared utilities for HSQSL mock servers.

Extracted from mock_gate.py — protobuf encoding/decoding, ARC4 cipher,
frame building/parsing, BSON encoding, entity message builders,
routes construction (ClientBindMsg/ServerInfo), RSA decryption.
"""

import struct
import hashlib
import os
import collections

from logger import setup_logger

# ---------------------------------------------------------------------------
# RSA decryption
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

_RSA_PRIVATE_KEY = None


def load_rsa_private_key():
    global _RSA_PRIVATE_KEY
    if not _HAS_CRYPTOGRAPHY:
        return None
    key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            _RSA_PRIVATE_KEY = load_pem_private_key(f.read(), password=None, backend=default_backend())
        return _RSA_PRIVATE_KEY
    return None


def rsa_decrypt_session_key(encrypted_data):
    """Decrypt the SessionKey protobuf from RSA ciphertext.

    Returns: (session_key_bytes, sha1_digest) or (None, None) on failure.
    """
    global _RSA_PRIVATE_KEY
    if _RSA_PRIVATE_KEY is None:
        _RSA_PRIVATE_KEY = load_rsa_private_key()
    if _RSA_PRIVATE_KEY is None:
        return None, None

    # Try OAEP first (matching client's PKCS1_OAEP.new(key))
    log = setup_logger('RSA')
    try:
        decrypted = _RSA_PRIVATE_KEY.decrypt(
            encrypted_data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None)
        )
        log(f'RSA OAEP decrypt OK: {len(decrypted)} bytes')
    except Exception as e_oaep:
        try:
            decrypted = _RSA_PRIVATE_KEY.decrypt(
                encrypted_data,
                padding.PKCS1v15()
            )
            log(f'RSA PKCS1v15 decrypt OK: {len(decrypted)} bytes')
        except Exception as e_pkcs:
            try:
                nums = _RSA_PRIVATE_KEY.private_numbers()
                c = int.from_bytes(encrypted_data, 'big')
                m = pow(c, nums.d, nums.public_numbers.n)
                raw = m.to_bytes(256, 'big')
                log(f'RSA raw decrypt first 32B: {raw[:32].hex()}')
            except Exception:
                pass
            log(f'RSA decrypt FAILED (OAEP={e_oaep})')
            return None, None

    parsed = parse_proto(decrypted)
    session_key = parsed.get(2, None)
    log(f'decrypted proto fields: {sorted(parsed.keys())}')
    if session_key is None or not isinstance(session_key, bytes) or len(session_key) == 0:
        log(f'session_key field 2 missing in decrypted {len(decrypted)}B')
        return None, None

    return session_key, session_key  # (plaintext, sha1_digest)


# ---------------------------------------------------------------------------
# ARC4 stream cipher
# ---------------------------------------------------------------------------
class ARC4Cipher:
    """Pure-Python ARC4 (RC4) stream cipher.

    Used by NeoX engine to encrypt the TCP stream after session key exchange.
    Key is SHA1(32 random bytes) = 20 bytes.
    """

    def __init__(self, key: bytes):
        assert 1 <= len(key) <= 256, f'ARC4 key must be 1-256 bytes, got {len(key)}'
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def state_info(self) -> str:
        """Return compact ARC4 state for debugging."""
        return (f'i={self.i} j={self.j} '
                f'S[0..7]={[self.S[k] for k in range(8)]} '
                f'S[i]={self.S[self.i]} S[j]={self.S[self.j]}')

    def save_state(self):
        """Return (i, j, S_copy) tuple for later restore."""
        return (self.i, self.j, self.S[:])

    def restore_state(self, state):
        """Restore ARC4 state from save_state() tuple."""
        self.i, self.j = state[0], state[1]
        self.S = state[2][:]

    def crypt(self, data: bytes) -> bytes:
        """Encrypt or decrypt (ARC4 is symmetric)."""
        S = self.S
        i = self.i
        j = self.j
        result = bytearray(len(data))
        for pos, byte in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            result[pos] = byte ^ S[(S[i] + S[j]) & 0xFF]
        self.i = i
        self.j = j
        return bytes(result)


# ---------------------------------------------------------------------------
# Protobuf primitives
# ---------------------------------------------------------------------------
WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_32BIT = 5


def encode_varint(value):
    result = []
    while value > 127:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(bytearray(result))


def encode_tag(field_number, wire_type):
    return encode_varint((field_number << 3) | wire_type)


def encode_int64(field_number, value):
    if value < 0:
        value = value & 0xFFFFFFFFFFFFFFFF
    return encode_tag(field_number, WIRE_VARINT) + encode_varint(value)


def encode_int32(field_number, value):
    if value < 0:
        value = value & 0xFFFFFFFFFFFFFFFF
    return encode_tag(field_number, WIRE_VARINT) + encode_varint(value)


def encode_bytes(field_number, data):
    return encode_tag(field_number, WIRE_LENGTH_DELIMITED) + encode_varint(len(data)) + data


def encode_message(field_number, msg):
    return encode_tag(field_number, WIRE_LENGTH_DELIMITED) + encode_varint(len(msg)) + msg


def encode_enum(field_number, value):
    return encode_tag(field_number, WIRE_VARINT) + encode_varint(value)


def decode_varint(data, offset):
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return value, offset


def decode_tag(data, offset):
    varint, offset = decode_varint(data, offset)
    field_number = varint >> 3
    wire_type = varint & 0x07
    return field_number, wire_type, offset


def parse_proto(data):
    """Generic protobuf decoder. Returns {field_number: value} dict."""
    result = {}
    offset = 0
    while offset < len(data):
        field, wire, offset = decode_tag(data, offset)
        if wire == WIRE_VARINT:
            value, offset = decode_varint(data, offset)
            result[field] = value
        elif wire == WIRE_LENGTH_DELIMITED:
            length, offset = decode_varint(data, offset)
            value = data[offset:offset + length]
            offset += length
            result[field] = value
        elif wire == WIRE_32BIT:
            value = data[offset:offset + 4]
            offset += 4
            result[field] = value
        elif wire == WIRE_64BIT:
            value = data[offset:offset + 8]
            offset += 8
            result[field] = value
    return result


def build_void():
    return b''


def build_session_seed(seed_value):
    """SessionSeed: field 1 = seed (int64)."""
    return b'\x08' + encode_varint(seed_value & 0xFFFFFFFFFFFFFFFF)


# ---------------------------------------------------------------------------
# BSON encoder
# ---------------------------------------------------------------------------
def encode_bson_document(d):
    """BSON encoder for dicts with int, str, bytes, list, dict, bool values."""
    elements = b''
    for key, value in d.items():
        key_bytes = key.encode('utf-8') if isinstance(key, str) else str(key).encode('utf-8')
        if isinstance(value, bool):
            elements += b'\x10' + key_bytes + b'\x00'
            elements += struct.pack('<i', 1 if value else 0)
        elif isinstance(value, int):
            elements += b'\x10' + key_bytes + b'\x00'
            elements += struct.pack('<i', value)
        elif isinstance(value, str):
            val_bytes = value.encode('utf-8')
            elements += b'\x02' + key_bytes + b'\x00'
            elements += struct.pack('<i', len(val_bytes) + 1)
            elements += val_bytes + b'\x00'
        elif isinstance(value, bytes):
            elements += b'\x05' + key_bytes + b'\x00'
            elements += struct.pack('<i', len(value))
            elements += b'\x00'  # subtype 0 (generic binary)
            elements += value
        elif isinstance(value, list):
            # BSON array: embedded document with string integer keys
            array_doc = {str(i): v for i, v in enumerate(value)}
            array_bytes = encode_bson_document(array_doc)
            elements += b'\x04' + key_bytes + b'\x00'
            elements += array_bytes
        elif isinstance(value, dict):
            # BSON embedded document
            sub_doc = encode_bson_document(value)
            elements += b'\x03' + key_bytes + b'\x00'
            elements += sub_doc
    total_len = 4 + len(elements) + 1
    return struct.pack('<i', total_len) + elements + b'\x00'


def encode_bson_array(items):
    """Minimal BSON array encoder (as document with integer keys)."""
    d = {str(i): v for i, v in enumerate(items)}
    return encode_bson_document(d)


# ---------------------------------------------------------------------------
# RPC index computation
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Md5OrIndex / Entity builders
# ---------------------------------------------------------------------------
def build_md5orindex(name):
    """Build Md5OrIndex with index=-1 (Strategy B: raw md5 dispatch)."""
    if isinstance(name, str):
        name = name.encode()
    return encode_bytes(1, name) + encode_int32(2, -1)


def build_md5orindex_positive(name):
    """Build Md5OrIndex with index=0 (Strategy A: INDEX2RPC lookup)."""
    if isinstance(name, str):
        name = name.encode()
    return encode_bytes(1, name) + encode_int32(2, 0)


def build_entity_info(entity_type_bytes, entity_id, bson_info=b"", use_positive_index=False):
    """Build EntityInfo protobuf.

    Fields: 1=routes, 2=type(Md5OrIndex), 3=id, 4=info(BSON)
    """
    if isinstance(entity_type_bytes, str):
        entity_type_bytes = entity_type_bytes.encode()
    result = encode_bytes(1, b'')  # routes: empty
    if entity_type_bytes:
        type_msg = build_md5orindex_positive(entity_type_bytes) if use_positive_index else build_md5orindex(entity_type_bytes)
        result += encode_message(2, type_msg)
    if entity_id:
        result += encode_bytes(3, entity_id)
    if bson_info:
        result += encode_bytes(4, bson_info)
    return result


def build_entity_message(entity_id, method_name, parameters=b'', reliable=0, localid=0):
    """Build EntityMessage protobuf.

    Fields: 1=routes, 2=id, 3=method(Md5OrIndex), 4=parameters, 5=reliable, 6=localid
    """
    if isinstance(method_name, str):
        method_name = method_name.encode()
    method_msg = build_md5orindex(method_name)
    result = encode_bytes(1, b'')
    result += encode_bytes(2, entity_id)
    result += encode_message(3, method_msg)
    if parameters:
        result += encode_bytes(4, parameters)
    result += encode_int32(5, reliable)
    result += encode_int32(6, localid)
    return result


# ---------------------------------------------------------------------------
# Routes builders — ClientBindMsg / ServerInfo / ConnectServerReply
# ---------------------------------------------------------------------------

# GateClientMsg oneof field numbers (IDA-verified: 09_data_parsing.c line 4)
# GateClientMsg: oneof msg { seed_reply=1, session_key_ok=2, connect_reply=3, ... }
# The dispatcher sub_E99240 maps oneof case N → IGateClient vtable[N+5]
# case N = field_number - 1  (oneof starts at field 1, no offset)
GATE_MSG_SEED_REPLY       = 1   # case 0 → vtable[5]  = sub_ECB270
GATE_MSG_SESSION_KEY_OK   = 2   # case 1 → vtable[6]  = sub_ECD840
GATE_MSG_CONNECT_REPLY    = 3   # case 2 → vtable[7]  = sub_ECA810
GATE_MSG_CREATE_ENTITY    = 4   # case 3 → vtable[8]  = sub_ECA920
GATE_MSG_DESTROY_ENTITY   = 5   # case 4 → vtable[9]  = sub_ECAB80
GATE_MSG_ENTITY_MESSAGE   = 6   # case 5 → vtable[10] = sub_ECAEE0
GATE_MSG_CHAT_TO_CLIENT   = 7   # case 6 → vtable[11] = sub_ECA710
GATE_MSG_REG_MD5_INDEX    = 8   # case 7 → vtable[12] = sub_ECB160
GATE_MSG_DISPATCH_FILTER  = 9   # case 8 → vtable[13] = sub_ECAC80


def build_gate_client_msg(oneof_field, inner_msg):
    """Wrap a message in GateClientMsg oneof wrapper.

    GateClientMsg is the top-level message for ALL server→client RPCs on cmd=2.
    IDA-verified: sub_E99240 dispatches 11 oneof fields (1-11), each mapping
    to IGateClient vtable[5]-vtable[15].

    Sending entity messages through cmd=2 (not cmd=3/5) is critical:
    cmd=3 uses sub_E99AD0 factory (always returns SessionKeyOk prototype),
    which cannot parse EntityInfo or EntityMessage protobuf.
    """
    return encode_message(oneof_field, inner_msg)


def build_connect_server_reply(con_type, entityid=b"", extramsg=b"", routes=b""):
    """Build ConnectServerReply protobuf (inner message only, no wrapper).

    Fields: 1=routes(bytes), 2=con_type(enum), 3=entityid(bytes), 4=extramsg(bytes)

    To send as a MobileRPC frame, wrap with build_gate_client_msg(3, result)
    before passing to build_frame(C_OUT_CONNECT_REPLY, wrapped).
    """
    result = b''
    if routes:
        result += encode_bytes(1, routes)
    result += encode_enum(2, con_type)
    if entityid:
        result += encode_bytes(3, entityid)
    if extramsg:
        result += encode_bytes(4, extramsg)
    return result


# ---------------------------------------------------------------------------
# Frame builder / parser (MobileRPC over TCP)
# ---------------------------------------------------------------------------
def build_frame(cmd_index, payload):
    """Build MobileRPC frame: [4B LE total_length] [2B LE cmd_index] [payload]"""
    data = struct.pack('<H', cmd_index) + payload
    return struct.pack('<I', len(data)) + data


def parse_frame(data):
    """Parse one MobileRPC frame. Returns (cmd_index, payload, remaining) or None."""
    if len(data) < 6:
        return None
    total_len = struct.unpack_from('<I', data, 0)[0]
    if total_len + 4 > len(data):
        return None
    cmd_index = struct.unpack_from('<H', data, 4)[0]
    payload = data[6:4 + total_len]
    remaining = data[4 + total_len:]
    return cmd_index, payload, remaining


# ---------------------------------------------------------------------------
# Hex dump
# ---------------------------------------------------------------------------
def hexdump(data, label=''):
    """Return hex+ASCII representation of bytes."""
    if not data:
        return f'{label} (0 bytes)'
    lines = [label]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  {i:04X}  {hex_part:<48s}  {ascii_part}')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Command index constants
# ---------------------------------------------------------------------------
# Client -> Server (IGateService)
C_IN_SEED_REQUEST   = 0
C_IN_SESSION_KEY    = 1
C_IN_CONNECT_SERVER = 2
C_IN_ENTITY_MESSAGE = 3

# Server -> Client (IGateClient)
C_OUT_SEED_REPLY     = 0
C_OUT_SESSION_KEY_OK = 1
C_OUT_CONNECT_REPLY  = 2
C_OUT_CREATE_ENTITY  = 3
C_OUT_ENTITY_MESSAGE = 5

# connect_server request types
REPLY_CONNECTED = 1
REPLY_RECONNECT_SUCCEEDED = 2

REQUEST_NEW_CONNECTION = 0
REQUEST_RE_CONNECTION = 1
REQUEST_BIND_AVATAR = 2
REQUEST_BIND_SOUL = 3

# ---------------------------------------------------------------------------
# C++ wire-format builders
# ---------------------------------------------------------------------------
# Field numbers verified against NPK bytecode protobuf definitions:
#   43DC30B2.py (common_pb2): ServerInfo — 1=ip, 2=port, 3=sid, 4=banclient, 5=svrtype
#   D7A991AF.py (gate_game_pb2): ClientBindMsg — 1=clientinfo, 2=server, 3=entityid
#
# IDA decompilation (README.md) suggests C++ engine may use different field numbers:
#   ServerInfo: 1=banclient, 2=svrtype, 3=servername, 4=dport
#   ClientBindMsg: 2=entityid, 3=serverinfo
# Both formats are provided below — use_ida_fields=True selects the IDA variant.

def build_server_info_wire(servername='127.0.0.1', dport=9091, sid=0, banclient=False, svrtype=0,
                           use_ida_fields=False):
    """Build ServerInfo protobuf.

    NPK-verified fields (use_ida_fields=False):
      field 1: ip (string)
      field 2: port (int32)
      field 3: sid (int32)
      field 4: banclient (bool)
      field 5: svrtype (int32)

    IDA-inferred fields (use_ida_fields=True):
      field 1: banclient (int32)
      field 2: svrtype (int32)
      field 3: servername (string)
      field 4: dport (int32)
    """
    if use_ida_fields:
        result = b''
        result += encode_int32(1, 1 if banclient else 0)
        result += encode_int32(2, svrtype)
        if servername:
            result += encode_bytes(3, servername.encode() if isinstance(servername, str) else servername)
        result += encode_int32(4, dport)
        return result
    else:
        result = b''
        if servername:
            result += encode_bytes(1, servername.encode() if isinstance(servername, str) else servername)
        result += encode_int32(2, dport)
        if sid:
            result += encode_int32(3, sid)
        if banclient:
            result += encode_int32(4, 1 if banclient else 0)
        if svrtype:
            result += encode_int32(5, svrtype)
        return result


def build_client_info_wire(client_id=b'player1', session_id=b'\x01\x02\x03\x04',
                           gate_id=b'\x05\x06\x07\x08', ip=None, port=0, is_soul=False):
    """Build ClientInfo protobuf (NPK-verified from D7A991AF.py).

    Fields:
      1: ip (bytes, optional)
      2: port (int32, optional)
      3: clientid (bytes, REQUIRED)
      4: sessionid (bytes, REQUIRED)
      5: gateid (bytes, REQUIRED)
      6: is_soul (bool, optional)
    """
    result = b''
    if ip:
        result += encode_bytes(1, ip.encode() if isinstance(ip, str) else ip)
    if port:
        result += encode_int32(2, port)
    if client_id:
        result += encode_bytes(3, client_id if isinstance(client_id, bytes) else client_id.encode())
    if session_id:
        result += encode_bytes(4, session_id)
    if gate_id:
        result += encode_bytes(5, gate_id)
    if is_soul:
        result += encode_int32(6, 1)
    return result


def build_client_bind_msg_wire(entity_id, server_info_wire, use_ida_fields=False,
                               client_info_wire=None):
    """Build ClientBindMsg protobuf.

    NPK-verified fields (use_ida_fields=False):
      field 1: clientinfo (ClientInfo message, REQUIRED by proto definition)
      field 2: server (ServerInfo message, REQUIRED)
      field 3: entityid (bytes, 12 raw bytes)

    IDA-inferred fields (use_ida_fields=True):
      field 2: entityid (bytes)
      field 3: serverinfo (ServerInfo message)

    entity_id must be raw bytes (12 bytes), NOT a hex string.
    """
    if use_ida_fields:
        result = b''
        if entity_id:
            result += encode_bytes(2, entity_id)
        if server_info_wire:
            result += encode_message(3, server_info_wire)
        return result
    else:
        result = b''
        if client_info_wire:
            result += encode_message(1, client_info_wire)
        if server_info_wire:
            result += encode_message(2, server_info_wire)
        if entity_id:
            result += encode_bytes(3, entity_id)
        return result


# ---------------------------------------------------------------------------
# Shared state between Gate and Game servers
# ---------------------------------------------------------------------------
GATE_STATE = {}            # entity_id -> {arc4_key, arc4_enc, arc4_dec}
GAME_PENDING_QUEUE = collections.deque()  # FIFO of (entity_id, arc4_key, arc4_enc, arc4_dec)
