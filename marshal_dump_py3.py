"""Python 3 compatible NeoX marshal serializer.

Provides dumps() that produces the same binary format as NeoX's marshal.dumps.
Uses resolve_stringrefs.load_marshal() for loading (already Python 3 compatible).
"""

import struct


TYPE_NULL = ord('0')
TYPE_NONE = ord('N')
TYPE_FALSE = ord('F')
TYPE_TRUE = ord('T')
TYPE_STOPITER = ord('S')
TYPE_ELLIPSIS = ord('.')
TYPE_INT = ord('i')
TYPE_INT64 = ord('I')
TYPE_FLOAT = ord('f')
TYPE_COMPLEX = ord('x')
TYPE_BINARY_FLOAT = ord('g')
TYPE_BINARY_COMPLEX = ord('y')
TYPE_LONG = ord('l')
TYPE_STRING = ord('s')
TYPE_INTERNED = ord('t')
TYPE_STRINGREF = ord('R')
TYPE_TUPLE = ord('(')
TYPE_LIST = ord('[')
TYPE_DICT = ord('{')
TYPE_CODE = ord('c')
TYPE_UNICODE = ord('u')
TYPE_SET = ord('<')
TYPE_FROZENSET = ord('>')

HAVE_ARGUMENT = 90


def w_long(x):
    """Pack a 32-bit signed integer as 4 bytes LE."""
    if x < 0:
        x += 0x100000000
    return struct.pack('<I', x & 0xFFFFFFFF)


def w_short(x):
    """Pack a 16-bit signed integer as 2 bytes LE."""
    x = x & 0xFFFF
    if x >= 0x8000:
        x -= 0x10000
    return struct.pack('<h', x)


# Global interning state -- reset per dump_marshal() call
_intern_map = {}   # bytes -> index
_intern_list = []  # [bytes, ...]


def dump_marshal(obj):
    """Serialize a Python object tree to NeoX marshal format.

    Returns bytes.
    """
    global _intern_map, _intern_list
    _intern_map = {}
    _intern_list = []
    parts = [_dump(obj)]
    return b''.join(parts)


def _dump_bytes(b):
    """Serialize bytes with interning: TYPE_INTERNED on first use, TYPE_STRINGREF on repeat."""
    global _intern_map, _intern_list
    if b in _intern_map:
        idx = _intern_map[b]
        return bytes([TYPE_STRINGREF]) + w_long(idx)
    idx = len(_intern_list)
    _intern_map[b] = idx
    _intern_list.append(b)
    return bytes([TYPE_INTERNED]) + w_long(len(b)) + b


def _dump(obj):
    """Internal recursive dump. Returns bytes."""
    if obj is None:
        return bytes([TYPE_NONE])
    elif obj is True:
        return bytes([TYPE_TRUE])
    elif obj is False:
        return bytes([TYPE_FALSE])
    elif obj == ('NULL',):  # Special sentinel from load_marshal
        return bytes([TYPE_NULL])
    elif isinstance(obj, bool):
        return bytes([TYPE_TRUE] if obj else [TYPE_FALSE])
    elif isinstance(obj, int):
        if obj < -2147483648 or obj > 2147483647:
            lo = obj & 0xFFFFFFFF
            hi = (obj >> 32) & 0xFFFFFFFF
            return bytes([TYPE_INT64]) + w_long(lo) + w_long(hi)
        return bytes([TYPE_INT]) + w_long(obj)
    elif isinstance(obj, float):
        return bytes([TYPE_BINARY_FLOAT]) + struct.pack('<d', obj)
    elif isinstance(obj, complex):
        return bytes([TYPE_BINARY_COMPLEX]) + struct.pack('<dd', obj.real, obj.imag)
    elif isinstance(obj, bytes):
        return _dump_bytes(obj)
    elif isinstance(obj, str):
        try:
            ascii_bytes = obj.encode('ascii')
            return _dump_bytes(ascii_bytes)
        except UnicodeEncodeError:
            encoded = obj.encode('utf-8')
            return bytes([TYPE_UNICODE]) + w_long(len(encoded)) + encoded
    elif isinstance(obj, tuple):
        body = b''
        for item in obj:
            body += _dump(item)
        return bytes([TYPE_TUPLE]) + w_long(len(obj)) + body
    elif isinstance(obj, list):
        body = b''
        for item in obj:
            body += _dump(item)
        return bytes([TYPE_LIST]) + w_long(len(obj)) + body
    elif isinstance(obj, frozenset):
        items = list(obj)
        body = b''
        for item in items:
            body += _dump(item)
        return bytes([TYPE_FROZENSET]) + w_long(len(items)) + body
    elif isinstance(obj, set):
        items = list(obj)
        body = b''
        for item in items:
            body += _dump(item)
        return bytes([TYPE_SET]) + w_long(len(items)) + body
    elif isinstance(obj, dict):
        if obj.get('type') == 'code':
            return _dump_code(obj)
        body = b''
        for key, value in obj.items():
            body += _dump(key)
            body += _dump(value)
        body += bytes([TYPE_NULL])
        return bytes([TYPE_DICT]) + body
    else:
        raise ValueError(f'Cannot marshal type: {type(obj)}: {repr(obj)[:100]}')


def _dump_code(obj):
    """Serialize a code object dict back to marshal format."""
    parts = [bytes([TYPE_CODE])]
    parts.append(w_long(obj.get('argcount', 0)))
    parts.append(w_long(obj.get('nlocals', 0)))
    parts.append(w_long(obj.get('stacksize', 0)))
    parts.append(w_long(obj.get('flags', 0)))
    parts.append(_dump(obj.get('bytecode', b'')))
    parts.append(_dump(obj.get('consts', ())))
    parts.append(_dump(obj.get('names', ())))
    parts.append(_dump(obj.get('varnames', ())))
    parts.append(_dump(obj.get('freevars', ())))
    parts.append(_dump(obj.get('cellvars', ())))
    parts.append(_dump(obj.get('filename', '')))
    parts.append(_dump(obj.get('name', '')))
    parts.append(w_long(obj.get('firstlineno', 0)))
    parts.append(_dump(obj.get('lnotab', b'')))
    return b''.join(parts)


if __name__ == '__main__':
    # Quick round-trip test
    from resolve_stringrefs import load_marshal

    test_path = r'E:\appfix\npk_hsqsl_decrypted\93B94535.marshal'
    with open(test_path, 'rb') as f:
        original = f.read()

    obj, _, _ = load_marshal(original, 0)

    # Dump back
    dumped = dump_marshal(obj)

    # Compare
    if dumped == original:
        print(f'OK: Round-trip match ({len(original)} bytes)')
    else:
        print(f'DIFF: original={len(original)} dumped={len(dumped)}')
        # Show first difference
        for i in range(min(len(original), len(dumped))):
            if original[i] != dumped[i]:
                print(f'  First diff at offset {i}: orig={original[i]:02X} '
                      f'dumped={dumped[i]:02X}')
                print(f'  Context orig: {original[max(0,i-5):i+10].hex()}')
                print(f'  Context dump: {dumped[max(0,i-5):i+10].hex()}')
                break
        else:
            print(f'  Length differs: orig longer by {len(original)-len(dumped)} bytes')
