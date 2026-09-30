def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _gen_sbox():
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if gmul(i, j) == 1:
                inv[i] = j
                break
    return [
        (x ^ _rotl8(x, 1) ^ _rotl8(x, 2) ^ _rotl8(x, 3) ^ _rotl8(x, 4) ^ 0x63) & 0xFF
        for x in inv
    ]


SBOX = _gen_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0] * 15
RCON[1] = 1
for _i in range(2, 15):
    RCON[_i] = gmul(RCON[_i - 1], 2)

_ROUNDS = {16: (4, 10), 24: (6, 12), 32: (8, 14)}


def expand_key(key):
    nk, nr = _ROUNDS[len(key)]
    total = 4 * (nr + 1)
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, total):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r + 4 * c] ^= w[4 * rnd + c][r]


def _sub(s):
    return [SBOX[b] for b in s]


def _inv_sub(s):
    return [INV_SBOX[b] for b in s]


def _shift_rows(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return o


def _inv_shift_rows(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return o


def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4 * c + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        o[4 * c + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        o[4 * c + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return o


def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
        o[4 * c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
        o[4 * c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
        o[4 * c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
    return o


def _encrypt_block(block, w, nr):
    s = list(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, nr):
        s = _sub(s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        _add_round_key(s, w, rnd)
    s = _sub(s)
    s = _shift_rows(s)
    _add_round_key(s, w, nr)
    return bytes(s)


def _decrypt_block(block, w, nr):
    s = list(block)
    _add_round_key(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        s = _inv_shift_rows(s)
        s = _inv_sub(s)
        _add_round_key(s, w, rnd)
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = _inv_sub(s)
    _add_round_key(s, w, 0)
    return bytes(s)


def cbc_decrypt(data, key, iv):
    w, nr = expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data) - 15, 16):
        blk = data[i:i + 16]
        d = _decrypt_block(blk, w, nr)
        out += bytes(x ^ y for x, y in zip(d, prev))
        prev = blk
    return bytes(out)


def cbc_encrypt(data, key, iv):
    w, nr = expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(x ^ y for x, y in zip(data[i:i + 16], prev))
        e = _encrypt_block(blk, w, nr)
        out += e
        prev = e
    return bytes(out)


def ecb_decrypt(data, key):
    w, nr = expand_key(key)
    out = bytearray()
    for i in range(0, len(data) - 15, 16):
        out += _decrypt_block(data[i:i + 16], w, nr)
    return bytes(out)


def ecb_encrypt(data, key):
    w, nr = expand_key(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += _encrypt_block(data[i:i + 16], w, nr)
    return bytes(out)


def pkcs7_pad(data, bs=16):
    n = bs - (len(data) % bs)
    return data + bytes([n]) * n


def pkcs7_unpad(data, bs=16):
    if not data or len(data) % bs:
        return None
    n = data[-1]
    if n == 0 or n > bs or data[-n:] != bytes([n]) * n:
        return None
    return data[:-n]
