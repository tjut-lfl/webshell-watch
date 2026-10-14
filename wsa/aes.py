"""
纯 Python AES-128 实现（仅解密，用于对冰蝎/哥斯拉流量做验证性解包取证）。

为什么自己实现：本工具坚持零第三方依赖，避免在应急/离线环境下因缺包无法运行。
本实现只用于解密取证，不用于生产加密，性能足够（单个密钥解密一次即可确认）。

实现依据 FIPS-197。密钥扩展、逆 S 盒、逆列混合均按标准实现。
"""

from __future__ import annotations

from typing import List, Optional

# ---------------------------------------------------------------------------
# 常量表
# ---------------------------------------------------------------------------
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def _mul(a: int, b: int) -> int:
    """GF(2^8) 乘法。"""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        b >>= 1
        a = _xtime(a)
    return res & 0xFF


class AES128:
    """AES-128 解密（ECB 分组运算，CBC 由调用方按模式串联）。"""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES128 需要 16 字节密钥")
        self.round_keys = self._expand_key(key)

    # -- 密钥扩展 ---------------------------------------------------------
    @staticmethod
    def _expand_key(key: bytes) -> List[List[int]]:
        words: List[List[int]] = [list(key[i : i + 4]) for i in range(0, 16, 4)]
        for i in range(4, 44):
            temp = list(words[i - 1])
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= RCON[i // 4 - 1]
            words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
        return [sum(words[4 * r : 4 * r + 4], []) for r in range(11)]

    # -- 单分组解密 -------------------------------------------------------
    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("分组长度必须为 16 字节")
        state = [list(block[i : i + 4]) for i in range(0, 16, 4)]  # 列主序
        self._add_round_key(state, 10)
        for rnd in range(9, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, rnd)
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, 0)
        return bytes(b for col in state for b in col)

    def _add_round_key(self, state: List[List[int]], rnd: int) -> None:
        rk = self.round_keys[rnd]
        for c in range(4):
            for r in range(4):
                state[c][r] ^= rk[4 * c + r]

    @staticmethod
    def _inv_sub_bytes(state: List[List[int]]) -> None:
        for c in range(4):
            for r in range(4):
                state[c][r] = INV_SBOX[state[c][r]]

    @staticmethod
    def _inv_shift_rows(state: List[List[int]]) -> None:
        # 状态按列存储：state[col][row]
        for r in range(1, 4):
            col = [state[c][r] for c in range(4)]
            col = col[-r:] + col[:-r]
            for c in range(4):
                state[c][r] = col[c]

    @staticmethod
    def _inv_mix_columns(state: List[List[int]]) -> None:
        for c in range(4):
            a0, a1, a2, a3 = state[c]
            state[c][0] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
            state[c][1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
            state[c][2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
            state[c][3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)


def decrypt_ecb(key: bytes, data: bytes) -> bytes:
    """AES-128-ECB 解密（自动忽略尾部不足 16 字节的部分）。"""
    aes = AES128(key)
    out = bytearray()
    for i in range(0, len(data) - len(data) % 16, 16):
        out.extend(aes.decrypt_block(data[i : i + 16]))
    return bytes(out)


def decrypt_cbc(key: bytes, data: bytes, iv: Optional[bytes] = None) -> bytes:
    """AES-128-CBC 解密（默认使用 16 字节 0 作为 IV，冰蝎 2.0 用随机 IV 时由调用方给出）。"""
    aes = AES128(key)
    prev = iv or b"\x00" * 16
    out = bytearray()
    for i in range(0, len(data) - len(data) % 16, 16):
        block = aes.decrypt_block(data[i : i + 16])
        out.extend(bytes(a ^ b for a, b in zip(block, prev)))
        prev = data[i : i + 16]
    return bytes(out)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data
