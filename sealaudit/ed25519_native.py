"""纯标准库 Ed25519 数字签名（RFC 8032）。

取证签收需要“独立验证”：验证方只持有控制者公钥（源自创世信任锚），
不需要任何签名私钥或共享密钥。标准库未暴露非对称签名原语，因此这里用
``hashlib.sha512`` + 大整数运算实现一份精简 Ed25519，并在启动时用
RFC 8032 测试向量做已知答案自检；自检失败会直接抛出，绝不静默使用错误算法。

实现采用 Bernstein 等人公开的经典仿射坐标参考实现，规模很小、便于审计。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache

b = 256
q = 2**255 - 19
# 群 l：Ed25519 主子群阶
l = 2**252 + 27742317777372353535851937790883648493  # noqa: E741


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, q - 2, q)


_d = -121665 * _inv(121666)
_I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = [_Bx % q, _By % q]


def _edwards(P, Q):
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e: int):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8)
    )


def _encodepoint(P) -> bytes:
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8)
    )


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    h = _H(m)
    return sum(2**i * _bit(h, i) for i in range(2 * b))


def _publickey_from_seed(seed: bytes) -> bytes:
    h = _H(seed)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def _signature(m: bytes, seed: bytes, pk: bytes) -> bytes:
    h = _H(seed)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    r = _hint(h[b // 8 : b // 4] + m)
    R = _scalarmult(_B, r)
    S = (r + _hint(_encodepoint(R) + pk + m) * a) % l
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P) -> bool:
    x, y = P[0], P[1]
    return (-x * x + y * y - 1 - _d * x * x * y * y) % q == 0


def _decodeint(s: bytes) -> int:
    return sum(2**i * _bit(s, i) for i in range(b))


def _decodepoint(s: bytes):
    y = sum(2**i * _bit(s, i) for i in range(0, b - 1))
    x = _xrecover(y)
    if (x & 1) != _bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("解码出的点不在曲线上")
    return P


class Ed25519Error(ValueError):
    """签名/密钥格式或校验失败。"""


@dataclass(frozen=True)
class KeyPair:
    """一个控制者的签名密钥对。seed 必须保密，public 可公开。"""

    seed: bytes
    public: bytes

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "KeyPair":
        seed = bytes.fromhex(seed_hex)
        if len(seed) != 32:
            raise Ed25519Error("Ed25519 seed 必须为 32 字节")
        return cls(seed=seed, public=_publickey_from_seed(seed))

    @property
    def public_hex(self) -> str:
        return self.public.hex()

    @property
    def seed_hex(self) -> str:
        return self.seed.hex()

    def sign(self, message: bytes) -> bytes:
        return _signature(message, self.seed, self.public)

    def sign_hex(self, message: bytes) -> str:
        return self.sign(message).hex()


@lru_cache(maxsize=4096)
def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """校验签名；任何格式/点/等式异常都归为 False（验证方绝不抛出）。

    结果按 (公钥, 消息, 签名) 缓存：穷举签收子集时同一条签名会被反复评估，
    缓存使每条唯一签名只做一次昂贵的标量乘。
    """
    try:
        if len(signature) != b // 4:  # 64
            return False
        if len(public) != b // 8:  # 32
            return False
        R = _decodepoint(signature[: b // 8])
        A = _decodepoint(public)
        S = _decodeint(signature[b // 8 : b // 4])
        if S >= l:
            return False
        h = _hint(signature[: b // 8] + public + message)
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False


def verify_hex(public_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        return verify(bytes.fromhex(public_hex), message, bytes.fromhex(signature_hex))
    except ValueError:
        return False


# ---- RFC 8032 §7.1 Test 1 已知答案自检（空消息） -------------------------
_RFC1_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
_RFC1_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
_RFC1_SIG = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def self_test() -> None:
    """用 RFC 8032 向量 + 往返/篡改用例验证算法实现。"""
    kp = KeyPair.from_seed_hex(_RFC1_SEED)
    if kp.public_hex != _RFC1_PUB:
        raise Ed25519Error("Ed25519 自检失败：公钥与 RFC 8032 向量不符")
    sig = kp.sign(b"")
    if sig.hex() != _RFC1_SIG:
        raise Ed25519Error("Ed25519 自检失败：签名与 RFC 8032 向量不符")
    if not verify_hex(_RFC1_PUB, b"", _RFC1_SIG):
        raise Ed25519Error("Ed25519 自检失败：RFC 向量验签未通过")

    # 往返 + 篡改必失败
    kp2 = KeyPair.from_seed_hex("01" * 32)
    msg = "封存水位 WM-0007|sha256:abc".encode("utf-8")
    s2 = kp2.sign(msg)
    if not verify(kp2.public, msg, s2):
        raise Ed25519Error("Ed25519 自检失败：自签自验未通过")
    if verify(kp2.public, msg + b"x", s2):
        raise Ed25519Error("Ed25519 自检失败：篡改消息竟通过")
    wrong = bytearray(s2)
    wrong[0] ^= 0x01
    if verify(kp2.public, msg, bytes(wrong)):
        raise Ed25519Error("Ed25519 自检失败：篡改签名竟通过")
