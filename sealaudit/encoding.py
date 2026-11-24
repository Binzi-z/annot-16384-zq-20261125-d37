"""规范编码、摘要与 Merkle 工具（全部标准库）。

所有进入签名 / 哈希的结构都先做 *规范化 JSON*：键排序、无多余空白、
UTF-8、不转义非 ASCII（仍确定性），从而消除同一语义因序列化不同而摘要不同的歧义。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

HEX_PREFIX = "sha256:"


def canonical_bytes(obj: Any) -> bytes:
    """返回结构的规范 JSON 字节。键排序、分隔符固定，保证跨进程一致。"""
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")


def _json_default(o: Any) -> Any:
    # dataclass / 集合等的兜底，保证可确定性序列化
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if hasattr(o, "to_json"):
        return o.to_json()
    if hasattr(o, "__dict__"):
        return o.__dict__
    raise TypeError(f"不可规范序列化的类型: {type(o)!r}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_obj(obj: Any) -> str:
    """对任意 JSON 兼容结构返回带前缀的规范摘要。"""
    return HEX_PREFIX + sha256_hex(canonical_bytes(obj))


def strip_prefix(d: str) -> str:
    return d[len(HEX_PREFIX) :] if d.startswith(HEX_PREFIX) else d


def raw_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_digest(key: bytes, *parts: bytes) -> bytes:
    """域分离的链式哈希辅助（这里直接用 sha256 拼接长度前缀，避免长度扩展歧义）。"""
    h = hashlib.sha256()
    h.update(b"sealaudit-v1|")
    h.update(key)
    for p in parts:
        h.update(len(p).to_bytes(8, "big"))
        h.update(p)
    return h.digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def leaf_hash(entry_canonical: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry_canonical).digest()


def merkle_root(leaves: Iterable[bytes]) -> bytes:
    """计算 Merkle 根；空列表返回空串哈希。奇数节点向上复制最后一个。"""
    level = list(leaves)
    if not level:
        return hashlib.sha256(b"empty-segment").digest()
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(node_hash(level[i], level[i + 1]))
            else:
                nxt.append(node_hash(level[i], level[i]))
        level = nxt
    return level[0]


def merkle_proof(leaves: list[bytes], index: int) -> list[tuple[str, bytes]]:
    """生成包含证明路径，元素为 ('l'|'r', sibling)。主要用于演示可独立验证单条。"""
    if not leaves:
        raise ValueError("空叶子集合无法生成证明")
    layer = list(leaves)
    idx = index
    proof: list[tuple[str, bytes]] = []
    while len(layer) > 1:
        if idx % 2 == 0:
            sib = layer[idx + 1] if idx + 1 < len(layer) else layer[idx]
            proof.append(("r", sib))
        else:
            proof.append(("l", layer[idx - 1]))
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                nxt.append(node_hash(layer[i], layer[i + 1]))
            else:
                nxt.append(node_hash(layer[i], layer[i]))
        layer = nxt
        idx //= 2
    return proof


def verify_merkle_proof(leaf: bytes, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    cur = leaf
    for side, sib in proof:
        if side == "r":
            cur = node_hash(cur, sib)
        else:
            cur = node_hash(sib, cur)
    return cur == root
