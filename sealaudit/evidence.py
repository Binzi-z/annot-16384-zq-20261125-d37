"""证据条目、分段摘要、Merkle 根、分段哈希链与访问计量。

* 每段含若干规范化账目录；段摘要 = 段内叶子哈希的 Merkle 根。
* 段间再做线性哈希链 ``chain_i = H("chain-v1", chain_{i-1}, seg_i)``，
  用来表达“连续前缀 / 最后连续可信前缀”。
* 所有段摘要再汇总成一棵清单 Merkle 树，水位承诺清单根；这样补齐单独一段
  时只需读取该段原始账目 + O(log S) 个路径兄弟摘要，不必重读全部账目。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .encoding import (
    canonical_bytes,
    leaf_hash,
    merkle_proof,
    merkle_root,
    sha256_hex,
    verify_merkle_proof,
)

CHAIN_GENESIS = "0" * 64


# ----------------------------------------------------------------------
# 访问计量：所有“读账目 / 读段文件 / 读段头 / 读字节”都经过 Meter
# ----------------------------------------------------------------------
@dataclass
class Meter:
    raw_entries_read: int = 0
    segment_files_opened: int = 0
    full_segments_read: int = 0
    headers_read: int = 0
    bytes_read: int = 0
    hash_input_entries: int = 0
    proof_hashes_read: int = 0
    metadata_bytes_read: int = 0
    accessed_segment_indices: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "raw_entries_read": self.raw_entries_read,
            "segment_files_opened": self.segment_files_opened,
            "full_segments_read": self.full_segments_read,
            "headers_read": self.headers_read,
            "bytes_read": self.bytes_read,
            "hash_input_entries": self.hash_input_entries,
            "proof_hashes_read": self.proof_hashes_read,
            "metadata_bytes_read": self.metadata_bytes_read,
            "accessed_segment_indices": list(self.accessed_segment_indices),
        }


# ----------------------------------------------------------------------
# 确定性合成账目（固定种子，跨机器/重跑一致；不使用墙钟或随机源）
# ----------------------------------------------------------------------
_FIRST = ["伟", "强", "磊", "军", "洋", "勇", "艳", "杰", "娟", "涛", "明", "超", "霞", "平", "刚"]
_CITY = ["北京", "上海", "广州", "深圳", "杭州", "成都", "武汉", "西安", "南京", "重庆"]
_KIND = ["存款", "取款", "转账", "消费", "退款", "利息", "手续费", "汇兑"]
_CP = ["对公结算", "个人账户", "商户收单", "代发工资", "同业拆借", "内部过渡"]


def make_account_entries(n: int = 60000, *, seed: int = 20261125) -> list[dict[str, Any]]:
    """生成 n 条确定性“合成账目”。用自建 LCG，避免依赖随机模块的跨版本差异。"""
    state = seed & 0xFFFFFFFF

    def nxt() -> int:
        # Numerical Recipes LCG（确定性）
        nonlocal state
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        return state

    def pick(seq: list[str]) -> str:
        return seq[nxt() % len(seq)]

    entries: list[dict[str, Any]] = []
    for i in range(1, n + 1):
        debit = nxt() % 500000
        credit = nxt() % 500000
        kind = pick(_KIND)
        entries.append(
            {
                "seq": i,
                "acct": f"6222-{i % 9973:04d}-{(i * 7) % 10000:04d}-{i % 10000:04d}",
                "name": pick(_FIRST) + pick(_FIRST),
                "city": pick(_CITY),
                "kind": kind,
                "cp": pick(_CP),
                "debit_cents": debit if kind in ("取款", "转账", "消费", "手续费") else 0,
                "credit_cents": credit if kind in ("存款", "退款", "利息", "汇兑") else 0,
                "voucher": f"V-{seed}-{i:06d}",
                "ledger_page": (i - 1) // 200 + 1,
            }
        )
    return entries


# ----------------------------------------------------------------------
# 段摘要 / 链 / 清单根
# ----------------------------------------------------------------------
def entry_leaf(entry: dict[str, Any]) -> bytes:
    return leaf_hash(canonical_bytes(entry))


def segment_digest(entries: list[dict[str, Any]], meter: Optional[Meter] = None) -> str:
    """计算段 Merkle 根。meter 只统计“被哈希的条目数”，I/O 字节由读取器计量。"""
    if meter is not None:
        meter.hash_input_entries += len(entries)
    root = merkle_root([entry_leaf(e) for e in entries])
    return root.hex()


def canonical_bytes_many(entries: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_bytes(e) for e in entries)


def chain_link(prev_hex: str, seg_digest_hex: str, index: int) -> str:
    return sha256_hex(
        b"sealaudit-chain-v1|"
        + index.to_bytes(8, "big")
        + bytes.fromhex(prev_hex)
        + bytes.fromhex(seg_digest_hex)
    )


def build_chain(seg_digests: list[str]) -> list[str]:
    chain: list[str] = []
    prev = CHAIN_GENESIS
    for i, d in enumerate(seg_digests):
        prev = chain_link(prev, d, i)
        chain.append(prev)
    return chain


def manifest_root(seg_digests: list[str]) -> str:
    return merkle_root([bytes.fromhex(d) for d in seg_digests]).hex()


def segment_merkle_path(seg_digests: list[str], index: int) -> list[tuple[str, str]]:
    leaves = [bytes.fromhex(d) for d in seg_digests]
    raw = merkle_proof(leaves, index)
    return [(side, sib.hex()) for side, sib in raw]


def verify_segment_in_manifest(
    seg_digest_hex: str, path: list[tuple[str, str]], root_hex: str
) -> bool:
    return verify_merkle_proof(
        bytes.fromhex(seg_digest_hex),
        [(side, bytes.fromhex(sib)) for side, sib in path],
        bytes.fromhex(root_hex),
    )


def chunk_segments(entries: list[dict[str, Any]], seg_size: int) -> list[list[dict[str, Any]]]:
    return [entries[i : i + seg_size] for i in range(0, len(entries), seg_size)]


# ----------------------------------------------------------------------
# 段文件持久化 + 计量读取
# ----------------------------------------------------------------------
def write_segment_file(seg_dir: Path, index: int, entries: list[dict[str, Any]]) -> Path:
    seg_dir.mkdir(parents=True, exist_ok=True)
    p = seg_dir / f"seg_{index:05d}.jsonl"
    with p.open("w", encoding="utf-8", newline="\n") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
    return p


def read_segment_file_metered(
    seg_dir: Path, index: int, meter: Meter
) -> list[dict[str, Any]]:
    p = seg_dir / f"seg_{index:05d}.jsonl"
    meter.segment_files_opened += 1
    meter.full_segments_read += 1
    meter.accessed_segment_indices.append(index)
    entries: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = line.encode("utf-8")
            meter.bytes_read += len(raw) + 1
            entries.append(json.loads(line))
    meter.raw_entries_read += len(entries)
    return entries


def write_header_file(out_dir: Path, seg_digests: list[str], extra: dict[str, Any]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "segment_headers.json"
    headers = [{"index": i, "digest": d} for i, d in enumerate(seg_digests)]
    p.write_text(
        json.dumps(
            {"segments": headers, **extra}, ensure_ascii=False, indent=2, sort_keys=True
        ),
        encoding="utf-8",
    )
    return p


def read_headers_metered(path: Path, meter: Meter) -> dict[str, Any]:
    raw = path.read_bytes()
    meter.bytes_read += len(raw)
    obj = json.loads(raw.decode("utf-8"))
    meter.headers_read += len(obj["segments"])
    return obj
