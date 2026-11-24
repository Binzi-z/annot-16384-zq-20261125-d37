"""60000 条合成账目：实测“补齐一段”的访问范围，对照逐段全量重新核验。

三条路径，结果必须一致：

A. 逐段全量重新核验：打开全部 60 个段文件、读全部 60000 条、重算所有段摘要/链/根；
B. 缺段补齐（前缀延伸）：缺口恰在已承诺前缀之后，只需读这一段 1000 条 + 上一链尖；
C. 单段清单包含证明（审计访问范围）：读这一段 + O(log S) 个 Merkle 兄弟哈希。

访问条目数 / 文件数 / 字节数 / 耗时全部用 Meter 与 perf_counter 实测，
并断言 B/C 得到的该段摘要、链值、清单根与 A 的全量结果完全相同。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .evidence import (
    Meter,
    build_chain,
    chunk_segments,
    make_account_entries,
    manifest_root,
    read_segment_file_metered,
    segment_digest,
    segment_merkle_path,
    verify_segment_in_manifest,
    write_segment_file,
)

N_ENTRIES = 60_000
SEG_SIZE = 1_000
TARGET_SEGMENT = 37  # 抽一个靠后的中段，避免“第一段”特例


def _build_dataset(root: Path) -> tuple[Path, list[str], list[str], str, list[list[dict]]]:
    bench_dir = root / "bench60k"
    seg_dir = bench_dir / "segments"
    seg_dir.mkdir(parents=True, exist_ok=True)
    entries = make_account_entries(N_ENTRIES)
    segments = chunk_segments(entries, SEG_SIZE)
    digests: list[str] = []
    for i, seg in enumerate(segments):
        digests.append(segment_digest(seg))
        write_segment_file(seg_dir, i, seg)
    chain = build_chain(digests)
    mroot = manifest_root(digests)
    return seg_dir, digests, chain, mroot, segments


def run_benchmark(root: Path) -> dict[str, Any]:
    seg_dir, digests, chain, mroot, segments = _build_dataset(root)
    seg_count = len(digests)
    k = TARGET_SEGMENT

    # ---------- A. 逐段全量重新核验（计量 + 计时） --------------------------
    full_meter = Meter()
    t0 = time.perf_counter()
    full_digests: list[str] = []
    for i in range(seg_count):
        seg = read_segment_file_metered(seg_dir, i, full_meter)
        full_digests.append(segment_digest(seg, full_meter))
    full_chain = build_chain(full_digests)
    full_root = manifest_root(full_digests)
    full_seconds = time.perf_counter() - t0
    full_match = (
        full_digests == digests and full_chain == chain and full_root == mroot
    )

    # ---------- B. 缺段补齐：只读目标段 + 上一链尖 --------------------------
    fill_meter = Meter()
    t0 = time.perf_counter()
    seg_k = read_segment_file_metered(seg_dir, k, fill_meter)
    dk = segment_digest(seg_k, fill_meter)
    prev_tip = chain[k - 1] if k > 0 else "0" * 64
    from .evidence import chain_link

    ck = chain_link(prev_tip, dk, k)
    fill_seconds = time.perf_counter() - t0
    fill_meter.metadata_bytes_read += 32  # 上一链尖 sha256
    fill_meter.headers_read += 1

    fill_matches = dk == full_digests[k] and ck == full_chain[k]

    # ---------- C. Merkle 包含证明：目标段 + O(log S) 兄弟哈希 --------------
    proof_meter = Meter()
    t0 = time.perf_counter()
    seg_k2 = read_segment_file_metered(seg_dir, k, proof_meter)
    dk2 = segment_digest(seg_k2, proof_meter)
    path = segment_merkle_path(digests, k)
    proof_meter.proof_hashes_read = len(path)
    proof_meter.metadata_bytes_read += 32 * len(path) + 32  # 兄弟 + 清单根
    inclusion_ok = verify_segment_in_manifest(dk2, path, mroot)
    proof_seconds = time.perf_counter() - t0
    proof_matches = dk2 == full_digests[k] and inclusion_ok and mroot == full_root

    # ---------- 汇总访问范围对照 -------------------------------------------
    fs = full_meter.snapshot()
    bs = fill_meter.snapshot()
    cs = proof_meter.snapshot()

    result = {
        "entries_total": N_ENTRIES,
        "segment_size": SEG_SIZE,
        "segment_count": seg_count,
        "target_segment": k,
        "merkle_path_length": len(path),
        "full_reverify": {
            **fs,
            "seconds": round(full_seconds, 6),
            "result_matches_build": full_match,
        },
        "fill_one_segment_prefix_extension": {
            **bs,
            "seconds": round(fill_seconds, 6),
            "matches_full_result": fill_matches,
            "new_watermark_chain_tip": ck,
        },
        "one_segment_merkle_inclusion": {
            **cs,
            "seconds": round(proof_seconds, 6),
            "matches_full_result": proof_matches,
            "manifest_root": mroot,
        },
        "access_ratio_raw_entries_full_vs_fill": round(
            fs["raw_entries_read"] / max(1, bs["raw_entries_read"]), 2
        ),
        "access_ratio_files_full_vs_fill": round(
            fs["segment_files_opened"] / max(1, bs["segment_files_opened"]), 2
        ),
        "byte_ratio_full_vs_fill": round(
            fs["bytes_read"] / max(1, bs["bytes_read"]), 2
        ),
        "all_paths_agree": bool(full_match and fill_matches and proof_matches),
        "note": (
            "补齐一段只需访问 1/60 的原始账目；Merkle 路径另需 "
            f"{len(path)} 个 32 字节兄弟哈希。全量核验须读全部 60000 条。"
        ),
    }
    return result
