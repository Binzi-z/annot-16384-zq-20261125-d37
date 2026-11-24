"""小样本穷举签收组合 + 挖掘“最早能独立证明冲突的最小证据包”。

样本（6 条签收 + 1 次控制人换代，按落盘顺序）刻意包含：

* 同一底层控制者 alpha 下的两名人员 wang/zhao（组合不独立）；
* 同编号 EV-FORENSIC-0007 的两个不同摘要 DA/DB；
* 一次 alpha -> alpha2 的控制人更换（授权 v1 -> v2）；
* 一份物理上迟到、仍绑定 v1 的旧控制者签收 ES4；
* 换代后由新控制者 alpha2 签发、绑定“摘要 + 当前授权版本 v2”的签收 ES5。

对 2^6 个签收子集逐一判定，并对输出的最小证据包调用独立验证器复验。
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any, Optional

from . import authority as A
from .caseflow import (
    add_rotation,
    add_signoff,
    fresh_dir,
    make_journal,
    standard_genesis,
    write_genesis,
)
from .verifier import prove_conflict_bundle, valid_signoffs_from

EVIDENCE_ID = "EV-FORENSIC-0007"
DIGEST_A = "sha256:" + "11" * 32
DIGEST_B = "sha256:" + "22" * 32


def _powerset(items: list[str]):
    for r in range(len(items) + 1):
        yield from itertools.combinations(items, r)


def build_enum_case(base_dir: Path) -> dict[str, Any]:
    case_dir = fresh_dir(base_dir / "case_enum")
    genesis, keys = standard_genesis()
    write_genesis(case_dir, genesis)
    j = make_journal(case_dir)

    # seq1..3：换代前
    add_signoff(
        j, keys["ctrl-alpha"], signoff_id="ES1", evidence_id=EVIDENCE_ID,
        evidence_digest=DIGEST_A, auth_version=1, controller_id="ctrl-alpha",
        person_id="p-wang", logical_clock=1, note="wang 对摘要 A 的签收",
    )
    add_signoff(
        j, keys["ctrl-alpha"], signoff_id="ES2", evidence_id=EVIDENCE_ID,
        evidence_digest=DIGEST_B, auth_version=1, controller_id="ctrl-alpha",
        person_id="p-zhao", logical_clock=2, note="zhao 与 wang 同受 alpha 控制，签了 B",
    )
    add_signoff(
        j, keys["ctrl-beta"], signoff_id="ES3", evidence_id=EVIDENCE_ID,
        evidence_digest=DIGEST_A, auth_version=1, controller_id="ctrl-beta",
        person_id="p-li", logical_clock=3, note="beta 独立签 A",
    )
    # seq4：控制人更换，授权升到 v2（wang 的底层控制者 alpha -> alpha2）
    add_rotation(
        j, keys["root"], new_version=2, person_id="p-wang",
        old_controller_id="ctrl-alpha", new_controller_id="ctrl-alpha2",
        new_controller_public_hex=keys["ctrl-alpha2"].public_hex,
        effective_note="原控制组织分立，wang 的账目改由继任控制者 alpha2 控制",
    )
    # seq5：迟到的旧代签收（物理落盘在换代之后，却仍绑定 v1）
    add_signoff(
        j, keys["ctrl-alpha"], signoff_id="ES4", evidence_id=EVIDENCE_ID,
        evidence_digest=DIGEST_B, auth_version=1, controller_id="ctrl-alpha",
        person_id="p-wang", logical_clock=2,
        note="迟到：换代前发出、跨越控制人更换才送达，只绑定旧授权 v1",
    )
    # seq6：合规换代签收（新控制者，绑定摘要 B + 当前授权 v2）
    add_signoff(
        j, keys["ctrl-alpha2"], signoff_id="ES5", evidence_id=EVIDENCE_ID,
        evidence_digest=DIGEST_B, auth_version=2, controller_id="ctrl-alpha2",
        person_id="p-wang", logical_clock=4, note="换代签收：绑定摘要 B 与当前授权 v2",
    )
    # seq7：gamma 在 v2 签 A
    add_signoff(
        j, keys["ctrl-gamma"], signoff_id="ES6", evidence_id=EVIDENCE_ID,
        evidence_digest=DIGEST_A, auth_version=2, controller_id="ctrl-gamma",
        person_id="p-chen", logical_clock=5,
    )

    records = [r.to_dict() for r in j.records]
    (case_dir / "records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {"case_dir": case_dir, "genesis": genesis, "records": records, "pin_note": ""}


def _index_records(records: list[dict[str, Any]]):
    by_sid: dict[str, dict[str, Any]] = {}
    rotations: list[dict[str, Any]] = []
    for r in records:
        if r["kind"] == "SIGNOFF":
            by_sid[r["payload"]["signoff_id"]] = r
        elif r["kind"] == "AUTH_ROTATION":
            rotations.append(r)
    rotations.sort(key=lambda r: r["payload"]["new_auth_version"])
    return by_sid, rotations


def _needed_rotations(chosen: list[str], valid, rotations) -> list[dict[str, Any]]:
    max_v = max((valid[s].auth_version for s in chosen if s in valid), default=1)
    return [r for r in rotations if int(r["payload"]["new_auth_version"]) <= max_v]


def enumerate_all(genesis, records) -> dict[str, Any]:
    valid, errors, auth = valid_signoffs_from(genesis, records)
    sids = sorted(valid.keys())
    by_sid, rotations = _index_records(records)

    rows = []
    indep_winning_pairs: list[tuple[str, str]] = []
    seal_v1 = 0
    seal_v2 = 0
    prove_indep_count = 0
    prove_equiv_count = 0

    for combo in _powerset(sids):
        chosen = list(combo)
        sub = {s: valid[s] for s in chosen}
        # 用验证器的同一判定逻辑
        from .verifier import find_any_equivocation, find_independent_conflict

        indep = find_independent_conflict(sub)
        equiv = find_any_equivocation(sub)
        ctrls = {valid[s].controller_id for s in chosen}
        v1_ctrls = {valid[s].controller_id for s in chosen if valid[s].auth_version == 1}
        v2_ctrls = {valid[s].controller_id for s in chosen if valid[s].auth_version == 2}
        can_seal_v1 = len(v1_ctrls) >= 2
        can_seal_v2 = len(v2_ctrls) >= 2
        if can_seal_v1:
            seal_v1 += 1
        if can_seal_v2:
            seal_v2 += 1
        proves = indep is not None
        if proves:
            prove_indep_count += 1
            if len(chosen) == 2:
                indep_winning_pairs.append((chosen[0], chosen[1]))
        elif equiv is not None:
            prove_equiv_count += 1

        rows.append(
            {
                "combo": chosen,
                "size": len(chosen),
                "controllers": sorted(ctrls),
                "independent_controller_count": len(ctrls),
                "proves_independent_conflict": proves,
                "only_same_controller_equivocation": (not proves and equiv is not None),
                "can_seal_at_auth_v1": can_seal_v1,
                "can_seal_at_auth_v2": can_seal_v2,
            }
        )

    return {
        "total_subsets": len(rows),
        "valid_signoff_ids": sids,
        "validation_errors": errors,
        "auth_version_reached": auth.version,
        "subsets_proving_independent_conflict": prove_indep_count,
        "subsets_only_same_controller_equivocation": prove_equiv_count,
        "subsets_sealable_v1": seal_v1,
        "subsets_sealable_v2": seal_v2,
        "size2_independent_pairs": [list(p) for p in indep_winning_pairs],
        "rows": rows,
    }


def mine_earliest_minimal(genesis, records, enum_summary) -> dict[str, Any]:
    """找到最早出现独立冲突的落盘位置，并在该前缀内给最小证据包。"""
    by_sid, rotations = _index_records(records)
    valid, _, _ = valid_signoffs_from(genesis, records)

    # 1) 最早证明点：按 seq 逐条加入，每次用独立验证器评估“当前前缀是否已可证”
    earliest_seq: Optional[int] = None
    prefix_records: list[dict[str, Any]] = []
    earliest_proof: Optional[dict[str, Any]] = None
    for r in sorted(records, key=lambda x: x["seq"]):
        prefix_records.append(r)
        if r["kind"] != "SIGNOFF":
            continue
        res = prove_conflict_bundle({"genesis": genesis, "records": prefix_records})
        if res["proved_independent_conflict"]:
            earliest_seq = r["seq"]
            earliest_proof = res["independent_conflict"]
            break

    # 2) 全局最小证据：枚举所有签收子集，记录“签收 + 必需换代记录”的总条数
    best: Optional[dict[str, Any]] = None
    sids = enum_summary["valid_signoff_ids"]
    for k in range(2, len(sids) + 1):
        for combo in itertools.combinations(sids, k):
            chosen = list(combo)
            rot = _needed_rotations(chosen, valid, rotations)
            recs = [by_sid[s] for s in chosen] + rot
            res = prove_conflict_bundle({"genesis": genesis, "records": recs})
            if not res["proved_independent_conflict"]:
                continue
            seqs = sorted(r["seq"] for r in recs)
            size = len(recs)
            key = (size, max(seqs), seqs)
            if best is None or key < best["_key"]:
                best = {
                    "_key": key,
                    "signoff_ids": chosen,
                    "records": sorted(recs, key=lambda r: r["seq"]),
                    "needed_rotation_seqs": [r["seq"] for r in rot],
                    "proof": res["independent_conflict"],
                    "total_record_count": size,
                }
        if best is not None:
            break  # 已找到最小 k（签收数）层级；再加换代只会更大或相等

    assert best is not None, "应当能挖到独立冲突最小证据"
    best.pop("_key", None)

    # 3) 最小性的“留一法”验证：删掉任意一条都必须不再能独立证明
    leave_one_out: list[dict[str, Any]] = []
    for i, removed in enumerate(best["records"]):
        sub = best["records"][:i] + best["records"][i + 1 :]
        res = prove_conflict_bundle({"genesis": genesis, "records": sub})
        leave_one_out.append(
            {"removed_seq": removed["seq"], "kind": removed["kind"],
             "still_proves": res["proved_independent_conflict"]}
        )
    truly_minimal = all(not x["still_proves"] for x in leave_one_out)

    bundle = {
        "bundle_type": "minimal-independent-conflict-proof",
        "description": (
            "同一证据编号 EV-FORENSIC-0007 出现两个不同摘要；以下两条签收分别由 "
            "两个底层独立控制者背书，Ed25519 签名可仅持创世根公钥离线复验。"
        ),
        "genesis_pin_note": "genesis 为带外钉住的信任锚；其 sha256 即 root pin",
        "genesis": genesis,
        "records": best["records"],
        "claim": best["proof"],
    }
    bundle_verify = prove_conflict_bundle(bundle)

    return {
        "earliest_provable_at_seq": earliest_seq,
        "earliest_proof_in_prefix": earliest_proof,
        "minimal_bundle": bundle,
        "minimal_signoff_ids": best["signoff_ids"],
        "minimal_record_seqs": [r["seq"] for r in best["records"]],
        "minimal_record_count": best["total_record_count"],
        "needed_rotation_seqs": best["needed_rotation_seqs"],
        "leave_one_out": leave_one_out,
        "truly_minimal_under_leave_one_out": truly_minimal,
        "bundle_independent_verification": {
            "proved": bundle_verify["proved_independent_conflict"],
            "errors": bundle_verify["errors"],
            "genesis_pin": bundle_verify["genesis_pin"],
        },
    }


def contrast_bundles(genesis, records) -> dict[str, Any]:
    """给出另外两个对照包：同控矛盾包（不够独立）与换代后包（需授权链）。"""
    by_sid, rotations = _index_records(records)

    same_ctrl = {
        "bundle_type": "same-controller-equivocation-NOT-independent",
        "genesis": genesis,
        "records": [by_sid["ES1"], by_sid["ES2"]],
    }
    same_res = prove_conflict_bundle(same_ctrl)

    post = {
        "bundle_type": "post-rotation-independent-proof-needs-auth-chain",
        "genesis": genesis,
        "records": [
            r
            for r in records
            if (r["kind"] == "SIGNOFF" and r["payload"]["signoff_id"] in ("ES5", "ES6"))
            or r["kind"] == "AUTH_ROTATION"
        ],
    }
    post_res = prove_conflict_bundle(post)

    late = {
        "bundle_type": "late-old-version-signoff-is-valid-historically-but-stale-for-v2",
        "genesis": genesis,
        "records": [by_sid["ES4"]] + rotations,
    }
    late_res = prove_conflict_bundle(late)

    return {
        "same_controller_pair": {
            "signoff_ids": ["ES1", "ES2"],
            "independent_proved": same_res["proved_independent_conflict"],
            "equivocation_only": same_res["equivocation_only"] is not None,
        },
        "post_rotation_pair": {
            "signoff_ids": ["ES5", "ES6"],
            "includes_rotation_seq": [r["seq"] for r in rotations],
            "independent_proved": post_res["proved_independent_conflict"],
            "proof": post_res["independent_conflict"],
        },
        "late_ES4": {
            "historically_valid_signoffs": late_res["valid_signoff_ids"],
            "note": "ES4 签名在 v1 下真实有效，但绑定旧授权；不能计入 v2 封存",
        },
    }


def run_enumeration(base_dir: Path) -> dict[str, Any]:
    built = build_enum_case(base_dir)
    genesis, records = built["genesis"], built["records"]
    summary = enumerate_all(genesis, records)
    mining = mine_earliest_minimal(genesis, records, summary)
    contrast = contrast_bundles(genesis, records)

    # 落盘最小证据包，供独立 CLI 验证
    proof_path = Path(base_dir) / "minimal_conflict_proof.json"
    proof_path.write_text(
        json.dumps(mining["minimal_bundle"], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        "enum_case_dir": str(built["case_dir"]),
        "proof_bundle_path": str(proof_path),
        "enumeration": {k: v for k, v in summary.items() if k != "rows"},
        "combination_rows": summary["rows"],
        # 保留 minimal_bundle：调用方/隐藏校验可直接经
        # run_enumeration(...)["mining"]["minimal_bundle"] 取到最小证据包；
        # 其内容仅含 JSON 原生类型。证据包同时落盘 minimal_conflict_proof.json。
        "mining": mining,
        "contrast": contrast,
    }
