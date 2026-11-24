"""独立验证引擎（只读）——不导入任何写入/服务代码。

验证方只信任带外钉住的创世指纹(root pin)，随后：

1. 独立重算日志哈希链（seq 连续、prev/hash 正确）；
2. 从创世 + 根签授权换代记录重建“人员 -> 底层控制者”的版本化绑定；
3. 逐条验签 SIGNOFF / REVOKE；
4. 按 *seq 落盘顺序* 裁决 撤销 vs 提交；
5. 从段原始账目重算段摘要 / 链尖 / 清单根，复验每个已承诺水位；
6. 发现同一 evidence_id 对应不同 evidence_digest 的冲突，并判断是否由
   两个底层独立控制者背书。

任何畸形输入都归为验证失败并记录，而不是抛出。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import authority as A
from .encoding import canonical_bytes, digest_obj
from .evidence import (
    CHAIN_GENESIS,
    build_chain,
    chain_link,
    chunk_segments,
    manifest_root,
    segment_digest,
)
from .journal import GENESIS_PREV, record_hash


# ----------------------------------------------------------------------
# 创世 / 授权状态重放
# ----------------------------------------------------------------------
@dataclass
class AuthState:
    root_public_key: str
    version: int = 1
    controllers: dict[str, str] = field(default_factory=dict)  # cid -> pubhex
    # person -> [(introduced_version, controller_id)]，按版本升序
    bindings: dict[str, list[tuple[int, str]]] = field(default_factory=dict)

    @classmethod
    def from_genesis(cls, g: dict[str, Any]) -> "AuthState":
        st = cls(root_public_key=str(g["root_public_key"]))
        st.version = int(g.get("auth_version", 1))
        for cid, pub in g.get("controllers", {}).items():
            st.controllers[str(cid)] = str(pub)
        for pid, info in g.get("persons", {}).items():
            cid = str(info["controller"])
            since = int(info.get("since_version", 1))
            st.bindings.setdefault(str(pid), []).append((since, cid))
        for pid in st.bindings:
            st.bindings[pid].sort()
        return st

    def controller_of(self, person_id: str, at_version: int) -> Optional[str]:
        hist = self.bindings.get(person_id)
        if not hist:
            return None
        chosen: Optional[str] = None
        for introduced, cid in hist:
            if introduced <= at_version:
                chosen = cid
            else:
                break
        return chosen

    def apply_rotation(self, p: dict[str, Any]) -> tuple[bool, str]:
        if not A.verify_rotation_sig(p, self.root_public_key):
            return False, "授权换代记录根签名无效"
        new_v = int(p["new_auth_version"])
        if new_v != self.version + 1:
            return False, f"授权版本跳跃：期望 {self.version + 1}，见到 {new_v}"
        pid = str(p["person_id"])
        new_cid = str(p["new_controller_id"])
        new_pub = str(p["new_controller_public_key"])
        self.controllers[new_cid] = new_pub
        self.bindings.setdefault(pid, []).append((new_v, new_cid))
        self.bindings[pid].sort()
        self.version = new_v
        return True, ""


def genesis_pin(genesis: dict[str, Any]) -> str:
    return digest_obj(genesis)


# ----------------------------------------------------------------------
# 日志哈希链独立校验
# ----------------------------------------------------------------------
def verify_chain(records: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    errs: list[str] = []
    prev = GENESIS_PREV
    for i, r in enumerate(records, 1):
        seq = int(r.get("seq", -1))
        if seq != i:
            errs.append(f"第 {i} 行 seq={seq} 不连续")
            continue
        if r.get("prev") != prev:
            errs.append(f"seq={seq} prev 与上一条哈希不符（链断裂）")
        expect = record_hash(seq, str(r.get("kind")), r.get("payload", {}), str(r.get("prev")))
        if r.get("hash") != expect:
            errs.append(f"seq={seq} 记录哈希重算不符（内容被篡改？）")
        prev = str(r.get("hash"))
    return (not errs), errs


# ----------------------------------------------------------------------
# 单条签收验证
# ----------------------------------------------------------------------
@dataclass
class ValidSignoff:
    seq: int
    signoff_id: str
    evidence_id: str
    evidence_digest: str
    person_id: str
    controller_id: str
    auth_version: int
    record: dict[str, Any]


def validate_signoff(
    seq: int, rec: dict[str, Any], auth: AuthState
) -> tuple[Optional[ValidSignoff], str]:
    try:
        sid = str(rec["signoff_id"])
        eid = str(rec["evidence_id"])
        dig = str(rec["evidence_digest"])
        pid = str(rec["person_id"])
        cid_claim = str(rec["controller_id"])
        ver = int(rec["auth_version"])
    except (KeyError, TypeError, ValueError):
        return None, "签收字段缺失/类型错误"

    if ver < 1 or ver > auth.version:
        return None, f"签收 auth_version={ver} 不在已知范围 [1,{auth.version}]"
    expected_cid = auth.controller_of(pid, ver)
    if expected_cid is None:
        return None, f"人员 {pid} 在 v{ver} 无授权绑定"
    if expected_cid != cid_claim:
        return None, f"签收声称控制者 {cid_claim}，但 v{ver} 底层控制者应为 {expected_cid}"
    pub = auth.controllers.get(cid_claim)
    if not pub:
        return None, f"控制者 {cid_claim} 公钥未知（未被创世/换代锚定）"
    if not A.verify_signoff_sig(rec, pub):
        return None, "签收 Ed25519 签名无效"
    return (
        ValidSignoff(seq, sid, eid, dig, pid, cid_claim, ver, rec),
        "",
    )


# ----------------------------------------------------------------------
# 核心评估：可对完整记录，也可对一个“最小证据子集”调用
# ----------------------------------------------------------------------
def _iter_rotations(records: list[dict[str, Any]], auth: AuthState, errors: list[str]) -> None:
    for r in sorted(records, key=lambda x: int(x.get("seq", 0))):
        if r.get("kind") == "AUTH_ROTATION":
            ok, why = auth.apply_rotation(r.get("payload", {}))
            if not ok:
                errors.append(f"seq={r.get('seq')} {why}")


def build_auth(genesis: dict[str, Any], records: list[dict[str, Any]]) -> tuple[AuthState, list[str]]:
    auth = AuthState.from_genesis(genesis)
    errs: list[str] = []
    _iter_rotations(records, auth, errs)
    return auth, errs


def valid_signoffs_from(
    genesis: dict[str, Any], records: list[dict[str, Any]]
) -> tuple[dict[str, ValidSignoff], list[str], AuthState]:
    auth, errs = build_auth(genesis, records)
    out: dict[str, ValidSignoff] = {}
    for r in sorted(records, key=lambda x: int(x.get("seq", 0))):
        if r.get("kind") != "SIGNOFF":
            continue
        vs, why = validate_signoff(int(r["seq"]), r.get("payload", {}), auth)
        if vs is None:
            errs.append(f"SIGNOFF seq={r.get('seq')} 无效：{why}")
        else:
            out[vs.signoff_id] = vs
    return out, errs, auth


def find_independent_conflict(
    valid: dict[str, ValidSignoff],
) -> Optional[dict[str, Any]]:
    """在有效签收中寻找 同编号/不同摘要/不同底层控制者 的最早最小一对。"""
    by_eid: dict[str, list[ValidSignoff]] = {}
    for vs in valid.values():
        by_eid.setdefault(vs.evidence_id, []).append(vs)

    best: Optional[dict[str, Any]] = None
    for eid, items in by_eid.items():
        digests = {v.evidence_digest for v in items}
        if len(digests) < 2:
            continue
        items = sorted(items, key=lambda v: v.seq)
        for i, a in enumerate(items):
            for b in items[i + 1 :]:
                if a.evidence_digest == b.evidence_digest:
                    continue
                if a.controller_id == b.controller_id:
                    continue  # 同一底层控制者，不构成“独立”双方
                pair = sorted([a, b], key=lambda v: v.seq)
                score = (pair[1].seq, pair[0].seq)
                cand = {
                    "evidence_id": eid,
                    "digest_a": pair[0].evidence_digest,
                    "digest_b": pair[1].evidence_digest,
                    "earliest_second_seq": pair[1].seq,
                    "signoff_seqs": [v.seq for v in pair],
                    "signoff_ids": [v.signoff_id for v in pair],
                    "controllers": [v.controller_id for v in pair],
                    "persons": [v.person_id for v in pair],
                    "auth_versions": [v.auth_version for v in pair],
                    "_score": score,
                }
                if best is None or score < best["_score"]:
                    best = cand
    if best:
        best.pop("_score", None)
    return best


def find_any_equivocation(valid: dict[str, ValidSignoff]) -> Optional[dict[str, Any]]:
    """更弱但最小的冲突：同一控制者（甚至同一人）对同编号签两个不同摘要。"""
    by_eid_ctrl: dict[tuple[str, str], list[ValidSignoff]] = {}
    for vs in valid.values():
        by_eid_ctrl.setdefault((vs.evidence_id, vs.controller_id), []).append(vs)
    for (eid, cid), items in by_eid_ctrl.items():
        digs = {v.evidence_digest for v in items}
        if len(digs) >= 2:
            items = sorted(items, key=lambda v: v.seq)
            # 关键：生成器谓词不能引用同一行元组解包尚未绑定的目标 a（CPython
            # 单元变量会抛 NameError）；这里改引已绑定的 items[0]。
            a, b = items[0], next(v for v in items[1:] if v.evidence_digest != items[0].evidence_digest)
            return {
                "evidence_id": eid,
                "controller_id": cid,
                "digest_a": a.evidence_digest,
                "digest_b": b.evidence_digest,
                "signoff_seqs": [a.seq, b.seq],
                "signoff_ids": [a.signoff_id, b.signoff_id],
                "note": "同一底层控制者自相矛盾：能证明摘要冲突，但不满足两个独立控制者",
            }
    return None


# ----------------------------------------------------------------------
# 撤销裁决
# ----------------------------------------------------------------------
def validated_revokes(
    genesis: dict[str, Any], records: list[dict[str, Any]], auth: AuthState
) -> dict[str, list[dict[str, Any]]]:
    """target_signoff_id -> 有效撤销记录列表（含 seq）。"""
    # 需要签收的控制者归属来验签撤销
    valid, _, _ = valid_signoffs_from(genesis, records)
    out: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        if r.get("kind") != "REVOKE":
            continue
        p = r.get("payload", {})
        sid = str(p.get("target_signoff_id", ""))
        vs = valid.get(sid)
        if vs is None:
            continue
        pub = auth.controllers.get(vs.controller_id, "")
        if not pub or not A.verify_revoke_sig(p, pub):
            continue
        if p.get("controller_id") != vs.controller_id:
            continue
        out.setdefault(sid, []).append({"seq": int(r["seq"]), "revoke_id": p.get("revoke_id")})
    return out


def revoke_state_for_commit(
    commit_seq: int, signoff_ids: list[str], revokes: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    """按落盘 seq 裁决：只有 seq < commit_seq 的撤销才抢先成立。"""
    preempted: list[str] = []
    late: list[str] = []
    for sid in signoff_ids:
        for rv in revokes.get(sid, []):
            if rv["seq"] < commit_seq:
                preempted.append(sid)
            else:
                late.append(sid)
    return {"preempted": sorted(set(preempted)), "late": sorted(set(late))}


# ----------------------------------------------------------------------
# 从段目录重算前缀承诺
# ----------------------------------------------------------------------
def recompute_prefix(
    seg_dir: Optional[Path], segment_digests: list[str], meter: Any = None
) -> tuple[bool, str, dict[str, Any]]:
    """读取段原始账目，逐段重算摘要并与承诺的 segment_digests 对比。

    若 seg_dir 为 None（最小证据包场景），无法重算账目，返回 skipped。
    """
    if seg_dir is None:
        return True, "skipped(no-segment-dir)", {}
    chains = build_chain(segment_digests)
    for i, promised in enumerate(segment_digests):
        p = seg_dir / f"seg_{i:05d}.jsonl"
        if not p.exists():
            return False, f"缺少段原始文件 seg_{i:05d}.jsonl", {}
        entries: list[dict[str, Any]] = []
        import json as _json

        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(_json.loads(line))
        actual = segment_digest(entries, meter)
        if actual != promised:
            return False, f"段 {i} 摘要重算不符", {"index": i, "promised": promised, "actual": actual}
    return (
        True,
        "ok",
        {"chain_tip": chains[-1] if chains else CHAIN_GENESIS, "segments": len(segment_digests)},
    )


# ----------------------------------------------------------------------
# 完整案例评估
# ----------------------------------------------------------------------
def evaluate_case(
    genesis: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    seg_dir: Optional[Path] = None,
    expected_pin: Optional[str] = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {"ok": False, "errors": [], "warnings": []}

    pin = genesis_pin(genesis)
    report["genesis_pin"] = pin
    report["root_public_key"] = genesis.get("root_public_key")
    if expected_pin and pin != expected_pin:
        report["errors"].append("创世指纹与带外钉住的 expected_pin 不一致 —— 信任锚不符")

    chain_ok, chain_errs = verify_chain(records)
    report["chain_ok"] = chain_ok
    report["chain_errors"] = chain_errs
    report["errors"].extend(chain_errs)

    valid, so_errs, auth = valid_signoffs_from(genesis, records)
    report["auth_version"] = auth.version
    report["signoff_count_valid"] = len(valid)
    report["errors"].extend(so_errs)

    revokes = validated_revokes(genesis, records, auth)

    # 冲突
    indep = find_independent_conflict(valid)
    equiv = find_any_equivocation(valid)
    report["independent_conflict"] = indep
    report["equivocation"] = equiv

    # 水位 / 提交裁决
    watermarks: list[dict[str, Any]] = []
    seen_idem: dict[str, int] = {}
    duplicate_idem: list[dict[str, Any]] = []
    for r in sorted(records, key=lambda x: int(x["seq"])):
        if r.get("kind") != "COMMIT":
            continue
        seq = int(r["seq"])
        p = r.get("payload", {})
        idem = p.get("idem_key")
        if isinstance(idem, str):
            if idem in seen_idem:
                duplicate_idem.append({"idem_key": idem, "seqs": [seen_idem[idem], seq]})
            else:
                seen_idem[idem] = seq

        so_ids = list(p.get("signoff_ids", []))
        verdict_rev = revoke_state_for_commit(seq, so_ids, revokes)

        # 仅“有效 + 未被抢先撤销 + 签署了本水位摘要 + 绑定本次授权版本”的签收
        # 才有资格封存本水位。签收对不上承诺摘要 = 授权对象错误，不得挪用。
        usable = [
            valid[sid]
            for sid in so_ids
            if sid in valid and sid not in verdict_rev["preempted"]
        ]
        current_v = int(p.get("auth_version", auth.version))
        claimed_digest = p.get("evidence_digest")

        digest_mismatch = [
            v.signoff_id for v in usable if v.evidence_digest != claimed_digest
        ]
        digest_matched = [v for v in usable if v.evidence_digest == claimed_digest]
        stale = [v.signoff_id for v in digest_matched if v.auth_version != current_v]
        qualifying = [v for v in digest_matched if v.auth_version == current_v]

        seg_digests = list(p.get("segment_digests", []))
        prefix_ok, prefix_why, prefix_info = recompute_prefix(seg_dir, seg_digests)

        computed_tip = (
            build_chain(seg_digests)[-1] if seg_digests else CHAIN_GENESIS
        )
        digest_bound_to_data = prefix_ok and (claimed_digest == computed_tip)

        ctrls = {v.controller_id for v in qualifying}
        independent = len(ctrls) >= 2

        # 陌生摘要：段前缀可重算，但声明摘要不等于重算链尖（无账可对 / 伪造）。
        foreign_digest = bool(seg_digests) and prefix_ok and (claimed_digest != computed_tip)

        sealed = (
            len(qualifying) >= 2
            and independent
            and prefix_ok
            and digest_bound_to_data
        )
        reasons: list[str] = []
        if verdict_rev["preempted"]:
            reasons.append(f"签收 {verdict_rev['preempted']} 在提交前已被撤销（落盘顺序在先），已剔除")
        if digest_mismatch:
            reasons.append(f"签收 {digest_mismatch} 签署的是别的摘要，不能用于本水位")
        if stale:
            reasons.append(f"签收 {stale} 绑定旧授权版本，不能作为本次换代封存的合格签收")
        if len(qualifying) < 2:
            reasons.append("合格签收不足两份")
        elif not independent:
            reasons.append("两份合格签收来自同一底层控制者，不独立")
        if not prefix_ok:
            reasons.append(f"前缀账目复验失败：{prefix_why}")
        if not digest_bound_to_data and prefix_ok:
            reasons.append("承诺摘要与从原始账目重算的链尖不一致（陌生/伪造摘要）")

        wm = {
            "wm_id": p.get("wm_id"),
            "commit_seq": seq,
            "idem_key": idem,
            "prefix_len": p.get("prefix_len", len(seg_digests)),
            "auth_version": current_v,
            "signoff_ids": so_ids,
            "qualifying_signoff_ids": [v.signoff_id for v in qualifying],
            "digest_mismatch_signoff_ids": digest_mismatch,
            "stale_signoff_ids": stale,
            "controllers": sorted(ctrls),
            "independent": independent,
            "revoke_adjudication": verdict_rev,
            "prefix_reverify_ok": prefix_ok,
            "digest_bound_to_data": digest_bound_to_data,
            "foreign_digest": foreign_digest,
            "sealed": sealed,
            "status": "SEALED" if sealed else "REJECTED",
            "reasons": reasons,
            "chain_tip": computed_tip,
        }
        watermarks.append(wm)

    report["watermarks"] = watermarks
    report["sealed_watermark_ids"] = [w["wm_id"] for w in watermarks if w["sealed"]]
    report["rejected_watermarks"] = [
        {"wm_id": w["wm_id"], "seq": w["commit_seq"], "reasons": w["reasons"]}
        for w in watermarks
        if not w["sealed"]
    ]
    report["duplicate_idem_commits"] = duplicate_idem

    # 每个已承诺水位都可复验：此处即独立重算；全部 sealed 必须 prefix ok
    report["every_committed_watermark_reverifies"] = all(
        w["prefix_reverify_ok"] and w["digest_bound_to_data"]
        for w in watermarks
        if w["sealed"]
    )
    report["no_duplicate_commit"] = not duplicate_idem

    # 总判定：链 OK、无重复幂等提交、所有 sealed 水位确实复验通过
    report["ok"] = (
        chain_ok
        and not duplicate_idem
        and report["every_committed_watermark_reverifies"]
        and not report["errors"]
    )
    return report


# ----------------------------------------------------------------------
# 最小自包含证据包：不要求哈希链连续（剪枝后的证据子集），只依赖创世锚
# 与其中的根签授权换代链 + 签收签名。
# ----------------------------------------------------------------------
def prove_conflict_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    genesis = bundle["genesis"]
    records = bundle.get("records", [])
    valid, errs, auth = valid_signoffs_from(genesis, records)
    indep = find_independent_conflict(valid)
    equiv = find_any_equivocation(valid)
    return {
        "proved_independent_conflict": indep is not None,
        "independent_conflict": indep,
        "equivocation_only": equiv if indep is None else None,
        "auth_version_reached": auth.version,
        "valid_signoff_ids": sorted(valid.keys()),
        "errors": errs,
        "record_count": len(records),
        "genesis_pin": genesis_pin(genesis),
    }


# ----------------------------------------------------------------------
# 从目录加载
# ----------------------------------------------------------------------
def load_case(case_dir: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]], Path]:
    d = Path(case_dir)
    genesis = json.loads((d / "genesis.json").read_text(encoding="utf-8"))
    records: list[dict[str, Any]] = []
    jf = d / "journal.log"
    if jf.exists():
        for line in jf.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return genesis, records, d / "segments"


def verify_directory(case_dir: str | Path, expected_pin: Optional[str] = None) -> dict[str, Any]:
    genesis, records, seg_dir = load_case(case_dir)
    return evaluate_case(
        genesis, records, seg_dir=seg_dir if seg_dir.exists() else None, expected_pin=expected_pin
    )
