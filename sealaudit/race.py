"""并发与故障注入：两线程 + Barrier 复现“撤销抢先”和“回执丢失”。

所有裁决最终都交给 verifier 按日志 seq（== 落盘顺序）独立判定；本模块只负责
确定性地制造两种交错，并在“重启”（新建 Journal 重放磁盘）后验证：

* 同一 idem_key 重试绝不产生第二条 COMMIT；
* 陌生摘要被诚实节点拒绝、也会被独立验证器标记为 FOREIGN 并不予封存。
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from . import authority as A
from .caseflow import (
    add_revoke,
    add_signoff,
    commit_watermark,
    fresh_dir,
    make_journal,
    standard_genesis,
    write_genesis,
)
from .evidence import build_chain, make_account_entries, segment_digest, write_segment_file
from .journal import ReceiptLost
from .verifier import recompute_prefix, verify_directory

FOREIGN = "sha256:" + "ef" * 32


def _setup(case_dir: Path):
    genesis, keys = standard_genesis()
    write_genesis(case_dir, genesis)
    seg_dir = case_dir / "segments"
    seg_dir.mkdir(parents=True, exist_ok=True)
    entries = make_account_entries(30, seed=4242)
    seg = entries[:30]
    d0 = segment_digest(seg)
    write_segment_file(seg_dir, 0, seg)
    tip = build_chain([d0])[-1]

    j = make_journal(case_dir)
    add_signoff(
        j, keys["ctrl-alpha"], signoff_id="R-S1", evidence_id="WM-RACE",
        evidence_digest=tip, auth_version=1, controller_id="ctrl-alpha",
        person_id="p-wang", logical_clock=1,
    )
    add_signoff(
        j, keys["ctrl-beta"], signoff_id="R-S2", evidence_id="WM-RACE",
        evidence_digest=tip, auth_version=1, controller_id="ctrl-beta",
        person_id="p-li", logical_clock=2,
    )
    return genesis, keys, j, seg_dir, d0, tip


def _run_two_threads(fn_a, fn_b) -> None:
    barrier = threading.Barrier(2)
    errs: list[BaseException] = []

    def wrap(fn):
        def _w():
            try:
                barrier.wait(timeout=10)
                fn()
            except BaseException as e:  # 收集而不是静默
                errs.append(e)
        return _w

    ta = threading.Thread(target=wrap(fn_a), name="actor-a")
    tb = threading.Thread(target=wrap(fn_b), name="actor-b")
    ta.start()
    tb.start()
    ta.join(timeout=20)
    tb.join(timeout=20)
    alive = [t.name for t in (ta, tb) if t.is_alive()]
    if alive:
        raise RuntimeError(f"线程超时未结束: {alive}")
    if errs:
        # ReceiptLost 在回执场景由调用方自行捕获；走到这里的都是意外错误
        raise errs[0]


def run_revoke_commit_ordering(art_dir: Path) -> dict[str, Any]:
    results: dict[str, Any] = {}

    # ---- 情形 1：撤销抢先落盘 --------------------------------------------
    dir1 = fresh_dir(art_dir / "race_revoke_first")
    _, keys, j1, _, d0_1, tip1 = _setup(dir1)
    revoke_done = threading.Event()

    def fault_preempt(stage, journal, ctx):
        kind = ctx.get("kind")
        if stage == "before_append" and kind == "COMMIT":
            if not revoke_done.wait(timeout=10):
                raise TimeoutError("等待撤销落盘超时")
        if stage == "after_fsync" and kind == "REVOKE":
            revoke_done.set()

    j1.fault = fault_preempt

    def do_revoke():
        add_revoke(
            j1, keys["ctrl-alpha"], revoke_id="REV-preempt",
            target_signoff_id="R-S1", controller_id="ctrl-alpha",
            reason="签收密钥疑似失控，立即撤销",
        )

    def do_commit():
        commit_watermark(
            j1, idem_key="idem-race-preempt", wm_id="WM-PREEMPT", prefix_len=1,
            auth_version=1, evidence_digest=tip1, segment_digests=[d0_1],
            signoff_ids=["R-S1", "R-S2"],
        )

    _run_two_threads(do_revoke, do_commit)
    results["revoke_first"] = _collect(dir1, "WM-PREEMPT", "idem-race-preempt")

    # ---- 情形 2：提交抢先落盘（对照：顺序反过来，裁决也反过来） ------------
    dir2 = fresh_dir(art_dir / "race_commit_first")
    _, keys2, j2, _, d0_2, tip2 = _setup(dir2)
    commit_done = threading.Event()

    def fault_commit_first(stage, journal, ctx):
        kind = ctx.get("kind")
        if stage == "before_append" and kind == "REVOKE":
            if not commit_done.wait(timeout=10):
                raise TimeoutError("等待提交落盘超时")
        if stage == "after_fsync" and kind == "COMMIT":
            commit_done.set()

    j2.fault = fault_commit_first

    def do_revoke2():
        add_revoke(
            j2, keys2["ctrl-alpha"], revoke_id="REV-late",
            target_signoff_id="R-S1", controller_id="ctrl-alpha",
            reason="迟到的撤销",
        )

    def do_commit2():
        commit_watermark(
            j2, idem_key="idem-race-late", wm_id="WM-LATE-REVOKE", prefix_len=1,
            auth_version=1, evidence_digest=tip2, segment_digests=[d0_2],
            signoff_ids=["R-S1", "R-S2"],
        )

    _run_two_threads(do_commit2, do_revoke2)
    results["commit_first"] = _collect(dir2, "WM-LATE-REVOKE", "idem-race-late")
    return results


def _collect(case_dir: Path, wm_id: str, idem: str) -> dict[str, Any]:
    rep = verify_directory(case_dir)
    seqs = {
        r["kind"]: r["seq"]
        for r in [
            json_loads_line(case_dir / "journal.log", k)
            for k in ("REVOKE", "COMMIT")
        ]
        if r
    }
    wm = next((w for w in rep["watermarks"] if w["wm_id"] == wm_id), None)
    commit_count = sum(
        1 for line in (case_dir / "journal.log").read_text(encoding="utf-8").splitlines()
        if '"COMMIT"' in line and idem in line
    )
    return {
        "case_dir": str(case_dir),
        "seq_by_kind": seqs,
        "commit_records_for_idem": commit_count,
        "wm_status": None if wm is None else wm["status"],
        "sealed": None if wm is None else wm["sealed"],
        "revoke_adjudication": None if wm is None else wm["revoke_adjudication"],
        "controllers": None if wm is None else wm["controllers"],
        "reasons": None if wm is None else wm["reasons"],
        "verifier_ok": rep["ok"],
    }


def json_loads_line(path: Path, kind: str):
    import json

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("kind") == kind:
            return obj
    return None


def run_receipt_loss_and_restart(art_dir: Path) -> dict[str, Any]:
    case_dir = fresh_dir(art_dir / "case_receipt")
    _, keys, j, seg_dir, d0, tip = _setup(case_dir)

    flag = {"lost_done": False}
    flag_lock = threading.Lock()

    def receipt_fault(stage, journal, ctx):
        if stage == "after_fsync" and ctx.get("kind") == "COMMIT":
            with flag_lock:
                if not flag["lost_done"]:
                    flag["lost_done"] = True
                    raise ReceiptLost("故障注入：COMMIT 已 fsync，但回执在返回途中丢失")

    j.fault = receipt_fault
    barrier = threading.Barrier(2)
    outcomes: list[dict[str, Any]] = []
    olock = threading.Lock()
    PAYLOAD = dict(
        idem_key="idem-receipt-once", wm_id="WM-RECEIPT", prefix_len=1,
        auth_version=1, evidence_digest=tip, segment_digests=[d0],
        signoff_ids=["R-S1", "R-S2"],
    )

    def worker():
        try:
            barrier.wait(timeout=10)
            rec, created = commit_watermark(j, **PAYLOAD)
            with olock:
                outcomes.append({"out": "ok", "seq": rec.seq, "created": created})
        except ReceiptLost:
            with olock:
                outcomes.append({"out": "receipt_lost_after_durable_commit"})
        except BaseException as e:  # noqa: BLE001
            with olock:
                outcomes.append({"out": "error", "error": repr(e)})

    t1 = threading.Thread(target=worker, name="client-1")
    t2 = threading.Thread(target=worker, name="client-2")
    t1.start(); t2.start()
    t1.join(timeout=20); t2.join(timeout=20)

    seq_after_loss = j.idem_seq("idem-receipt-once")
    commits_before_restart = len(j.find("COMMIT"))

    # ---- 模拟进程重启：新建 Journal 从磁盘重放，故障解除 -------------------
    j_restart = make_journal(case_dir, fault=None)
    replayed_idem_seq = j_restart.idem_seq("idem-receipt-once")
    rec_retry, created_retry = commit_watermark(j_restart, **PAYLOAD)
    commits_after_retry = len(j_restart.find("COMMIT"))

    # 另一个并发迟到者/重启后再次重试，仍应幂等
    rec_retry2, created_retry2 = commit_watermark(j_restart, **PAYLOAD)

    # ---- 诚实节点：重启后只接受能从段账目重算的摘要 -----------------------
    prefix_ok, why, _ = recompute_prefix(seg_dir, [d0])
    expected_tip = build_chain([d0])[-1]

    def honest_seal_request(presented_digest: str) -> dict[str, Any]:
        ok, reason, _ = recompute_prefix(seg_dir, [d0])
        if not ok:
            return {"accepted": False, "reason": reason}
        if presented_digest != expected_tip:
            return {
                "accepted": False,
                "reason": "陌生摘要：与从原始账目重算的链尖不符，拒绝封存且不写 COMMIT",
            }
        return {"accepted": True}

    honest_foreign = honest_seal_request(FOREIGN)
    commits_before_rogue = len(j_restart.find("COMMIT"))

    # ---- 即使有失控节点强写陌生摘要 COMMIT，独立验证器也必须否决 -----------
    rogue_rec, rogue_created = j_restart.append_idempotent(
        "idem-rogue-foreign",
        "COMMIT",
        {
            "wm_id": "WM-ROGUE-FOREIGN",
            "prefix_len": 1,
            "auth_version": 1,
            "evidence_digest": FOREIGN,
            "segment_digests": [d0],
            "signoff_ids": ["R-S1", "R-S2"],
        },
    )
    rep = verify_directory(case_dir)
    rogue_wm = next(w for w in rep["watermarks"] if w["wm_id"] == "WM-ROGUE-FOREIGN")
    receipt_wm = next(w for w in rep["watermarks"] if w["wm_id"] == "WM-RECEIPT")

    return {
        "case_dir": str(case_dir),
        "thread_outcomes": outcomes,
        "idem_seq_after_fault": seq_after_loss,
        "commits_before_restart": commits_before_restart,
        "replayed_idem_seq_after_restart": replayed_idem_seq,
        "restart_retry_created_new": created_retry,
        "restart_retry_seq": rec_retry.seq,
        "second_retry_created_new": created_retry2,
        "second_retry_seq": rec_retry2.seq,
        "commits_after_restart_retry": commits_after_retry,
        "single_commit_for_idem": commits_after_retry == 1,
        "honest_node_rejects_foreign": honest_foreign,
        "commits_before_rogue": commits_before_rogue,
        "rogue_commit_seq": rogue_rec.seq,
        "rogue_created": rogue_created,
        "verifier_flags_foreign": rogue_wm["foreign_digest"],
        "rogue_wm_sealed": rogue_wm["sealed"],
        "rogue_reasons": rogue_wm["reasons"],
        "receipt_wm_sealed": receipt_wm["sealed"],
        "verifier_no_duplicate_commit": rep["no_duplicate_commit"],
        "verifier_ok": rep["ok"],
    }
