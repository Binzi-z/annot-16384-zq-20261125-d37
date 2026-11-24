#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键离线封存审计：自检 + 主案例 + 并发故障 + 穷举最小证据 + 6 万条实测。

运行（Windows 原生 Python 3.12，仅标准库）：

    py -3.12 run_audit.py

产物：
    artifacts/audit_report.json     全量机器结果
    artifacts/AUDIT_REPORT.md       人读报告（含实测访问范围对照）
    artifacts/case_main/            主审计案例（可用 verify_audit.py 独立复验）
    artifacts/minimal_conflict_proof.json  最早最小独立冲突证据包
    artifacts/case_enum|race_*|case_receipt|bench60k/ ...

进程退出码 0 表示所有关键不变量自检通过。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
sys.path.insert(0, str(ROOT))

from sealaudit.bench60k import run_benchmark  # noqa: E402
from sealaudit.ed25519_native import self_test as ed_self_test  # noqa: E402
from sealaudit.enummine import run_enumeration  # noqa: E402
from sealaudit.maincase import build_main_case  # noqa: E402
from sealaudit.race import run_receipt_loss_and_restart, run_revoke_commit_ordering  # noqa: E402
from sealaudit.verifier import verify_directory  # noqa: E402


class Checks:
    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []

    def expect(self, name: str, cond: bool, detail: object = "") -> bool:
        self.items.append({"name": name, "pass": bool(cond), "detail": detail})
        print(f"[{'PASS' if cond else 'FAIL'}] {name}" + ("" if cond else f"  -> {detail}"))
        return bool(cond)

    @property
    def all_pass(self) -> bool:
        return all(x["pass"] for x in self.items)


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, str(ROOT / "verify_audit.py"), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=120,
    )


def render_markdown(report: dict) -> str:
    c = report["checks"]
    main = report["main_case"]["verifier"]
    mine = report["enumeration"]["mining"]
    enum = report["enumeration"]["enumeration"]
    bench = report["benchmark"]
    race = report["race"]

    def yn(b: bool) -> str:
        return "是" if b else "否"

    lines: list[str] = []
    lines.append("# 封存证据多方签收 / 回滚审计 — 运行报告\n")
    lines.append(f"- 运行时间戳(逻辑)：run-{report['run_id']}")
    lines.append(f"- Python：{report['python']}")
    lines.append(f"- Ed25519 RFC8032 自检：{'通过' if report['ed25519_selftest'] else '失败'}")
    lines.append(f"- 关键自检：{sum(x['pass'] for x in c)}/{len(c)} 通过\n")

    lines.append("## 1. 独立验证主案例 `artifacts/case_main`\n")
    lines.append(f"- 创世 pin：`{main.get('genesis_pin')}`")
    lines.append(f"- 日志哈希链完整：{yn(main['chain_ok'])}")
    lines.append(f"- 重放授权版本：v{main['auth_version']}")
    lines.append(f"- 无重复幂等提交：{yn(main['no_duplicate_commit'])}")
    lines.append(f"- 每个已承诺水位均可复验：{yn(main['every_committed_watermark_reverifies'])}\n")
    lines.append("| seq | 水位 | 裁决 | 陌生摘要 | 撤销抢先 | 说明 |")
    lines.append("|---:|---|---|---|---|---|")
    for w in main["watermarks"]:
        lines.append(
            f"| {w['commit_seq']} | {w['wm_id']} | {w['status']} | "
            f"{'是' if w['foreign_digest'] else ''} | "
            f"{'是' if w['revoke_adjudication']['preempted'] else ''} | "
            f"{'；'.join(w['reasons'])} |"
        )

    ic = main.get("independent_conflict")
    if ic:
        lines.append("\n### 同一编号不同摘要（两个底层独立控制者）\n")
        lines.append(f"- 证据编号：`{ic['evidence_id']}`")
        lines.append(f"- 摘要 A：`{ic['digest_a']}` by `{ic['controllers'][0]}` @seq {ic['signoff_seqs'][0]}")
        lines.append(f"- 摘要 B：`{ic['digest_b']}` by `{ic['controllers'][1]}` @seq {ic['signoff_seqs'][1]}\n")

    lines.append("## 2. 小样本穷举与最早最小独立冲突证据\n")
    lines.append(f"- 穷举签收子集数：{enum['total_subsets']}（6 条签收的幂集，含空集，共 2^6=64）")
    lines.append(f"- 其中可独立证明冲突的子集：{enum['subsets_proving_independent_conflict']}")
    lines.append(f"- 仅能证明同控矛盾（不独立）的子集：{enum['subsets_only_same_controller_equivocation']}")
    lines.append(f"- 可在 v1 封存的组合数：{enum['subsets_sealable_v1']}；v2：{enum['subsets_sealable_v2']}")
    lines.append(f"- 最早可独立证明冲突的落盘 seq：**{mine['earliest_provable_at_seq']}**")
    lines.append(f"- 最小证据记录 seq：`{mine['minimal_record_seqs']}`，共 **{mine['minimal_record_count']}** 条")
    lines.append(f"- 留一法验证真正最小：{yn(mine['truly_minimal_under_leave_one_out'])}")
    lines.append(f"- 证据包独立复验通过：{yn(mine['bundle_independent_verification']['proved'])}\n")
    lines.append("最小证据包已写入 `artifacts/minimal_conflict_proof.json`，可用：")
    lines.append("`py -3.12 verify_audit.py --bundle artifacts/minimal_conflict_proof.json` 复验。\n")

    lines.append("## 3. 两线程 / Barrier / 故障注入：撤销抢先与回执丢失\n")
    rf, cf = race["ordering"]["revoke_first"], race["ordering"]["commit_first"]
    lines.append("### 3.1 撤销 vs 提交按落盘顺序裁决\n")
    lines.append("| 交错 | REVOKE seq | COMMIT seq | 裁决 | 被抢先撤销签收 |")
    lines.append("|---|---:|---:|---|---|")
    lines.append(
        f"| 撤销抢先 | {rf['seq_by_kind'].get('REVOKE')} | {rf['seq_by_kind'].get('COMMIT')} "
        f"| **{rf['wm_status']}** | {rf['revoke_adjudication']['preempted']} |"
    )
    lines.append(
        f"| 提交抢先(对照) | {cf['seq_by_kind'].get('REVOKE')} | {cf['seq_by_kind'].get('COMMIT')} "
        f"| **{cf['wm_status']}** | 抢先={cf['revoke_adjudication']['preempted']}，"
        f"迟到={cf['revoke_adjudication']['late']} |"
    )
    rc = race["receipt"]
    lines.append("\n### 3.2 回执丢失 + 重启不重复提交 / 不接受陌生摘要\n")
    lines.append(f"- 两线程结果：`{rc['thread_outcomes']}`")
    lines.append(f"- 故障后内存 idem seq：{rc['idem_seq_after_fault']}；重启重放 idem seq：{rc['replayed_idem_seq_after_restart']}")
    lines.append(f"- 重启后首次重试是否新建提交：{rc['restart_retry_created_new']}（应为 False）")
    lines.append(f"- 该 idem 的 COMMIT 总数始终为 1：{yn(rc['single_commit_for_idem'])}")
    lines.append(f"- 独立验证器判定无重复提交：{yn(rc['verifier_no_duplicate_commit'])}")
    lines.append(f"- 诚实节点拒绝陌生摘要：{rc['honest_node_rejects_foreign']['accepted'] is False}")
    lines.append(f"- 强写的陌生摘要 COMMIT 被验证器标记 foreign={rc['verifier_flags_foreign']}、封存={rc['rogue_wm_sealed']}（应为 False）\n")

    lines.append("## 4. 60000 条合成账目：补齐一段 vs 逐段全量核验\n")
    f = bench["full_reverify"]
    b = bench["fill_one_segment_prefix_extension"]
    m = bench["one_segment_merkle_inclusion"]
    lines.append(f"- 总条目 {bench['entries_total']}，每段 {bench['segment_size']}，共 {bench['segment_count']} 段；抽测第 {bench['target_segment']} 段")
    lines.append(f"- 三条路径结果完全一致：**{yn(bench['all_paths_agree'])}**\n")
    lines.append("| 核验方式 | 读原始条目 | 打开段文件 | 读字节 | Merkle/证明哈希 | 耗时(s) | 与全量结果一致 |")
    lines.append("|---|---:|---:|---:|---:|---:|---|")
    lines.append(f"| 逐段全量重核 | {f['raw_entries_read']} | {f['segment_files_opened']} | {f['bytes_read']} | 0 | {f['seconds']} | {yn(f['result_matches_build'])} |")
    lines.append(f"| 补齐一段(前缀延伸) | {b['raw_entries_read']} | {b['segment_files_opened']} | {b['bytes_read']} | {b['headers_read']} 链尖 | {b['seconds']} | {yn(b['matches_full_result'])} |")
    lines.append(f"| 单段 Merkle 包含证明 | {m['raw_entries_read']} | {m['segment_files_opened']} | {m['bytes_read']} | {m['proof_hashes_read']} | {m['seconds']} | {yn(m['matches_full_result'])} |")
    lines.append(
        f"\n访问范围：原始条目 {bench['access_ratio_raw_entries_full_vs_fill']}×、"
        f"段文件 {bench['access_ratio_files_full_vs_fill']}×、"
        f"字节 {bench['byte_ratio_full_vs_fill']}× 的差距（全量/补齐）。"
    )
    lines.append(f"\n> {bench['note']}\n")

    lines.append("## 5. 独立进程 CLI 复验\n")
    lines.append(f"- `verify_audit.py --case artifacts/case_main` 退出码：{report['cli']['case_returncode']}")
    lines.append(f"- `verify_audit.py --bundle ...minimal_conflict_proof.json` 退出码：{report['cli']['bundle_returncode']}\n")
    lines.append("---\n_本报告由 `run_audit.py` 用本机 Python 3.12 标准库离线生成，所有数字为当次实测。_\n")
    return "\n".join(lines)


def main() -> int:
    ART.mkdir(parents=True, exist_ok=True)
    chk = Checks()
    t_start = time.perf_counter()

    # 0) 加密自检
    ed_ok = True
    try:
        ed_self_test()
        print("[PASS] Ed25519 RFC8032 已知答案自检")
    except Exception as e:  # noqa: BLE001
        ed_ok = False
        print(f"[FAIL] Ed25519 自检: {e!r}")
    chk.expect("Ed25519 RFC8032 自检通过", ed_ok)

    # 1) 主案例 + 独立验证
    built = build_main_case(ART)
    main_rep = verify_directory(built["case_dir"], expected_pin=built["genesis_pin"])
    sealed = set(main_rep["sealed_watermark_ids"])
    chk.expect("主案例日志哈希链完整", main_rep["chain_ok"], main_rep["chain_errors"])
    chk.expect("主案例验证总判定 ok", main_rep["ok"], main_rep["errors"])
    chk.expect("恰好封存 WM-1 与 WM-2", sealed == {"WM-1", "WM-2"}, sealed)
    status = {w["wm_id"]: w for w in main_rep["watermarks"]}
    chk.expect("同控双签 WM-NONIND 被拒", status["WM-NONIND"]["sealed"] is False)
    chk.expect("缺段 WM-GAP-4 被拒且原因含复验失败",
               status["WM-GAP-4"]["sealed"] is False
               and not status["WM-GAP-4"]["prefix_reverify_ok"])
    chk.expect("陌生摘要 WM-FOREIGN 被识别并拒绝",
               status["WM-FOREIGN"]["foreign_digest"] is True
               and status["WM-FOREIGN"]["sealed"] is False)
    chk.expect("发现独立控制者同号异摘要冲突",
               main_rep["independent_conflict"] is not None)
    chk.expect("每个已承诺水位均可复验",
               main_rep["every_committed_watermark_reverifies"] is True)
    chk.expect("主案例无重复提交", main_rep["no_duplicate_commit"] is True)
    chk.expect("WM-2 含迟到旧签但由两张 v2 独立签封存",
               status["WM-2"]["sealed"] is True
               and "LATE-wang-v1" in status["WM-2"]["stale_signoff_ids"]
               and len(status["WM-2"]["qualifying_signoff_ids"]) == 2,
               status["WM-2"])

    # 2) 穷举 + 最小证据
    enum_res = run_enumeration(ART)
    mine = enum_res["mining"]
    chk.expect("穷举覆盖 64 个子集", enum_res["enumeration"]["total_subsets"] == 64)
    chk.expect("最早冲突证明出现在 seq=3",
               mine["earliest_provable_at_seq"] == 3,
               mine["earliest_provable_at_seq"])
    chk.expect("最小证据仅 2 条签收记录",
               mine["minimal_record_count"] == 2, mine["minimal_record_seqs"])
    chk.expect("留一法确认最小", mine["truly_minimal_under_leave_one_out"] is True)
    chk.expect("最小证据包通过独立复验",
               mine["bundle_independent_verification"]["proved"] is True,
               mine["bundle_independent_verification"]["errors"])

    # 3) 并发 / 故障
    ordering = run_revoke_commit_ordering(ART)
    chk.expect("撤销抢先 -> 提交被裁决 REJECTED",
               ordering["revoke_first"]["wm_status"] == "REJECTED"
               and "R-S1" in ordering["revoke_first"]["revoke_adjudication"]["preempted"],
               ordering["revoke_first"])
    chk.expect("提交抢先 -> 水位 SEALED，迟到撤销不推翻",
               ordering["commit_first"]["wm_status"] == "SEALED"
               and ordering["commit_first"]["revoke_adjudication"]["preempted"] == []
               and "R-S1" in ordering["commit_first"]["revoke_adjudication"]["late"],
               ordering["commit_first"])

    receipt = run_receipt_loss_and_restart(ART)
    outs = [o["out"] for o in receipt["thread_outcomes"]]
    chk.expect("两同 idem 线程：一回执丢失、一幂等命中",
               any(x.startswith("receipt_lost") for x in outs)
               and any(o.get("created") is False for o in receipt["thread_outcomes"] if o["out"] == "ok"),
               outs)
    chk.expect("重启重放恢复同一 idem seq",
               receipt["replayed_idem_seq_after_restart"] == receipt["idem_seq_after_fault"])
    chk.expect("重启后重试不新建提交", receipt["restart_retry_created_new"] is False)
    chk.expect("该 idem 始终只有一条 COMMIT", receipt["single_commit_for_idem"] is True)
    chk.expect("验证器确认无重复提交", receipt["verifier_no_duplicate_commit"] is True)
    chk.expect("诚实节点拒绝陌生摘要",
               receipt["honest_node_rejects_foreign"]["accepted"] is False)
    chk.expect("强写陌生摘要被验证器标记且不封存",
               receipt["verifier_flags_foreign"] is True
               and receipt["rogue_wm_sealed"] is False)

    # 4) 60k 基准
    bench = run_benchmark(ART)
    chk.expect("60000 条 / 60 段",
               bench["entries_total"] == 60000 and bench["segment_count"] == 60)
    chk.expect("补齐/Merkle/全量三条路径结果一致", bench["all_paths_agree"] is True)
    chk.expect("补齐一段仅读 1000 条",
               bench["fill_one_segment_prefix_extension"]["raw_entries_read"] == 1000)
    chk.expect("全量核验读 60000 条",
               bench["full_reverify"]["raw_entries_read"] == 60000)

    # 5) 独立进程 CLI
    case_cli = run_cli(["--case", str(built["case_dir"]), "--pin", built["genesis_pin"]])
    bundle_path = ART / "minimal_conflict_proof.json"
    bundle_cli = run_cli(["--bundle", str(bundle_path)])
    chk.expect("独立 CLI 验证 case_main 退出码 0",
               case_cli.returncode == 0, case_cli.stderr[-500:])
    chk.expect("独立 CLI 验证最小证据包退出码 0",
               bundle_cli.returncode == 0, bundle_cli.stderr[-500:])

    elapsed = round(time.perf_counter() - t_start, 3)

    report = {
        "run_id": time.strftime("%Y%m%d-%H%M%S"),
        "python": sys.version.split()[0],
        "elapsed_seconds": elapsed,
        "ed25519_selftest": ed_ok,
        "checks": chk.items,
        "all_checks_pass": chk.all_pass,
        "main_case": {
            "dir": str(built["case_dir"]),
            "genesis_pin": built["genesis_pin"],
            "continuous_trusted_prefix_len": built["continuous_trusted_prefix_len"],
            "missing_segment_index": built["missing_segment_index"],
            "verifier": main_rep,
        },
        "enumeration": enum_res,
        "race": {"ordering": ordering, "receipt": receipt},
        "benchmark": bench,
        "cli": {
            "case_returncode": case_cli.returncode,
            "bundle_returncode": bundle_cli.returncode,
            "case_stdout_tail": case_cli.stdout[-1200:],
            "bundle_stdout_head": bundle_cli.stdout[:1200:],
        },
    }

    (ART / "audit_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    md = render_markdown(report)
    (ART / "AUDIT_REPORT.md").write_text(md, encoding="utf-8")
    (ROOT / "REPORT.md").write_text(md, encoding="utf-8")

    print("\n" + "=" * 64)
    print(f"自检 {sum(x['pass'] for x in chk.items)}/{len(chk.items)} 通过，用时 {elapsed}s")
    print(f"机器报告: {ART / 'audit_report.json'}")
    print(f"人读报告: {ART / 'AUDIT_REPORT.md'}  (并复制到根 REPORT.md)")
    print("=" * 64)
    return 0 if chk.all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
