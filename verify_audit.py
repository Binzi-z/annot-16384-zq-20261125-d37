#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线独立验证器入口（仅依赖 Python 3.12 标准库与 sealaudit.verifier 只读逻辑）。

用法（Windows，原生 Python 3.12）：

    py -3.12 verify_audit.py --case artifacts/case_main
    py -3.12 verify_audit.py --case artifacts/case_main --pin sha256:...
    py -3.12 verify_audit.py --bundle artifacts/minimal_conflict_proof.json --json

退出码：0 验证通过；2 案例验证未通过；3 证据包未能证明冲突；4 用法/读取错误。
本进程不导入任何写入侧 / 并发 / 基准代码，体现“独立验证”。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# 允许从仓库根直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

from sealaudit.verifier import prove_conflict_bundle, verify_directory  # noqa: E402


def _print_case_human(rep: dict) -> None:
    print("=" * 72)
    print("独立离线验证报告")
    print("=" * 72)
    print(f"创世信任锚指纹 pin : {rep.get('genesis_pin')}")
    print(f"日志哈希链完整      : {rep.get('chain_ok')}")
    print(f"重放后授权版本      : v{rep.get('auth_version')}")
    print(f"有效签收数          : {rep.get('signoff_count_valid')}")
    print(f"无重复幂等提交      : {rep.get('no_duplicate_commit')}")
    print(f"已承诺水位全部可复验: {rep.get('every_committed_watermark_reverifies')}")
    ic = rep.get("independent_conflict")
    if ic:
        print("-" * 72)
        print("[冲突] 发现两个底层独立控制者对同一编号给出不同摘要：")
        print(f"  证据编号 : {ic['evidence_id']}")
        print(f"  摘要 A   : {ic['digest_a']}  (seq {ic['signoff_seqs'][0]}, {ic['controllers'][0]})")
        print(f"  摘要 B   : {ic['digest_b']}  (seq {ic['signoff_seqs'][1]}, {ic['controllers'][1]})")
    eq = rep.get("equivocation")
    if eq and not ic:
        print(f"[弱冲突] 同一控制者自相矛盾（不独立）：{eq['evidence_id']}")
    print("-" * 72)
    print("水位裁决：")
    for w in rep.get("watermarks", []):
        mark = "SEALED  " if w["sealed"] else "REJECTED"
        extra = ""
        if w.get("foreign_digest"):
            extra = " [陌生摘要]"
        if w["revoke_adjudication"]["preempted"]:
            extra += " [撤销抢先]"
        print(f"  seq {w['commit_seq']:>2}  {w['wm_id']:<16} {mark}{extra}")
        for r in w.get("reasons", []):
            print(f"        - {r}")
    if rep.get("errors"):
        print("-" * 72)
        print("错误：")
        for e in rep["errors"]:
            print(f"  ! {e}")
    print("=" * 72)
    print("结论：", "通过（所有 SEALED 水位均可独立复验）" if rep["ok"] else "未通过")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="封存取证摘要的离线独立验证器")
    ap.add_argument("--case", help="案例目录（含 genesis.json / journal.log / segments/）")
    ap.add_argument("--bundle", help="最小冲突证据包 JSON")
    ap.add_argument("--pin", help="带外钉住的创世 sha256 指纹")
    ap.add_argument("--json", action="store_true", help="只输出机器 JSON")
    args = ap.parse_args(argv)

    if not args.case and not args.bundle:
        ap.print_help()
        return 4

    try:
        if args.bundle:
            bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
            res = prove_conflict_bundle(bundle)
            if args.json:
                print(json.dumps(res, ensure_ascii=False, indent=2))
            else:
                print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0 if res["proved_independent_conflict"] else 3

        rep = verify_directory(args.case, expected_pin=args.pin)
        if args.json:
            print(json.dumps(rep, ensure_ascii=False, indent=2, default=str))
        else:
            _print_case_human(rep)
        return 0 if rep["ok"] else 2
    except FileNotFoundError as e:
        print(f"读取失败：{e}", file=sys.stderr)
        return 4
    except Exception as e:  # 独立验证器：任何异常都视为验证/用法失败
        print(f"验证器错误：{type(e).__name__}: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
