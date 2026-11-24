"""构建主审计案例：一份分批封存的合成取证摘要。

集中复现题面中的业务情形：

* 同一证据编号 EV-FORENSIC-0007 在交换中出现两个不同摘要（两个独立控制者背书）；
* 一次底层控制者更换（授权 v1→v2），一份旧代签收迟到、跨越换代；
* 合规“换代签收”绑定证据摘要 + 当前授权版本 v2；
* 两名人员同受 ctrl-alpha 控制时，签收不独立 → 封存被拒；
* 第 3 段缺失 → 任何越过缺口的水位都无法复验，只有最后连续可信前缀可封存；
* 陌生摘要（与重算链尖不符）被独立验证器标记并拒绝。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .caseflow import (
    add_rotation,
    add_signoff,
    commit_watermark,
    fresh_dir,
    make_journal,
    standard_genesis,
    write_genesis,
)
from .evidence import (
    build_chain,
    chunk_segments,
    make_account_entries,
    segment_digest,
    write_segment_file,
    write_header_file,
)
from .verifier import genesis_pin

EVIDENCE_ID = "EV-FORENSIC-0007"
DIGEST_A = "sha256:" + "a1" * 32
DIGEST_B = "sha256:" + "b2" * 32
FOREIGN_DIGEST = "sha256:" + "de" * 32


def build_main_case(art_dir: Path) -> dict[str, Any]:
    case_dir = fresh_dir(art_dir / "case_main")
    seg_dir = case_dir / "segments"
    seg_dir.mkdir(parents=True, exist_ok=True)

    genesis, keys = standard_genesis()
    write_genesis(case_dir, genesis)
    j = make_journal(case_dir)

    # ---- 合成账目：250 条 / 每段 50 / 共 5 段；第 3 段原始文件缺失 ---------
    entries = make_account_entries(250, seed=20261125)
    segments = chunk_segments(entries, 50)
    all_digests = [segment_digest(seg) for seg in segments]
    for i, seg in enumerate(segments):
        if i == 3:
            continue  # 故意制造缺段（只有段头摘要，没有原始账目文件）
        write_segment_file(seg_dir, i, seg)
    write_header_file(
        case_dir,
        all_digests,
        {"note": "段头/清单由两名独立控制者钉住；seg_00003 原始件缺失"},
    )

    def tip(prefix_len: int) -> str:
        return build_chain(all_digests[:prefix_len])[-1]

    tip2 = tip(2)
    tip3 = tip(3)
    tip4 = tip(4)

    # ---- 1) 同编号不同摘要：beta 签 A、gamma 签 B（底层独立） --------------
    add_signoff(
        j, keys["ctrl-beta"], signoff_id="CF-A-beta", evidence_id=EVIDENCE_ID,
        evidence_digest=DIGEST_A, auth_version=1, controller_id="ctrl-beta",
        person_id="p-li", logical_clock=11, note="交换副本 A 的摘要",
    )
    add_signoff(
        j, keys["ctrl-gamma"], signoff_id="CF-B-gamma", evidence_id=EVIDENCE_ID,
        evidence_digest=DIGEST_B, auth_version=1, controller_id="ctrl-gamma",
        person_id="p-chen", logical_clock=12, note="交换副本 B 的不同摘要",
    )

    # ---- 2) WM-1：v1 正常双独立签收封存前缀 2 ------------------------------
    add_signoff(
        j, keys["ctrl-alpha"], signoff_id="WM1-wang", evidence_id="WM-1",
        evidence_digest=tip2, auth_version=1, controller_id="ctrl-alpha",
        person_id="p-wang", logical_clock=21,
    )
    add_signoff(
        j, keys["ctrl-beta"], signoff_id="WM1-li", evidence_id="WM-1",
        evidence_digest=tip2, auth_version=1, controller_id="ctrl-beta",
        person_id="p-li", logical_clock=22,
    )
    commit_watermark(
        j, idem_key="idem-wm1", wm_id="WM-1", prefix_len=2, auth_version=1,
        evidence_digest=tip2, segment_digests=all_digests[:2],
        signoff_ids=["WM1-wang", "WM1-li"],
    )

    # ---- 3) 同控不独立：wang 与 zhao 都受 ctrl-alpha 控制 ------------------
    add_signoff(
        j, keys["ctrl-alpha"], signoff_id="NI-wang", evidence_id="WM-NONIND",
        evidence_digest=tip2, auth_version=1, controller_id="ctrl-alpha",
        person_id="p-wang", logical_clock=31,
    )
    add_signoff(
        j, keys["ctrl-alpha"], signoff_id="NI-zhao", evidence_id="WM-NONIND",
        evidence_digest=tip2, auth_version=1, controller_id="ctrl-alpha",
        person_id="p-zhao", logical_clock=32,
    )
    commit_watermark(
        j, idem_key="idem-wm-nonind", wm_id="WM-NONIND", prefix_len=2, auth_version=1,
        evidence_digest=tip2, segment_digests=all_digests[:2],
        signoff_ids=["NI-wang", "NI-zhao"],
    )

    # ---- 4) 控制人更换 alpha -> alpha2，授权 v2 ---------------------------
    add_rotation(
        j, keys["root"], new_version=2, person_id="p-wang",
        old_controller_id="ctrl-alpha", new_controller_id="ctrl-alpha2",
        new_controller_public_hex=keys["ctrl-alpha2"].public_hex,
        effective_note="控制人更换；当前授权版本 v2",
    )

    # ---- 5) 迟到的旧代签收（物理在换代后，仍绑定摘要 + v1） ----------------
    add_signoff(
        j, keys["ctrl-alpha"], signoff_id="LATE-wang-v1", evidence_id="WM-2",
        evidence_digest=tip3, auth_version=1, controller_id="ctrl-alpha",
        person_id="p-wang", logical_clock=40,
        note="迟到：跨越控制人更换，只绑定旧授权 v1",
    )
    # ---- 6) 合规换代签收：新控制者 alpha2，绑定摘要 tip3 + 当前 v2 ----------
    add_signoff(
        j, keys["ctrl-alpha2"], signoff_id="GEN2-wang-v2", evidence_id="WM-2",
        evidence_digest=tip3, auth_version=2, controller_id="ctrl-alpha2",
        person_id="p-wang", logical_clock=41,
        note="换代签收：绑定证据摘要与当前授权版本 v2",
    )
    add_signoff(
        j, keys["ctrl-gamma"], signoff_id="GEN2-chen-v2", evidence_id="WM-2",
        evidence_digest=tip3, auth_version=2, controller_id="ctrl-gamma",
        person_id="p-chen", logical_clock=42,
    )
    commit_watermark(
        j, idem_key="idem-wm2", wm_id="WM-2", prefix_len=3, auth_version=2,
        evidence_digest=tip3, segment_digests=all_digests[:3],
        signoff_ids=["LATE-wang-v1", "GEN2-wang-v2", "GEN2-chen-v2"],
        extra={"note": "附迟到 v1 签收留痕；由两张 v2 独立签收合格封存"},
    )

    # ---- 7) 越缺段：试图封存前缀 4（第 3 段缺失）→ 独立复验必失败 ----------
    # 签收确实签署 tip4 且独立合规，因此唯一失败原因就是缺段导致无法重算。
    add_signoff(
        j, keys["ctrl-alpha2"], signoff_id="GAP-wang-v2", evidence_id="WM-GAP-4",
        evidence_digest=tip4, auth_version=2, controller_id="ctrl-alpha2",
        person_id="p-wang", logical_clock=51,
    )
    add_signoff(
        j, keys["ctrl-gamma"], signoff_id="GAP-chen-v2", evidence_id="WM-GAP-4",
        evidence_digest=tip4, auth_version=2, controller_id="ctrl-gamma",
        person_id="p-chen", logical_clock=52,
    )
    commit_watermark(
        j, idem_key="idem-wm-gap", wm_id="WM-GAP-4", prefix_len=4, auth_version=2,
        evidence_digest=tip4, segment_digests=all_digests[:4],
        signoff_ids=["GAP-wang-v2", "GAP-chen-v2"],
    )

    # ---- 8) 陌生摘要：两名独立控制者甚至为它签了收，但它与账目对不上 -------
    add_signoff(
        j, keys["ctrl-alpha2"], signoff_id="FRN-wang-v2", evidence_id="WM-FOREIGN",
        evidence_digest=FOREIGN_DIGEST, auth_version=2, controller_id="ctrl-alpha2",
        person_id="p-wang", logical_clock=61,
    )
    add_signoff(
        j, keys["ctrl-gamma"], signoff_id="FRN-chen-v2", evidence_id="WM-FOREIGN",
        evidence_digest=FOREIGN_DIGEST, auth_version=2, controller_id="ctrl-gamma",
        person_id="p-chen", logical_clock=62,
    )
    commit_watermark(
        j, idem_key="idem-wm-foreign", wm_id="WM-FOREIGN", prefix_len=2, auth_version=2,
        evidence_digest=FOREIGN_DIGEST, segment_digests=all_digests[:2],
        signoff_ids=["FRN-wang-v2", "FRN-chen-v2"],
        extra={"note": "声称一个与原始账目不匹配的陌生摘要；签名虽真，账目复验否决"},
    )

    return {
        "case_dir": case_dir,
        "genesis_pin": genesis_pin(genesis),
        "digests": {
            "DIGEST_A": DIGEST_A,
            "DIGEST_B": DIGEST_B,
            "FOREIGN_DIGEST": FOREIGN_DIGEST,
            "tip2": tip2,
            "tip3": tip3,
            "tip4": tip4,
        },
        "missing_segment_index": 3,
        "continuous_trusted_prefix_len": 3,
        "entry_count": len(entries),
    }
