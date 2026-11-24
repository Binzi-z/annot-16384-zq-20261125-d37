"""构建一个封存案例目录：genesis.json + journal.log + segments/。

写入侧的便捷封装。独立验证器 verifier.py 不导入本模块。
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Optional

from . import authority as A
from .journal import Journal


def fresh_dir(path: str | Path) -> Path:
    p = Path(path)
    if p.exists():
        shutil.rmtree(p)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_genesis(case_dir: Path, genesis: dict[str, Any]) -> None:
    (case_dir / "genesis.json").write_text(
        json.dumps(genesis, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def make_journal(case_dir: str | Path, fault=None) -> Journal:
    return Journal(Path(case_dir), fault=fault)


def standard_genesis() -> tuple[dict[str, Any], dict[str, A.KeyPair]]:
    """标准小世界：一个根 + 三个底层控制者 + 四名人员（其中 wang/zhao 同控）。"""
    root = A.keypair("root-anchor-2026")
    k_alpha = A.keypair("ctrl-alpha")
    k_beta = A.keypair("ctrl-beta")
    k_gamma = A.keypair("ctrl-gamma")
    k_alpha2 = A.keypair("ctrl-alpha-generation2")  # 换代后的新控制者/新钥

    genesis = {
        "case": "sealed-forensic-summary",
        "root_public_key": root.public_hex,
        "auth_version": 1,
        "controllers": {
            "ctrl-alpha": k_alpha.public_hex,
            "ctrl-beta": k_beta.public_hex,
            "ctrl-gamma": k_gamma.public_hex,
        },
        "persons": {
            "p-wang": {"controller": "ctrl-alpha"},
            "p-zhao": {"controller": "ctrl-alpha"},  # 与 wang 同一底层控制者
            "p-li": {"controller": "ctrl-beta"},
            "p-chen": {"controller": "ctrl-gamma"},
        },
    }
    keys = {
        "root": root,
        "ctrl-alpha": k_alpha,
        "ctrl-beta": k_beta,
        "ctrl-gamma": k_gamma,
        "ctrl-alpha2": k_alpha2,
    }
    return genesis, keys


def add_signoff(
    j: Journal,
    kp: A.KeyPair,
    *,
    signoff_id: str,
    evidence_id: str,
    evidence_digest: str,
    auth_version: int,
    controller_id: str,
    person_id: str,
    logical_clock: int = 0,
    note: str = "",
):
    payload = A.build_signoff(
        kp,
        signoff_id=signoff_id,
        evidence_id=evidence_id,
        evidence_digest=evidence_digest,
        auth_version=auth_version,
        controller_id=controller_id,
        person_id=person_id,
        logical_clock=logical_clock,
        note=note,
    )
    return j.append("SIGNOFF", payload)


def add_rotation(j: Journal, root_kp: A.KeyPair, **kw):
    return j.append("AUTH_ROTATION", A.build_rotation(root_kp, **kw))


def add_revoke(j: Journal, kp: A.KeyPair, **kw):
    return j.append("REVOKE", A.build_revoke(kp, **kw))


def commit_watermark(
    j: Journal,
    *,
    idem_key: str,
    wm_id: str,
    prefix_len: int,
    auth_version: int,
    evidence_digest: str,
    segment_digests: list[str],
    signoff_ids: list[str],
    extra: Optional[dict[str, Any]] = None,
):
    payload: dict[str, Any] = {
        "wm_id": wm_id,
        "prefix_len": prefix_len,
        "auth_version": auth_version,
        "evidence_digest": evidence_digest,
        "segment_digests": segment_digests,
        "signoff_ids": signoff_ids,
    }
    if extra:
        payload.update(extra)
    return j.append_idempotent(idem_key, "COMMIT", payload)
