"""控制者 / 人员身份、规范签收报文、独立性判定（纯函数，无文件/线程依赖）。

信任模型
--------
* 每个“底层控制者”持有一把 Ed25519 签名钥；人员(person)在某授权版本下
  绑定到一个控制者(controller)。
* 两份人员签收是否“独立”，只看其**底层 controller_id 是否不同**：
  两个不同 person 若同受一个 controller 控制，仍不算独立。
* 授权本身有单调 ``auth_version``；控制人更换 / 钥换代时 +1。换代后的签收
  必须同时绑定 ``evidence_digest`` 与 **当前** ``auth_version``。
* 根钥(root)签署授权换代记录；根公钥指纹是带外钉住的信任锚。
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Optional

from .ed25519_native import KeyPair, verify_hex
from .encoding import canonical_bytes, sha256_hex

SIGNOFF_DOMAIN = b"sealaudit-signoff-v2|"
REVOKE_DOMAIN = b"sealaudit-revoke-v1|"
AUTH_ROTATION_DOMAIN = b"sealaudit-auth-rotation-v1|"


def deterministic_seed(label: str) -> str:
    """由标签确定性派生 32 字节 seed（hex），让演示密钥可复现。"""
    return sha256_hex(b"sealaudit-keyseed-v1|" + label.encode("utf-8"))


@lru_cache(maxsize=None)
def keypair(label: str) -> KeyPair:
    # 缓存：同一标签在穷举 / 多场景中复用同一密钥对，避免重复标量乘。
    return KeyPair.from_seed_hex(deterministic_seed(label))


@dataclass(frozen=True)
class Person:
    person_id: str
    controller_id: str


# ----------------------------------------------------------------------
# 签收
# ----------------------------------------------------------------------
def signoff_signing_bytes(body: dict[str, Any]) -> bytes:
    return SIGNOFF_DOMAIN + canonical_bytes(body)


def build_signoff(
    kp: KeyPair,
    *,
    signoff_id: str,
    evidence_id: str,
    evidence_digest: str,
    auth_version: int,
    controller_id: str,
    person_id: str,
    logical_clock: int = 0,
    note: str = "",
) -> dict[str, Any]:
    """生成一条含签名的签收记录 payload（签名不覆盖自身）。"""
    body: dict[str, Any] = {
        "signoff_id": signoff_id,
        "evidence_id": evidence_id,
        "evidence_digest": evidence_digest,
        "auth_version": auth_version,
        "controller_id": controller_id,
        "person_id": person_id,
        "logical_clock": logical_clock,
    }
    if note:
        body["note"] = note
    sig = kp.sign_hex(signoff_signing_bytes(body))
    return {**body, "sig_alg": "Ed25519", "sig": sig}


def signoff_body_without_sig(rec: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in rec.items() if k not in ("sig", "sig_alg")}


def verify_signoff_sig(rec: dict[str, Any], controller_public_hex: str) -> bool:
    sig = rec.get("sig")
    if not isinstance(sig, str):
        return False
    body = signoff_body_without_sig(rec)
    return verify_hex(controller_public_hex, signoff_signing_bytes(body), sig)


# ----------------------------------------------------------------------
# 撤销
# ----------------------------------------------------------------------
def revoke_signing_bytes(body: dict[str, Any]) -> bytes:
    return REVOKE_DOMAIN + canonical_bytes(body)


def build_revoke(
    kp: KeyPair,
    *,
    revoke_id: str,
    target_signoff_id: str,
    controller_id: str,
    reason: str,
) -> dict[str, Any]:
    body = {
        "revoke_id": revoke_id,
        "target_signoff_id": target_signoff_id,
        "controller_id": controller_id,
        "reason": reason,
    }
    sig = kp.sign_hex(revoke_signing_bytes(body))
    return {**body, "sig_alg": "Ed25519", "sig": sig}


def verify_revoke_sig(rec: dict[str, Any], controller_public_hex: str) -> bool:
    sig = rec.get("sig")
    if not isinstance(sig, str):
        return False
    body = {k: v for k, v in rec.items() if k not in ("sig", "sig_alg")}
    return verify_hex(controller_public_hex, revoke_signing_bytes(body), sig)


# ----------------------------------------------------------------------
# 授权换代
# ----------------------------------------------------------------------
def rotation_signing_bytes(body: dict[str, Any]) -> bytes:
    return AUTH_ROTATION_DOMAIN + canonical_bytes(body)


def build_rotation(
    root_kp: KeyPair,
    *,
    new_version: int,
    person_id: str,
    old_controller_id: str,
    new_controller_id: str,
    new_controller_public_hex: str,
    effective_note: str = "",
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "CONTROLLER_ROTATION",
        "new_auth_version": new_version,
        "person_id": person_id,
        "old_controller_id": old_controller_id,
        "new_controller_id": new_controller_id,
        "new_controller_public_key": new_controller_public_hex,
    }
    if effective_note:
        body["note"] = effective_note
    sig = root_kp.sign_hex(rotation_signing_bytes(body))
    return {**body, "sig_alg": "Ed25519", "root_sig": sig}


def verify_rotation_sig(rec: dict[str, Any], root_public_hex: str) -> bool:
    sig = rec.get("root_sig")
    if not isinstance(sig, str):
        return False
    body = {k: v for k, v in rec.items() if k not in ("root_sig", "sig_alg")}
    return verify_hex(root_public_hex, rotation_signing_bytes(body), sig)


# ----------------------------------------------------------------------
# 独立性
# ----------------------------------------------------------------------
def underlying_controllers(signoffs: list[dict[str, Any]]) -> set[str]:
    return {str(s["controller_id"]) for s in signoffs}


def has_two_independent_controllers(valid_signoffs: list[dict[str, Any]]) -> bool:
    """至少两份有效签收，且其底层 controller 至少有两个不同。"""
    if len(valid_signoffs) < 2:
        return False
    return len(underlying_controllers(valid_signoffs)) >= 2


def root_pin(root_public_hex: str, genesis_canonical_digest: Optional[str] = None) -> str:
    """带外钉住的信任锚指纹：优先用创世文件摘要，否则用根公钥指纹。"""
    if genesis_canonical_digest:
        return genesis_canonical_digest
    return "rootpub:" + sha256_hex(bytes.fromhex(root_public_hex))[:16]
