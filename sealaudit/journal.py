"""追加式、哈希链、fsync 持久化日志 —— “落盘顺序”的唯一裁判。

关键不变量：

* 每条记录先在进程内锁内分配单调 ``seq``，再把整行 JSON 一次写入并
  ``flush + os.fsync``。因此 ``seq`` 顺序 == 实际落盘顺序，两个线程的
  撤销/提交竞争由各自拿到的 ``seq`` 先后裁决。
* 记录间用 ``prev`` 哈希串成链，任何篡改/删改都会被独立验证方发现。
* 维护 ``idem_key -> seq`` 索引并可在重放后重建，用于“回执丢失 + 重试”
  场景的幂等去重，保证不重复提交。

本模块只负责读写日志机制；“是否有效”的业务裁决放在 verifier / service。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .encoding import canonical_bytes, sha256_hex

GENESIS_PREV = "0" * 64


class ReceiptLost(RuntimeError):
    """故障注入：记录已持久化，但返回给客户端的回执在途中丢失。"""


class JournalFault(RuntimeError):
    """其它注入故障。"""


@dataclass
class Record:
    seq: int
    kind: str
    payload: dict[str, Any]
    prev: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "payload": self.payload,
            "prev": self.prev,
            "hash": self.hash,
        }


def record_hash(seq: int, kind: str, payload: dict[str, Any], prev: str) -> str:
    body = {"seq": seq, "kind": kind, "payload": payload, "prev": prev}
    return sha256_hex(canonical_bytes(body))


class Journal:
    """线程安全的追加式 JSONL 哈希链日志。"""

    def __init__(
        self,
        directory: str | os.PathLike[str],
        filename: str = "journal.log",
        *,
        fault: Optional[Callable[[str, "Journal", dict[str, Any]], None]] = None,
    ) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / filename
        self._lock = threading.RLock()
        self._records: list[Record] = []
        self._idem: dict[str, int] = {}
        # fault(stage, journal, ctx): stage in {"before_append","after_fsync"}
        # 可在精确注入点阻塞 / 抛 ReceiptLost。
        self.fault = fault
        self._replay()

    # ---------- 重放 / 校验 ----------
    def _replay(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                rec = Record(
                    seq=int(obj["seq"]),
                    kind=str(obj["kind"]),
                    payload=dict(obj["payload"]),
                    prev=str(obj["prev"]),
                    hash=str(obj["hash"]),
                )
                expected_seq = len(self._records) + 1
                if rec.seq != expected_seq:
                    raise JournalFault(
                        f"日志序列不连续：第 {lineno} 行 seq={rec.seq}，应为 {expected_seq}"
                    )
                expected_prev = self._records[-1].hash if self._records else GENESIS_PREV
                if rec.prev != expected_prev:
                    raise JournalFault(f"日志哈希链在 seq={rec.seq} 断裂（prev 不符）")
                if rec.hash != record_hash(rec.seq, rec.kind, rec.payload, rec.prev):
                    raise JournalFault(f"日志记录 seq={rec.seq} 哈希不符，疑似篡改")
                self._records.append(rec)
                idem = rec.payload.get("idem_key")
                if isinstance(idem, str):
                    if idem in self._idem:
                        # 重放时若已出现重复 idem，保留最早 seq；重复本身由上层计数暴露。
                        pass
                    else:
                        self._idem[idem] = rec.seq

    # ---------- 读视图 ----------
    @property
    def records(self) -> list[Record]:
        with self._lock:
            return list(self._records)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def last_hash(self) -> str:
        with self._lock:
            return self._records[-1].hash if self._records else GENESIS_PREV

    def idem_seq(self, idem_key: str) -> Optional[int]:
        with self._lock:
            return self._idem.get(idem_key)

    def find(self, kind: Optional[str] = None) -> list[Record]:
        with self._lock:
            return [r for r in self._records if kind is None or r.kind == kind]

    def get(self, seq: int) -> Record:
        with self._lock:
            return self._records[seq - 1]

    # ---------- 追加 ----------
    def append(self, kind: str, payload: dict[str, Any]) -> Record:
        ctx: dict[str, Any] = {"kind": kind, "payload": payload}
        if self.fault is not None:
            # 注入点 1：在获取写锁 / 分配 seq 之前。可在此阻塞以让对手线程
            # 先落盘；必须在锁外等待，否则会与对手的写盘形成自死锁。
            self.fault("before_append", self, ctx)

        with self._lock:
            return self._write_locked(kind, payload, ctx)

    def append_idempotent(
        self, idem_key: str, kind: str, payload: dict[str, Any]
    ) -> tuple[Record, bool]:
        """按 idem_key 幂等提交，返回 ``(record, created)``。

        命中已有键时 ``created=False`` 且不追加。写入前在锁内做双重检查，
        两个线程用同一 idem_key 并发也只会落一条 COMMIT。若首次写在 fsync
        后被注入 ReceiptLost，记录与 idem 索引仍已持久化，重试（含重启
        重放）会命中已有记录，绝不重复提交。
        """
        with self._lock:
            existing = self._idem.get(idem_key)
            if existing is not None:
                return self._records[existing - 1], False

        ctx: dict[str, Any] = {"kind": kind, "payload": payload, "idem_key": idem_key}
        if self.fault is not None:
            self.fault("before_append", self, ctx)

        with self._lock:
            existing = self._idem.get(idem_key)  # 双重检查：可能已被另一线程写入
            if existing is not None:
                return self._records[existing - 1], False
            payload = {**payload, "idem_key": idem_key}
            rec = self._write_locked(kind, payload, ctx)  # 持久化后可能抛 ReceiptLost
            return rec, True

    def _write_locked(
        self, kind: str, payload: dict[str, Any], ctx: dict[str, Any]
    ) -> Record:
        seq = len(self._records) + 1
        prev = self._records[-1].hash if self._records else GENESIS_PREV
        h = record_hash(seq, kind, payload, prev)
        rec = Record(seq=seq, kind=kind, payload=payload, prev=prev, hash=h)

        line = json.dumps(rec.to_dict(), ensure_ascii=False, sort_keys=True)
        # 以追加模式单行写入；锁保证两个线程不会交错。
        with self.path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

        self._records.append(rec)
        idem = payload.get("idem_key")
        if isinstance(idem, str) and idem not in self._idem:
            self._idem[idem] = seq

        if self.fault is not None:
            # 注入点 2：已 fsync 持久化之后（可在此抛“回执丢失”）。
            self.fault("after_fsync", self, ctx | {"record": rec})

        return rec
