# 封存证据的多方签收与回滚审计

题面见 `task/PROMPT.txt`。本仓库用 **Windows 原生 Python 3.12 + 仅标准库**，
实现离线封存与独立验证，覆盖：两名底层独立控制者签收、控制人换代绑定
（证据摘要 + 当前授权版本）、缺段只承诺最后连续可信前缀、撤销/提交按落盘
顺序裁决、两线程 + Barrier + 故障注入复现“撤销抢先 / 回执丢失”、重启幂等与
拒绝陌生摘要、小样本穷举与最早最小独立冲突证据、60000 条合成账目的访问范围实测。

## 一键运行

```bat
py -3.12 run_audit.py
```

或 `python run_audit.py`。脚本会先做 Ed25519 RFC 8032 已知答案自检，
随后构建并验证全部案例，退出码 0 表示所有关键不变量通过。

产物：

- `REPORT.md` / `artifacts/AUDIT_REPORT.md`：当次实测人读报告；
- `artifacts/audit_report.json`：全量机器结果；
- `artifacts/case_main/`：主审计案例（`genesis.json` + `journal.log` + `segments/`）；
- `artifacts/minimal_conflict_proof.json`：最早最小独立冲突证据包；
- `artifacts/case_enum/`、`artifacts/race_*`、`artifacts/case_receipt/`、`artifacts/bench60k/`。

## 独立验证（不导入任何写入/并发/基准代码）

```bat
py -3.12 verify_audit.py --case artifacts/case_main
py -3.12 verify_audit.py --case artifacts/case_main --pin sha256:...
py -3.12 verify_audit.py --bundle artifacts/minimal_conflict_proof.json --json
```

退出码：`0` 通过；`2` 案例未通过；`3` 证据包不能证明冲突；`4` 用法/读取错误。

## 设计要点

- `sealaudit/ed25519_native.py`：纯标准库 Ed25519，启动跑 RFC 8032 向量自检。
- `sealaudit/journal.py`：哈希链 + `fsync` 的追加日志；单调 `seq` 即落盘顺序；
  `idem_key` 双重检查幂等；暴露 `before_append` / `after_fsync` 故障注入点。
- `sealaudit/authority.py`：人员→底层控制者的版本化绑定；独立性按 `controller_id` 判定。
- `sealaudit/verifier.py`：只读独立验证器，重放授权、验签、按 `seq` 裁决撤销、
  从段原始账目重算每个水位。
- `sealaudit/enummine.py`：2^6 签收子集穷举 + 最早/最小冲突证据挖掘与留一法最小性。
- `sealaudit/race.py`：两线程 + `threading.Barrier(2)` + 确定性故障门，复现两种交错。
- `sealaudit/bench60k.py`：60000 条账目，计量“补齐一段 / Merkle 包含证明 / 全量重核”的访问范围。
