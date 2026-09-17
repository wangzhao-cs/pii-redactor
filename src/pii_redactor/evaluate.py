"""评测：金标 span 对比、P/R/F1 统计、残留泄漏率。

评测口径
--------
* **匹配**：``Span.type`` 相同且区间完全一致（``exact``）；也支持
  ``relaxed``（同类型且区间有重叠）作为边界敏感性参考；
* **micro**：汇总所有类型的 TP/FP/FN 后计算；
* **macro**：对"金标中出现过"的类型求算术平均；
* **泄漏率**：脱敏后文本中，金标原值仍**逐字出现**的比例。这个口径不依赖
  二次检测的召回，因此能真实反映"漏检 = 泄漏"的后果；
* **二次校验捕获数**：上述残留中被残留检测器重新命中的数量。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import HARD_TYPES, Span, TYPE_LABELS, sort_spans
from .redactor import Redactor
from .residual import check_residual
from .textwidth import render_table

__all__ = [
    "Metrics",
    "EvalResult",
    "load_labels",
    "load_documents",
    "match_spans",
    "evaluate_corpus",
    "format_table",
    "default_data_dir",
]


def default_data_dir() -> Path:
    """定位仓库内的 ``data/`` 目录（可用环境变量 ``PII_REDACTOR_DATA_DIR`` 覆盖）。"""
    override = os.environ.get("PII_REDACTOR_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "data"


# ---------------------------------------------------------------------------
# 指标
# ---------------------------------------------------------------------------


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / float(denominator) if denominator else 0.0


@dataclass
class Metrics:
    """一个（或一组）类型的 TP/FP/FN 与派生指标。"""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def support(self) -> int:
        """金标中的实体总数。"""
        return self.tp + self.fn

    @property
    def predicted(self) -> int:
        """预测出的实体总数。"""
        return self.tp + self.fp

    @property
    def precision(self) -> float:
        """精确率。"""
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        """召回率。"""
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        """F1（精确率与召回率的调和平均）。"""
        precision, recall = self.precision, self.recall
        return _ratio(2 * precision * recall, precision + recall) if (precision + recall) else 0.0

    def to_dict(self) -> Dict[str, object]:
        """转换为可 JSON 序列化的字典。"""
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "support": self.support,
            "predicted": self.predicted,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def match_spans(
    gold: Sequence[Span], pred: Sequence[Span], mode: str = "exact"
) -> Tuple[Metrics, List[Span], List[Span]]:
    """比对金标与预测。

    Returns:
        ``(metrics, false_positives, false_negatives)``
    """
    if mode not in ("exact", "relaxed"):
        raise ValueError("mode 只能是 'exact' 或 'relaxed'")
    gold = sort_spans(gold)
    pred = sort_spans(pred)
    used = [False] * len(pred)
    tp = 0
    fn_spans: List[Span] = []
    for g in gold:
        hit = -1
        for index, p in enumerate(pred):
            if used[index] or p.type != g.type:
                continue
            if g.same_region(p) if mode == "exact" else g.overlaps(p):
                hit = index
                break
        if hit >= 0:
            used[hit] = True
            tp += 1
        else:
            fn_spans.append(g)
    fp_spans = [p for index, p in enumerate(pred) if not used[index]]
    return Metrics(tp=tp, fp=len(fp_spans), fn=len(fn_spans)), fp_spans, fn_spans


# ---------------------------------------------------------------------------
# 数据加载
# ---------------------------------------------------------------------------


def load_labels(path: Optional[str] = None) -> Dict[str, object]:
    """读取金标文件（默认 ``data/labels.json``）。"""
    labels_path = Path(path) if path else default_data_dir() / "labels.json"
    with open(labels_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_documents(
    labels: Optional[Dict[str, object]] = None, *, data_dir: Optional[str] = None
) -> List[Tuple[str, str, List[Span], str]]:
    """从金标文件加载全部样本。

    Returns:
        ``[(doc_id, 文档全文, 金标 span 列表, 相对路径), ...]``
    """
    payload = labels if labels is not None else load_labels()
    base = Path(data_dir) if data_dir else default_data_dir()
    documents: List[Tuple[str, str, List[Span], str]] = []
    for doc in payload["documents"]:  # type: ignore[index]
        path = base / doc["path"]
        text = path.read_text(encoding="utf-8")
        spans: List[Span] = []
        for item in doc["spans"]:
            snippet = text[item["start"] : item["end"]]
            if snippet != item["text"]:
                raise ValueError(
                    "金标偏移与文本不一致：%s [%s:%s] 期望 %r 实际 %r"
                    % (doc["doc_id"], item["start"], item["end"], item["text"], snippet)
                )
            spans.append(
                Span(
                    type=item["type"],
                    start=int(item["start"]),
                    end=int(item["end"]),
                    text=snippet,
                    confidence=1.0,
                    detector="gold",
                    meta={"doc_id": doc["doc_id"]},
                )
            )
        documents.append((doc["doc_id"], text, spans, doc["path"]))
    return documents


# ---------------------------------------------------------------------------
# 评测主流程
# ---------------------------------------------------------------------------


@dataclass
class EvalResult:
    """一次语料级评测的全部结果。"""

    per_type: Dict[str, Metrics] = field(default_factory=dict)
    micro: Metrics = field(default_factory=Metrics)
    macro: Metrics = field(default_factory=Metrics)
    mode: str = "exact"
    strategy: str = "mask"
    documents: List[Dict[str, object]] = field(default_factory=list)
    leakage: Dict[str, object] = field(default_factory=dict)
    data_dir: str = ""
    #: macro 平均覆盖的类型数
    macro_types: int = 0
    #: macro 平均指标（对"金标中出现过"的类型求算术平均）
    macro_precision: float = 0.0
    macro_recall: float = 0.0
    macro_f1: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        """转换为可 JSON 序列化的字典。"""
        return {
            "config": {
                "mode": self.mode,
                "strategy": self.strategy,
                "data_dir": self.data_dir,
                "documents": len(self.documents),
                "types": len(self.per_type),
            },
            "per_type": {name: metrics.to_dict() for name, metrics in sorted(self.per_type.items())},
            "micro": self.micro.to_dict(),
            "macro": self.macro.to_dict(),
            "macro_types": self.macro_types,
            "macro_precision": round(self.macro_precision, 4),
            "macro_recall": round(self.macro_recall, 4),
            "macro_f1": round(self.macro_f1, 4),
            "leakage": self.leakage,
            "documents": self.documents,
        }


def evaluate_corpus(
    *,
    labels_path: Optional[str] = None,
    data_dir: Optional[str] = None,
    types: Optional[Iterable[str]] = None,
    strategy: str = "mask",
    mode: str = "exact",
    check_leakage: bool = True,
) -> EvalResult:
    """在合成标注集上评测检测与脱敏效果。

    Args:
        labels_path: 金标文件路径，默认 ``data/labels.json``。
        data_dir: 样本目录，默认仓库 ``data/``。
        types: 只评测/只脱敏这些类型。
        strategy: 脱敏策略（用于泄漏率评估）。
        mode: ``exact`` 或 ``relaxed`` 匹配口径。
        check_leakage: 是否计算泄漏率（需要额外跑一遍脱敏）。
    """
    payload = load_labels(labels_path) if labels_path else load_labels()
    base_dir = Path(data_dir) if data_dir else default_data_dir()
    documents = load_documents(payload, data_dir=str(base_dir))

    wanted = set(types) if types is not None else None
    redactor = Redactor(types=types, strategy=strategy)

    per_type: Dict[str, Metrics] = {}
    micro = Metrics()
    doc_reports: List[Dict[str, object]] = []

    for doc_id, text, gold_spans, path in documents:
        gold = [s for s in gold_spans if wanted is None or s.type in wanted]
        predicted = redactor.detect(text)
        metrics, fps, fns = match_spans(gold, predicted, mode=mode)
        micro.tp += metrics.tp
        micro.fp += metrics.fp
        micro.fn += metrics.fn
        for span in gold:
            per_type.setdefault(span.type, Metrics())
        for span in predicted:
            per_type.setdefault(span.type, Metrics())
        matched_pred = {id(p) for p in predicted} - {id(p) for p in fps}
        for index, p in enumerate(predicted):
            if id(p) not in matched_pred:
                continue
            bucket = per_type.setdefault(p.type, Metrics())
            bucket.tp += 1
        for span in fps:
            per_type.setdefault(span.type, Metrics()).fp += 1
        for span in fns:
            per_type.setdefault(span.type, Metrics()).fn += 1
        doc_reports.append(
            {
                "doc_id": doc_id,
                "path": path,
                "gold": len(gold),
                "predicted": len(predicted),
                "tp": metrics.tp,
                "fp": len(fps),
                "fn": len(fns),
                "precision": round(metrics.precision, 4),
                "recall": round(metrics.recall, 4),
                "f1": round(metrics.f1, 4),
                "false_positives": [span.to_dict() for span in fps],
                "false_negatives": [span.to_dict() for span in fns],
            }
        )

    macro_values = [
        (metrics.precision, metrics.recall, metrics.f1)
        for name, metrics in per_type.items()
        if metrics.support > 0
    ]
    macro = Metrics()
    macro_types = len(macro_values)
    macro_precision = sum(v[0] for v in macro_values) / macro_types if macro_types else 0.0
    macro_recall = sum(v[1] for v in macro_values) / macro_types if macro_types else 0.0
    macro_f1 = sum(v[2] for v in macro_values) / macro_types if macro_types else 0.0

    result = EvalResult(
        per_type=per_type,
        micro=micro,
        macro=macro,
        mode=mode,
        strategy=strategy,
        documents=doc_reports,
        data_dir=str(base_dir),
        macro_types=macro_types,
        macro_precision=macro_precision,
        macro_recall=macro_recall,
        macro_f1=macro_f1,
    )
    result.leakage = (
        evaluate_leakage(documents, strategy=strategy, types=types) if check_leakage else {}
    )
    return result


def evaluate_leakage(
    documents: Sequence[Tuple[str, str, List[Span], str]],
    *,
    strategy: str = "format_preserve",
    types: Optional[Iterable[str]] = None,
) -> Dict[str, object]:
    """计算"完整流水线"与"部分流水线（只脱敏手机号+身份证）"的残留泄漏率。

    泄漏判定：金标原值在脱敏结果中仍逐字出现。
    """
    wanted = list(types) if types is not None else None
    full = Redactor(types=wanted, strategy=strategy)
    partial = Redactor(types=["PHONE", "ID_CARD"], strategy=strategy)

    report: Dict[str, object] = {"strategy": strategy, "configs": {}}
    for label, redactor in (("full_pipeline", full), ("partial_pipeline_phone_id", partial)):
        total = leaked = caught = 0
        hard_total = hard_leaked = 0
        examples: List[Dict[str, object]] = []
        for doc_id, text, gold_spans, _path in documents:
            gold = [s for s in gold_spans if wanted is None or s.type in wanted]
            result = redactor.redact(text, verify=False)
            redacted = result.redacted
            residual = check_residual(
                redacted,
                original_spans=result.spans,
                known_replacements=[rep.replacement for rep in result.replacements],
            )
            detected_texts = {(s.type, s.text) for s in residual.residual_spans}
            for span in gold:
                total += 1
                if span.text in redacted:
                    leaked += 1
                    if (span.type, span.text) in detected_texts:
                        caught += 1
                    if len(examples) < 12:
                        examples.append(
                            {"doc_id": doc_id, "type": span.type, "text": span.text}
                        )
                if span.type in HARD_TYPES:
                    hard_total += 1
                    if span.text in redacted:
                        hard_leaked += 1
        report["configs"][label] = {
            "entities": total,
            "leaked": leaked,
            "leak_rate": round(leaked / float(total), 6) if total else 0.0,
            "recalled_by_residual_check": caught,
            "residual_check_coverage": round(caught / float(leaked), 6) if leaked else 0.0,
            "hard_entities": hard_total,
            "hard_leaked": hard_leaked,
            "examples": examples,
        }
    return report


def format_table(result: EvalResult) -> str:
    """把评测结果渲染成定宽文本表格（CLI 输出用）。"""
    aligns = ["left", "right", "right", "right", "right", "right", "right"]
    rows: List[List[str]] = [["类型", "TP", "FP", "FN", "精确率", "召回率", "F1"]]
    for name in sorted(result.per_type, key=lambda n: (-result.per_type[n].support, n)):
        metrics = result.per_type[name]
        if metrics.support == 0 and metrics.predicted == 0:
            continue
        rows.append(
            [
                "%s(%s)" % (name, TYPE_LABELS.get(name, name)),
                str(metrics.tp),
                str(metrics.fp),
                str(metrics.fn),
                "%.4f" % metrics.precision,
                "%.4f" % metrics.recall,
                "%.4f" % metrics.f1,
            ]
        )
    rows.append(
        [
            "micro",
            str(result.micro.tp),
            str(result.micro.fp),
            str(result.micro.fn),
            "%.4f" % result.micro.precision,
            "%.4f" % result.micro.recall,
            "%.4f" % result.micro.f1,
        ]
    )
    rows.append(
        [
            "macro(%d类)" % result.macro_types,
            "-",
            "-",
            "-",
            "%.4f" % result.macro_precision,
            "%.4f" % result.macro_recall,
            "%.4f" % result.macro_f1,
        ]
    )
    lines = render_table(rows, aligns)
    width = max(len(line) for line in lines)
    lines.insert(1, "-" * width)
    lines.append("-" * width)
    if result.leakage:
        configs = result.leakage.get("configs", {})  # type: ignore[union-attr]
        for label, data in configs.items():  # type: ignore[union-attr]
            lines.append(
                "泄漏率[%s, 策略=%s]: %.2f%% (%d/%d)  二次校验捕获 %d 处  强类型残留 %d/%d"
                % (
                    label,
                    result.leakage.get("strategy"),
                    100.0 * data["leak_rate"],
                    data["leaked"],
                    data["entities"],
                    data["recalled_by_residual_check"],
                    data["hard_leaked"],
                    data["hard_entities"],
                )
            )
    return "\n".join(lines)
