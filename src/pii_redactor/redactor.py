"""对外门面：把"检测 -> 消歧 -> 脱敏 -> 残留校验"串成一条流水线。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from .detectors import Detector, detect_spans
from .models import Span, SpanType, TYPE_LABELS
from .residual import ResidualReport, check_residual
from .strategies import (
    DEFAULT_SEED,
    STRATEGIES,
    RedactionContext,
    Replacement,
    redact_spans,
)

__all__ = ["RedactionResult", "Redactor", "detect", "redact", "redact_text", "verify"]


@dataclass
class RedactionResult:
    """一次完整脱敏的产物。"""

    original: str
    redacted: str
    spans: List[Span]
    replacements: List[Replacement]
    strategy: str
    seed: str = DEFAULT_SEED
    residual: Optional[ResidualReport] = None

    # -- 统计 -------------------------------------------------------------
    @property
    def stats(self) -> Dict[str, int]:
        """各类型的命中数量。"""
        counts: Dict[str, int] = {}
        for span in self.spans:
            counts[span.type] = counts.get(span.type, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def total(self) -> int:
        """命中的敏感信息总数。"""
        return len(self.spans)

    def to_dict(self, *, include_text: bool = True) -> Dict[str, object]:
        """转换为可 JSON 序列化的字典。"""
        data: Dict[str, object] = {
            "strategy": self.strategy,
            "seed": self.seed,
            "total_spans": self.total,
            "stats": self.stats,
            "spans": [span.to_dict() for span in self.spans],
            "replacements": [rep.to_dict() for rep in self.replacements],
        }
        if include_text:
            data["original"] = self.original
            data["redacted"] = self.redacted
        if self.residual is not None:
            data["residual"] = self.residual.to_dict()
        return data


class Redactor:
    """检测 + 脱敏的一体化入口。

    Example:
        >>> redactor = Redactor(strategy="mask")
        >>> result = redactor.redact("联系 13800138000")
        >>> result.redacted
        '联系 138****8000'
    """

    def __init__(
        self,
        *,
        types: Optional[Iterable[str]] = None,
        strategy: str = "mask",
        seed: str = DEFAULT_SEED,
        detectors: Optional[Sequence[Detector]] = None,
        min_confidence: float = 0.0,
    ) -> None:
        if strategy not in STRATEGIES:
            raise ValueError("未知策略 %r，可选：%s" % (strategy, ", ".join(sorted(STRATEGIES))))
        self.types = tuple(types) if types is not None else None
        self.strategy = strategy
        self.seed = seed
        self.detectors = list(detectors) if detectors is not None else None
        self.min_confidence = min_confidence

    # -- 检测 -------------------------------------------------------------
    def detect(self, text: str) -> List[Span]:
        """识别文本中的敏感信息（已消歧、按位置排序）。"""
        spans = detect_spans(text, types=self.types, detectors=self.detectors)
        if self.min_confidence > 0:
            spans = [span for span in spans if span.confidence >= self.min_confidence]
        return spans

    # -- 脱敏 -------------------------------------------------------------
    def redact(
        self,
        text: str,
        *,
        strategy: Optional[str] = None,
        verify: bool = True,
    ) -> RedactionResult:
        """执行脱敏；``verify=True`` 时顺带做残留二次校验。

        注意：``types`` 只限制**脱敏范围**，残留校验始终扫描全部类型，
        否则"只脱敏手机号"会漏掉文档里剩下的身份证、邮箱等敏感信息。
        """
        name = strategy or self.strategy
        spans = self.detect(text)
        redacted, replacements = redact_spans(
            text, spans, name, seed=self.seed, context=RedactionContext(seed=self.seed, strategy=name)
        )
        residual = None
        if verify:
            all_spans = detect_spans(text, types=None, detectors=self.detectors)
            residual = check_residual(
                redacted,
                original_spans=all_spans,
                types=None,
                detectors=self.detectors,
                known_replacements=[rep.replacement for rep in replacements],
            )
        return RedactionResult(
            original=text,
            redacted=redacted,
            spans=spans,
            replacements=replacements,
            strategy=name,
            seed=self.seed,
            residual=residual,
        )

    def redact_text(self, text: str, *, strategy: Optional[str] = None) -> str:
        """只取脱敏后的文本。"""
        return self.redact(text, strategy=strategy, verify=False).redacted


# ---------------------------------------------------------------------------
# 便捷函数
# ---------------------------------------------------------------------------


def detect(text: str, *, types: Optional[Iterable[str]] = None) -> List[Span]:
    """便捷方法：识别文本中的敏感信息。"""
    return detect_spans(text, types=types)


def redact(
    text: str,
    *,
    strategy: str = "mask",
    types: Optional[Iterable[str]] = None,
    verify: bool = True,
    seed: str = DEFAULT_SEED,
) -> RedactionResult:
    """便捷方法：脱敏并（默认）校验残留。"""
    return Redactor(types=types, strategy=strategy, seed=seed).redact(text, verify=verify)


def redact_text(
    text: str,
    *,
    strategy: str = "mask",
    types: Optional[Iterable[str]] = None,
    seed: str = DEFAULT_SEED,
) -> str:
    """便捷方法：只返回脱敏后的文本。"""
    return redact(text, strategy=strategy, types=types, verify=False, seed=seed).redacted


def verify(
    redacted_text: str,
    *,
    original_spans: Optional[Sequence[Span]] = None,
    types: Optional[Iterable[str]] = None,
) -> ResidualReport:
    """便捷方法：对给定文本做残留校验。"""
    return check_residual(redacted_text, original_spans=original_spans, types=types)
