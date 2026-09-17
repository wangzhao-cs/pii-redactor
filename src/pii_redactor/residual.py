"""残留二次校验：脱敏后重新检测，量化"还剩多少敏感信息"。

这是本项目区别于普通"正则替换脚本"的核心能力：脱敏不是终点，
**验证脱敏结果** 才是。校验分三层：

1. 全量重扫：对脱敏后文本重跑全部检测器；
2. 专项校验：只要仍存在通过校验位/Luhn/结构验证的强类型（身份证、
   银行卡、统一社会信用代码、凭据），即判定为泄漏（``hard_hits``）；
3. 泄漏率：与原始（或金标）span 逐一比对，统计"原值仍然存在"的比例。

第三层按"原值文本"匹配而不是"重新命中"匹配：假名策略会把 ``张伟``
换成 ``张某``，重扫必然命中同类型的合成值，但它并不是泄漏。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from .detectors import default_detectors, detect_spans
from .models import HARD_TYPES, Span, TYPE_LABELS, is_mask_like, sort_spans

__all__ = ["ResidualReport", "check_residual", "is_mask_like"]


@dataclass
class ResidualReport:
    """残留校验结果。

    Attributes:
        residual_spans: 脱敏后文本上重新命中的全部 span。
        hard_hits: 其中属于"强校验类型"的（即通过校验算法，判定为泄漏）。
        soft_hits: 属于启发式类型的（建议人工复核）。
        leaked_spans: 原始 span 中"原值仍可检出"的部分。
        leak_rate: 泄漏率 = ``leaked_spans / original_spans``（无原始值时按有无残留取 0/1）。
        characters_after: 脱敏后文本长度，用于折算泄漏字符占比。
    """

    residual_spans: List[Span] = field(default_factory=list)
    hard_hits: List[Span] = field(default_factory=list)
    soft_hits: List[Span] = field(default_factory=list)
    leaked_spans: List[Span] = field(default_factory=list)
    original_spans: List[Span] = field(default_factory=list)
    leak_rate: float = 0.0
    characters_after: int = 0

    @property
    def ok(self) -> bool:
        """是否未发现残留泄漏（强类型零残留 + 泄漏率为 0）。"""
        return not self.hard_hits and self.leak_rate == 0.0

    @property
    def leak_rate_char(self) -> float:
        """泄漏字符占脱敏后文本的比例。"""
        if not self.characters_after:
            return 0.0
        leaked_chars = sum(span.length for span in self.leaked_spans)
        return leaked_chars / float(self.characters_after)

    def to_dict(self) -> Dict[str, object]:
        """转换为可 JSON 序列化的字典。"""
        return {
            "ok": self.ok,
            "leak_rate": round(self.leak_rate, 6),
            "leak_rate_char": round(self.leak_rate_char, 6),
            "original_spans": len(self.original_spans),
            "leaked_spans": len(self.leaked_spans),
            "residual_spans": len(self.residual_spans),
            "hard_hits": len(self.hard_hits),
            "soft_hits": len(self.soft_hits),
            "residual_detail": [span.to_dict() for span in self.residual_spans],
            "hard_detail": [span.to_dict() for span in self.hard_hits],
            "leaked_detail": [span.to_dict() for span in self.leaked_spans],
        }

    def summary(self) -> str:
        """人类可读的单行摘要。"""
        if self.ok:
            return "残留校验通过：未发现泄漏（强类型残留 0 处，泄漏率 0.00%）"
        parts = []
        if self.hard_hits:
            kinds = sorted({TYPE_LABELS.get(s.type, s.type) for s in self.hard_hits})
            parts.append("强校验残留 %d 处（%s）" % (len(self.hard_hits), "、".join(kinds)))
        if self.leaked_spans:
            parts.append("泄漏率 %.2f%%（%d/%d）" % (
                100.0 * self.leak_rate, len(self.leaked_spans), len(self.original_spans)))
        if not parts:
            parts.append("启发式残留 %d 处（未通过校验算法，建议复核）" % len(self.soft_hits))
        return "残留校验未通过：" + "；".join(parts)


def check_residual(
    redacted_text: str,
    *,
    original_spans: Optional[Sequence[Span]] = None,
    types: Optional[Iterable[str]] = None,
    detectors=None,
    known_replacements: Optional[Iterable[str]] = None,
    detect_types: Optional[Iterable[str]] = None,
) -> ResidualReport:
    """对脱敏后文本做二次校验。

    Args:
        redacted_text: 脱敏后的文本。
        original_spans: 脱敏前的 span 列表；给出后即可计算泄漏率。
        types: 只关注的类型（同时作用于重扫与泄漏比对）。
        detectors: 自定义检测器列表。
        known_replacements: 已知的替换结果文本（如假名），重扫命中这些值时
            不计入残留（它们是我们自己写入的合成值）。
        detect_types: 仅重扫这些类型；默认与 ``types`` 相同，``None`` 表示全部。

    Returns:
        :class:`ResidualReport`
    """
    wanted = set(types) if types is not None else None
    scan_types = set(detect_types) if detect_types is not None else wanted
    active = list(detectors) if detectors is not None else default_detectors()

    raw = detect_spans(redacted_text, types=scan_types, detectors=active)
    safe = {text for text in (known_replacements or []) if text}
    residual = [
        span
        for span in raw
        if not is_mask_like(span.text) and span.text not in safe
    ]
    if wanted is not None:
        residual = [span for span in residual if span.type in wanted]

    hard = sort_spans(span for span in residual if span.type in HARD_TYPES)
    soft = sort_spans(span for span in residual if span.type not in HARD_TYPES)

    original = list(original_spans or [])
    if wanted is not None:
        original = [span for span in original if span.type in wanted]

    leaked: List[Span] = []
    for span in original:
        if any(
            other.type == span.type and other.text == span.text for other in residual
        ):
            leaked.append(span)

    if original:
        leak_rate = len(leaked) / float(len(original))
    else:
        leak_rate = 1.0 if residual else 0.0

    return ResidualReport(
        residual_spans=sort_spans(residual),
        hard_hits=hard,
        soft_hits=soft,
        leaked_spans=sort_spans(leaked),
        original_spans=sort_spans(original),
        leak_rate=leak_rate,
        characters_after=len(redacted_text),
    )
