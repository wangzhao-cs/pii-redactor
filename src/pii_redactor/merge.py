"""重叠消歧与去重。

多个检测器可能在同一段文字上同时命中（例如 18 位数字串既像身份证又像
银行卡），需要一个确定的裁决规则：

1. 类型优先级：凭据 > 强校验标识 > 弱启发式（见 ``DEFAULT_PRIORITY``）；
2. 同优先级时取更长的匹配（最长匹配优先）；
3. 仍然并列时按 (起始位置, 检测器名) 稳定排序，保证结果可复现。

被更高优先级 span 覆盖的低优先级 span 直接丢弃。
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence

from .models import DEFAULT_PRIORITY, Span, sort_spans

__all__ = ["resolve_overlaps", "drop_contained", "dedupe"]


def dedupe(spans: Iterable[Span]) -> List[Span]:
    """去掉完全相同的 span（类型 + 区间），保留置信度更高者。"""
    best: Dict[tuple, Span] = {}
    for span in spans:
        key = (span.type, span.start, span.end)
        current = best.get(key)
        if current is None or span.confidence > current.confidence:
            best[key] = span
    return list(best.values())


def drop_contained(spans: Iterable[Span]) -> List[Span]:
    """若一个 span 被另一个**同类型**的 span 完整包含，丢弃较短者。"""
    ordered = sort_spans(spans)
    keep: List[Span] = []
    for span in ordered:
        contained = any(
            other is not span and other.type == span.type and other.contains(span)
            for other in ordered
        )
        if not contained:
            keep.append(span)
    return keep


def resolve_overlaps(
    spans: Iterable[Span],
    priority: Optional[Dict[str, int]] = None,
) -> List[Span]:
    """按优先级 + 最长匹配裁决重叠，返回互不重叠的 span。"""
    table = dict(DEFAULT_PRIORITY)
    if priority:
        table.update(priority)
    candidates = sorted(
        drop_contained(dedupe(spans)),
        key=lambda s: (-table.get(s.type, 0), -s.length, s.start, s.detector, s.type),
    )
    accepted: List[Span] = []
    for span in candidates:
        if any(span.overlaps(kept) for kept in accepted):
            continue
        accepted.append(span)
    return sort_spans(accepted)
