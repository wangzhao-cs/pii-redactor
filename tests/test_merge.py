"""消歧合并测试：优先级、最长匹配、去重与包含关系。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor.merge import dedupe, drop_contained, resolve_overlaps  # noqa: E402
from pii_redactor.models import Span, SpanType  # noqa: E402


def span(span_type, start, end, detector="test", confidence=1.0):
    """构造测试用 span（文本内容与位置无关紧要）。"""
    return Span(
        type=span_type,
        start=start,
        end=end,
        text="x" * (end - start),
        confidence=confidence,
        detector=detector,
    )


class ResolveOverlapsTest(unittest.TestCase):
    """重叠裁决规则。"""

    def test_priority_wins_over_longer_match(self):
        # 身份证（优先级 78）与银行卡（74）重叠时，身份证胜出
        id_card = span(SpanType.ID_CARD, 0, 18)
        bank = span(SpanType.BANK_CARD, 0, 18)
        result = resolve_overlaps([bank, id_card])
        self.assertEqual([s.type for s in result], [SpanType.ID_CARD])

    def test_credential_beats_structured_id(self):
        key = span(SpanType.API_KEY, 5, 40)
        id_card = span(SpanType.ID_CARD, 5, 23)
        result = resolve_overlaps([id_card, key])
        self.assertEqual([s.type for s in result], [SpanType.API_KEY])

    def test_longest_match_wins_within_same_priority(self):
        short = span(SpanType.ADDRESS, 0, 12)
        long = span(SpanType.ADDRESS, 0, 20)
        result = resolve_overlaps([short, long])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].end, 20)

    def test_non_overlapping_spans_all_kept_and_sorted(self):
        spans = [span(SpanType.PHONE, 20, 31), span(SpanType.EMAIL, 0, 10)]
        result = resolve_overlaps(spans)
        self.assertEqual([s.start for s in result], [0, 20])

    def test_partial_overlap_resolved_in_favour_of_priority(self):
        phone = span(SpanType.PHONE, 0, 11)
        address = span(SpanType.ADDRESS, 5, 25)
        result = resolve_overlaps([address, phone])
        self.assertEqual([s.type for s in result], [SpanType.PHONE])

    def test_output_has_no_overlaps(self):
        spans = [
            span(SpanType.ID_CARD, 0, 18),
            span(SpanType.BANK_CARD, 10, 26),
            span(SpanType.ADDRESS, 12, 30),
            span(SpanType.PERSON_NAME, 2, 5),
        ]
        result = resolve_overlaps(spans)
        for index, left in enumerate(result):
            for right in result[index + 1 :]:
                self.assertFalse(left.overlaps(right))


class DedupeAndContainmentTest(unittest.TestCase):
    """去重与包含关系。"""

    def test_dedupe_keeps_highest_confidence(self):
        low = span(SpanType.PHONE, 0, 11, detector="a", confidence=0.5)
        high = span(SpanType.PHONE, 0, 11, detector="b", confidence=1.0)
        result = dedupe([low, high])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].detector, "b")

    def test_drop_contained_removes_shorter_same_type(self):
        outer = span(SpanType.ADDRESS, 0, 30)
        inner = span(SpanType.ADDRESS, 5, 20)
        self.assertEqual(drop_contained([outer, inner]), [outer])

    def test_drop_contained_keeps_different_types(self):
        outer = span(SpanType.ADDRESS, 0, 30)
        inner = span(SpanType.PERSON_NAME, 5, 8)
        self.assertEqual(len(drop_contained([outer, inner])), 2)

    def test_custom_priority_can_be_overridden(self):
        id_card = span(SpanType.ID_CARD, 0, 18)
        bank = span(SpanType.BANK_CARD, 0, 18)
        result = resolve_overlaps([id_card, bank], priority={SpanType.BANK_CARD: 99})
        self.assertEqual([s.type for s in result], [SpanType.BANK_CARD])


if __name__ == "__main__":
    unittest.main()
