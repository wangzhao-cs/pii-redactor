"""残留二次校验测试。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import Redactor, check_residual, detect  # noqa: E402
from pii_redactor.models import Span, SpanType  # noqa: E402
from pii_redactor.residual import is_mask_like  # noqa: E402

SAMPLE = (
    "姓名：李文博，身份证 110101199003078515，银行卡 62220212345678903，"
    "电话 13800138000，邮箱 liwenbo@example.com。"
)


class ResidualBasicsTest(unittest.TestCase):
    """基础行为。"""

    def test_clean_redaction_passes(self):
        result = Redactor(strategy="mask").redact(SAMPLE)
        self.assertIsNotNone(result.residual)
        self.assertTrue(result.residual.ok)
        self.assertEqual(result.residual.leak_rate, 0.0)
        self.assertEqual(result.residual.hard_hits, [])

    def test_unredacted_text_is_reported_as_leak(self):
        spans = detect(SAMPLE)
        report = check_residual(SAMPLE, original_spans=spans)
        self.assertFalse(report.ok)
        self.assertEqual(len(report.leaked_spans), len(spans))
        self.assertEqual(report.leak_rate, 1.0)
        self.assertTrue(report.hard_hits)

    def test_partial_redaction_leak_rate_between_zero_and_one(self):
        spans = detect(SAMPLE)
        redactor = Redactor(types=[SpanType.PHONE, SpanType.ID_CARD], strategy="format_preserve")
        result = redactor.redact(SAMPLE, verify=False)
        report = check_residual(result.redacted, original_spans=spans)
        self.assertGreater(report.leak_rate, 0.0)
        self.assertLess(report.leak_rate, 1.0)
        self.assertGreater(len(report.leaked_spans), 0)

    def test_hard_types_counted_separately_from_soft(self):
        report = check_residual("电话 13800138000，地址：北京市海淀区中关村大街27号")
        soft_types = {span.type for span in report.soft_hits}
        hard_types = {span.type for span in report.hard_hits}
        self.assertIn(SpanType.ADDRESS, soft_types)
        self.assertIn(SpanType.PHONE, soft_types)
        self.assertEqual(hard_types, set())

    def test_checksum_verified_types_are_hard_hits(self):
        report = check_residual("身份证 110101199003078515，账号 62220212345678903")
        hard_types = {span.type for span in report.hard_hits}
        self.assertEqual(hard_types, {SpanType.ID_CARD, SpanType.BANK_CARD})
        self.assertFalse(report.ok)

    def test_presence_mode_without_original_spans(self):
        clean = check_residual("没有敏感信息的文本。")
        dirty = check_residual("电话 13800138000")
        self.assertTrue(clean.ok)
        self.assertEqual(clean.leak_rate, 0.0)
        self.assertFalse(dirty.ok)
        self.assertEqual(dirty.leak_rate, 1.0)


class ResidualFilteringTest(unittest.TestCase):
    """掩码与已知替换的排除。"""

    def test_mask_like_values_are_not_treated_as_residual(self):
        self.assertTrue(is_mask_like("********"))
        self.assertFalse(is_mask_like("*a*"))
        report = check_residual("password=********")
        self.assertEqual(report.residual_spans, [])

    def test_known_replacements_are_ignored(self):
        text = "邮箱 user0f3a@example.com"
        without = check_residual(text)
        with_known = check_residual(text, known_replacements=["user0f3a@example.com"])
        self.assertEqual(len(without.residual_spans), 1)
        self.assertEqual(len(with_known.residual_spans), 0)

    def test_pseudonym_output_is_not_counted_as_leak(self):
        result = Redactor(strategy="pseudonym").redact(SAMPLE)
        self.assertTrue(result.residual.ok)
        self.assertEqual(result.residual.residual_spans, [])

    def test_type_filter_limits_scan(self):
        text = "电话 13800138000，地址：北京市海淀区中关村大街27号"
        report = check_residual(text, types=[SpanType.PHONE])
        self.assertEqual([span.type for span in report.residual_spans], [SpanType.PHONE])


class ResidualReportingTest(unittest.TestCase):
    """报告结构。"""

    def test_to_dict_is_json_friendly(self):
        report = check_residual("电话 13800138000")
        payload = report.to_dict()
        self.assertIn("leak_rate", payload)
        self.assertIn("hard_detail", payload)
        self.assertIsInstance(payload["residual_detail"], list)

    def test_summary_text(self):
        ok_report = check_residual("无敏感信息。")
        self.assertIn("通过", ok_report.summary())
        bad_report = check_residual("身份证 110101199003078515")
        self.assertIn("未通过", bad_report.summary())

    def test_character_leak_rate(self):
        span = Span(type=SpanType.PHONE, start=0, end=11, text="13800138000")
        report = check_residual("13800138000", original_spans=[span])
        self.assertAlmostEqual(report.leak_rate_char, 11 / 11, places=4)


if __name__ == "__main__":
    unittest.main()
