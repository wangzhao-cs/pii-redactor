"""门面 API 测试：Redactor 与模块级便捷函数。"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import (  # noqa: E402
    Redactor,
    SpanType,
    __version__,
    detect,
    redact,
    redact_text,
    verify,
)

SAMPLE = "姓名：李文博，身份证 110101199003078515，电话 13800138000，邮箱 liwenbo@example.com。"


class RedactorApiTest(unittest.TestCase):
    """Redactor 类。"""

    def test_redact_returns_result_bundle(self):
        result = Redactor(strategy="mask").redact(SAMPLE)
        self.assertEqual(result.original, SAMPLE)
        self.assertNotIn("110101199003078515", result.redacted)
        self.assertEqual(len(result.spans), len(result.replacements))
        self.assertEqual(result.strategy, "mask")
        self.assertGreater(result.total, 0)

    def test_stats_and_to_dict(self):
        result = Redactor(strategy="mask").redact(SAMPLE)
        self.assertEqual(result.stats.get(SpanType.ID_CARD), 1)
        payload = json.loads(json.dumps(result.to_dict(), ensure_ascii=False))
        self.assertIn("residual", payload)
        self.assertEqual(payload["stats"][SpanType.PHONE], 1)

    def test_types_filter(self):
        result = Redactor(types=[SpanType.PHONE], strategy="mask").redact(SAMPLE)
        self.assertEqual([span.type for span in result.spans], [SpanType.PHONE])
        self.assertIn("110101199003078515", result.redacted)

    def test_min_confidence_filter(self):
        text = "护照号 E12345678 与身份证 110101199003078515"
        low = Redactor(min_confidence=0.0).detect(text)
        strict = Redactor(min_confidence=0.9).detect(text)
        self.assertGreater(len(low), len(strict))
        self.assertTrue(all(span.confidence >= 0.9 for span in strict))

    def test_unknown_strategy_raises_value_error(self):
        with self.assertRaises(ValueError):
            Redactor(strategy="nope")

    def test_redact_text_and_verify_helpers(self):
        masked = Redactor(strategy="mask").redact_text(SAMPLE)
        self.assertNotIn("13800138000", masked)
        report = verify(masked, original_spans=detect(SAMPLE))
        self.assertTrue(report.ok)

    def test_module_level_helpers(self):
        self.assertTrue(detect("电话 13800138000"))
        self.assertEqual(redact("电话 13800138000").redacted, "电话 138****8000")
        self.assertEqual(redact_text("电话 13800138000", strategy="remove"), "电话 ")
        self.assertEqual(Redactor(strategy="mask").redact_text("电话 13800138000"), "电话 138****8000")

    def test_version_is_exposed(self):
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
