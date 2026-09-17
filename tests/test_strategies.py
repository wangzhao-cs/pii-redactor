"""脱敏策略测试：mask / placeholder / pseudonym / remove / format_preserve。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import Redactor, redact_text  # noqa: E402
from pii_redactor.models import Span  # noqa: E402
from pii_redactor.strategies import (  # noqa: E402
    STRATEGIES,
    RedactionContext,
    Replacement,
    apply_replacements,
    redact_spans,
)


class MaskStrategyTest(unittest.TestCase):
    """掩码：保留头尾。"""

    def test_phone_and_id_mask(self):
        text = "手机 13800138000，身份证 110101199003078515"
        masked = redact_text(text, strategy="mask")
        self.assertEqual(masked, "手机 138****8000，身份证 110101********8515")

    def test_email_keeps_domain(self):
        masked = redact_text("邮箱 liwenbo1990@example.com", strategy="mask")
        self.assertEqual(masked, "邮箱 li*********@example.com")

    def test_ipv4_masks_last_two_octets(self):
        masked = redact_text("来源 192.168.31.24", strategy="mask")
        self.assertEqual(masked, "来源 192.168.*.*")

    def test_password_uses_full_marker(self):
        masked = redact_text("password=Pr0d-Pass-2026!", strategy="mask")
        self.assertEqual(masked, "password=********")

    def test_private_key_uses_marker(self):
        text = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"
        masked = redact_text(text, strategy="mask")
        self.assertEqual(masked, "[PRIVATE-KEY-REDACTED]")

    def test_separated_phone_is_normalized_when_masked(self):
        self.assertEqual(redact_text("+86 139 1234 5678", strategy="mask"), "139****5678")


class PlaceholderStrategyTest(unittest.TestCase):
    """占位符：同类型独立编号。"""

    def test_numbering_is_per_type_and_in_order(self):
        text = "13800138000 与 13900139000，邮箱 a@example.com 与 b@example.com"
        result = Redactor(strategy="placeholder").redact(text, verify=False)
        self.assertEqual(
            result.redacted,
            "<PHONE_1> 与 <PHONE_2>，邮箱 <EMAIL_1> 与 <EMAIL_2>",
        )

    def test_replacement_details_recorded(self):
        result = Redactor(strategy="placeholder").redact("电话 13800138000", verify=False)
        self.assertEqual(len(result.replacements), 1)
        self.assertEqual(result.replacements[0].replacement, "<PHONE_1>")
        self.assertEqual(result.replacements[0].strategy, "placeholder")


class PseudonymStrategyTest(unittest.TestCase):
    """一致性假名（详细一致性测试见 test_pseudonym.py）。"""

    def test_consistent_within_document(self):
        text = "申请人：李娜；复核人：李娜。"
        result = Redactor(strategy="pseudonym").redact(text, verify=False)
        self.assertEqual(result.redacted.count("李娜"), 0)
        names = [rep.replacement for rep in result.replacements]
        self.assertEqual(names[0], names[1])

    def test_credentials_fall_back_to_mask(self):
        result = Redactor(strategy="pseudonym").redact(
            "password=Pr0d-Pass-2026!", verify=False
        )
        self.assertEqual(result.redacted, "password=********")


class RemoveAndFormatPreserveTest(unittest.TestCase):
    """删除与格式保留。"""

    def test_remove(self):
        self.assertEqual(redact_text("电话 13800138000 谢谢", strategy="remove"), "电话  谢谢")

    def test_format_preserve_keeps_length_and_separators(self):
        text = "手机 138-0013-8000，邮箱 ab.cd@example.com"
        preserved = redact_text(text, strategy="format_preserve")
        self.assertEqual(len(preserved), len(text))
        self.assertIn("-", preserved)
        self.assertIn("@", preserved)
        self.assertIn("***", preserved)
        self.assertNotIn("13800138000", preserved)
        self.assertNotIn("example.com", preserved)

    def test_format_preserve_of_plain_run(self):
        self.assertEqual(redact_text("13800138000", strategy="format_preserve"), "***********")

    def test_all_strategies_preserve_non_sensitive_text(self):
        text = "普通文本，不含敏感信息。"
        for name in STRATEGIES:
            with self.subTest(strategy=name):
                self.assertEqual(redact_text(text, strategy=name), text)


class ApplyReplacementsTest(unittest.TestCase):
    """替换写回与边界检查。"""

    def test_applies_in_position_order(self):
        text = "abcdef"
        spans = [
            Span(type="PHONE", start=4, end=6, text="ef"),
            Span(type="EMAIL", start=0, end=2, text="ab"),
        ]
        replacements = [Replacement(span=span, replacement="*") for span in spans]
        self.assertEqual(apply_replacements(text, replacements), "*cd*")

    def test_overlapping_replacements_raise(self):
        text = "abcdef"
        spans = [
            Span(type="PHONE", start=0, end=4, text="abcd"),
            Span(type="EMAIL", start=2, end=6, text="cdef"),
        ]
        replacements = [Replacement(span=span, replacement="*") for span in spans]
        with self.assertRaises(ValueError):
            apply_replacements(text, replacements)

    def test_unknown_strategy_raises(self):
        with self.assertRaises(ValueError):
            redact_spans("abc", [], "no-such-strategy")

    def test_empty_span_list_is_noop(self):
        self.assertEqual(redact_spans("abc", [], "mask")[0], "abc")

    def test_context_counters_are_independent_per_call(self):
        context = RedactionContext()
        first = redact_spans("13800138000", [Span(type="PHONE", start=0, end=11, text="13800138000")], "placeholder", context=context)[0]
        second = redact_spans("13900139000", [Span(type="PHONE", start=0, end=11, text="13900139000")], "placeholder", context=context)[0]
        self.assertEqual(first, "<PHONE_1>")
        self.assertEqual(second, "<PHONE_2>")


if __name__ == "__main__":
    unittest.main()
