"""假名一致性专项测试：同原文 -> 同假名、固定种子、冲突处理、合成值不可通过校验。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import Redactor, checksums  # noqa: E402
from pii_redactor.models import Span, SpanType  # noqa: E402
from pii_redactor.strategies import RedactionContext, generate_pseudonym  # noqa: E402


class PseudonymConsistencyTest(unittest.TestCase):
    """一致性：同原文恒得同一假名，且与出现顺序无关。"""

    def test_same_text_same_pseudonym_across_calls(self):
        first = Redactor(strategy="pseudonym").redact("联系人 张伟", verify=False)
        second = Redactor(strategy="pseudonym").redact("联系人 张伟", verify=False)
        self.assertEqual(first.redacted, second.redacted)

    def test_same_text_same_pseudonym_within_document(self):
        text = "申请人：王强；复核人：王强；备注：王强已确认。"
        result = Redactor(strategy="pseudonym").redact(text, verify=False)
        replacements = [rep.replacement for rep in result.replacements]
        self.assertEqual(len(set(replacements)), 1)

    def test_different_names_get_different_pseudonyms(self):
        text = "申请人：王强；审核人：李明。"
        result = Redactor(strategy="pseudonym").redact(text, verify=False)
        values = [rep.replacement for rep in result.replacements]
        self.assertEqual(len(values), 2)
        self.assertNotEqual(values[0], values[1])

    def test_pseudonym_is_anonymised_chinese_name(self):
        result = Redactor(strategy="pseudonym").redact("姓名：张伟", verify=False)
        value = result.replacements[0].replacement
        self.assertEqual(len(value), 2)
        self.assertIn("某", value)

    def test_seed_changes_pseudonym(self):
        default = Redactor(strategy="pseudonym").redact("姓名：张伟", verify=False)
        other = Redactor(strategy="pseudonym", seed="another-seed").redact(
            "姓名：张伟", verify=False
        )
        self.assertNotEqual(default.redacted, other.redacted)

    def test_many_names_stay_distinct(self):
        """多人名场景下假名必须互不相同（姓氏不同或使用「甲乙丙」后缀）。"""
        text = "申请人：张伟；审核人：张敏；审批人：张强；担保人：张磊。"
        result = Redactor(strategy="pseudonym").redact(text, verify=False)
        values = [rep.replacement for rep in result.replacements]
        self.assertEqual(len(values), 4)
        self.assertEqual(len(set(values)), 4)
        self.assertTrue(all("某" in value for value in values))

    def test_collision_uses_ordinal_suffix(self):
        """同姓氏不同人：先到者用「张某」，冲突者加「甲/乙」后缀。"""
        span = Span(type=SpanType.PERSON_NAME, start=0, end=2, text="张伟")
        base = generate_pseudonym(span, RedactionContext())
        # 人为构造冲突：同名假名已被另一个原文占用
        context = RedactionContext()
        context.used_pseudonyms[base] = "PERSON_NAME:其他人"
        alternative = generate_pseudonym(span, context)
        self.assertNotEqual(base, alternative)
        self.assertTrue(alternative.startswith(base))

    def test_same_original_reuses_pseudonym_even_after_other_collisions(self):
        span = Span(type=SpanType.PERSON_NAME, start=0, end=2, text="张伟")
        context = RedactionContext()
        first = generate_pseudonym(span, context)
        second = generate_pseudonym(span, context)
        self.assertEqual(first, second)


class PseudonymSynthesisedValuesTest(unittest.TestCase):
    """合成值必须是"看起来像但不可用"的假数据。"""

    def test_fake_id_card_fails_checksum(self):
        result = Redactor(strategy="pseudonym").redact("身份证 110101199003078515", verify=False)
        fake = result.replacements[0].replacement
        self.assertEqual(len(fake), 18)
        self.assertFalse(checksums.is_valid_id_card(fake))

    def test_fake_bank_card_fails_luhn(self):
        result = Redactor(strategy="pseudonym").redact("账号 62220212345678903", verify=False)
        fake = result.replacements[0].replacement
        self.assertEqual(len(fake), 16)
        self.assertTrue(fake.startswith("6222"))
        self.assertFalse(checksums.is_luhn_valid(fake))

    def test_fake_uscc_fails_checksum(self):
        result = Redactor(strategy="pseudonym").redact("代码 91110108MA01ABCDEN", verify=False)
        fake = result.replacements[0].replacement
        self.assertEqual(len(fake), 18)
        self.assertFalse(checksums.is_valid_uscc(fake))

    def test_fake_ip_uses_documentation_range(self):
        result = Redactor(strategy="pseudonym").redact("IP 192.168.31.24", verify=False)
        self.assertTrue(result.replacements[0].replacement.startswith("203.0.113."))

    def test_fake_email_uses_example_domain(self):
        result = Redactor(strategy="pseudonym").redact("邮箱 li.na@corp.cn", verify=False)
        self.assertTrue(result.replacements[0].replacement.endswith("@example.com"))

    def test_fake_phone_keeps_mobile_shape(self):
        result = Redactor(strategy="pseudonym").redact("电话 13800138000", verify=False)
        fake = result.replacements[0].replacement
        self.assertEqual(len(fake), 11)
        self.assertRegex(fake, r"^1[3-9]\d{9}$")
        self.assertNotEqual(fake, "13800138000")

    def test_type_preserved_in_replacement(self):
        result = Redactor(strategy="pseudonym").redact(
            "身份证 110101199003078515 与 电话 13800138000", verify=False
        )
        types = [rep.span.type for rep in result.replacements]
        self.assertEqual(types, [SpanType.ID_CARD, SpanType.PHONE])


if __name__ == "__main__":
    unittest.main()
