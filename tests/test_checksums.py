"""校验算法测试：身份证（GB 11643 / ISO 7064 MOD 11-2）、Luhn、统一社会信用代码。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import checksums  # noqa: E402

#: 公开资料中广泛使用的测试身份证号（校验位合法）
PUBLIC_TEST_ID = "11010519491231002X"
#: 本项目合成文档中使用的小写 x 校验位身份证
LOWERCASE_X_ID = "11010119900307803x"


def reference_id_check_char(first17: str) -> str:
    """按 ISO 7064 MOD 11-2 独立实现（不调用被测代码）。"""
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    codes = "10X98765432"
    total = 0
    for index, char in enumerate(first17):
        total += int(char) * weights[index]
    return codes[total % 11]


def reference_luhn_check_digit(payload: str) -> str:
    """独立实现 Luhn 校验位计算。"""
    total = 0
    for index, char in enumerate(reversed(payload)):
        value = int(char)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return str((10 - total % 10) % 10)


class IdCardChecksumTest(unittest.TestCase):
    """身份证号校验位与出生日期校验。"""

    def test_check_char_matches_reference_implementation(self):
        samples = [
            "11010119900307851",
            "31010419880615234",
            "44030519951210002",
            "11010519491231002",
            "13010219850312456",
        ]
        for first17 in samples:
            with self.subTest(first17=first17):
                self.assertEqual(
                    checksums.id_card_check_char(first17), reference_id_check_char(first17)
                )

    def test_public_test_id_is_valid(self):
        self.assertTrue(checksums.is_valid_id_card(PUBLIC_TEST_ID))

    def test_lowercase_x_check_char_is_valid(self):
        self.assertTrue(checksums.is_valid_id_card(LOWERCASE_X_ID))

    def test_wrong_check_digit_is_rejected(self):
        self.assertFalse(checksums.is_valid_id_card("110101199003078514"))

    def test_illegal_birth_date_is_rejected_but_can_be_disabled(self):
        first17 = "11010119900230001"
        candidate = first17 + checksums.id_card_check_char(first17)
        self.assertFalse(checksums.is_valid_id_card(candidate))
        self.assertTrue(checksums.is_valid_id_card(candidate, check_date=False))

    def test_wrong_length_and_shape_are_rejected(self):
        for candidate in ["11010119900307851", "1101011990030785155", "abcdefghijklmnopqr"]:
            with self.subTest(candidate=candidate):
                self.assertFalse(checksums.is_valid_id_card(candidate))

    def test_separators_are_normalized(self):
        self.assertTrue(checksums.is_valid_id_card("110101 19900307 8515"))

    def test_birthdate_extraction(self):
        born = checksums.id_card_birthdate("110101199003078515")
        self.assertIsNotNone(born)
        self.assertEqual((born.year, born.month, born.day), (1990, 3, 7))

    def test_check_char_on_bad_input_raises(self):
        with self.assertRaises(ValueError):
            checksums.id_card_check_char("1234")


class LuhnTest(unittest.TestCase):
    """Luhn（ISO/IEC 7812）实现。"""

    def test_check_digit_matches_reference(self):
        for payload in ["6222021234567890", "6217000012345678", "4563510100888888"]:
            with self.subTest(payload=payload):
                self.assertEqual(
                    checksums.luhn_check_digit(payload), reference_luhn_check_digit(payload)
                )

    def test_well_known_test_cards_are_valid(self):
        for card in ["4111111111111111", "378282246310005", "62220212345678903"]:
            with self.subTest(card=card):
                self.assertTrue(checksums.is_luhn_valid(card))

    def test_mutated_check_digit_is_invalid(self):
        self.assertFalse(checksums.is_luhn_valid("4111111111111112"))

    def test_complete_and_repair(self):
        self.assertEqual(checksums.luhn_complete("411111111111111"), "4111111111111111")
        repaired = checksums.luhn_repair("62220212345678909")
        self.assertTrue(checksums.is_luhn_valid(repaired))
        broken = checksums.luhn_repair("62220212345678903", invalidate=True)
        self.assertFalse(checksums.is_luhn_valid(broken))

    def test_non_numeric_input(self):
        self.assertFalse(checksums.is_luhn_valid("abcd"))


class UsccTest(unittest.TestCase):
    """统一社会信用代码（GB 32100）。"""

    def test_reference_implementation_agrees(self):
        charset = "0123456789ABCDEFGHJKLMNPQRTUWXY"
        weights = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]
        for first17 in ["91110108MA01ABCDE", "91310115MA1K4Q5F2", "91110108000000000"]:
            total = sum(charset.index(ch) * w for ch, w in zip(first17, weights))
            remainder = 31 - total % 31
            expected = charset[0 if remainder == 31 else remainder]
            with self.subTest(first17=first17):
                self.assertEqual(checksums.uscc_check_char(first17), expected)

    def test_generated_codes_are_valid(self):
        for code in ["91110108MA01ABCDEN", "91310115MA1K4Q5F2H", "91440300MA5EQ2XY9C"]:
            with self.subTest(code=code):
                self.assertTrue(checksums.is_valid_uscc(code))

    def test_wrong_check_char_is_rejected(self):
        self.assertFalse(checksums.is_valid_uscc("91110108MA01ABCDEM"))

    def test_illegal_characters_are_rejected(self):
        # 字符集不含 I、O、S、V、Z
        self.assertFalse(checksums.is_valid_uscc("91110108MA01ABCDEI"))

    def test_all_digit_code_is_valid(self):
        self.assertTrue(checksums.is_valid_uscc("911101080000000007"))


class NormalizeTest(unittest.TestCase):
    """分隔符归一化。"""

    def test_normalize_digits_removes_separators(self):
        self.assertEqual(checksums.normalize_digits("6222 0212-3456.7890"), "6222021234567890")
        self.assertEqual(checksums.normalize_digits(""), "")


if __name__ == "__main__":
    unittest.main()
