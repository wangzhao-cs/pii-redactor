"""检测器测试：各类型命中与误报抑制。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import detect  # noqa: E402
from pii_redactor.detectors import (  # noqa: E402
    AddressDetector,
    IpAddressDetector,
    PersonNameDetector,
)
from pii_redactor.models import SpanType  # noqa: E402


def find(text, span_type=None):
    """辅助：返回命中列表，可按类型过滤。"""
    spans = detect(text)
    if span_type is None:
        return spans
    return [span for span in spans if span.type == span_type]


class PhoneDetectorTest(unittest.TestCase):
    """手机号与固话。"""

    def test_plain_mobile(self):
        spans = find("联系电话 13800138000。", SpanType.PHONE)
        self.assertEqual([span.text for span in spans], ["13800138000"])

    def test_country_code_and_separators(self):
        for text, expected in [
            ("+86 139 1234 5678", "+86 139 1234 5678"),
            ("86-137-8899-0011", "86-137-8899-0011"),
            ("159-0088-7766", "159-0088-7766"),
        ]:
            with self.subTest(text=text):
                spans = find(text, SpanType.PHONE)
                self.assertEqual(len(spans), 1)
                self.assertEqual(spans[0].text, expected)
                self.assertRegex(spans[0].meta["normalized"], r"^1[3-9]\d{9}$")

    def test_landline(self):
        spans = find("总机 010-88886666，传真 021-56789012", SpanType.PHONE)
        self.assertEqual([span.text for span in spans], ["010-88886666", "021-56789012"])
        self.assertEqual(spans[0].meta["kind"], "landline")

    def test_invalid_mobile_prefix_rejected(self):
        self.assertEqual(find("编号 12345678901 与 12812345678", SpanType.PHONE), [])

    def test_digits_inside_longer_number_not_matched(self):
        self.assertEqual(find("卡号 6222021234567890312345", SpanType.PHONE), [])


class IdCardDetectorTest(unittest.TestCase):
    """身份证号。"""

    def test_valid_id_detected(self):
        spans = find("身份证号：110101199003078515。", SpanType.ID_CARD)
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].meta["birthdate"], "1990-03-07")

    def test_lowercase_check_char_detected(self):
        spans = find("号码 11010119900307803x 已核验", SpanType.ID_CARD)
        self.assertEqual(len(spans), 1)

    def test_bad_checksum_rejected(self):
        self.assertEqual(find("号码 110101199003078514", SpanType.ID_CARD), [])

    def test_fifteen_digit_legacy_id_not_supported(self):
        self.assertEqual(find("旧版号码 110101900307851", SpanType.ID_CARD), [])


class BankCardDetectorTest(unittest.TestCase):
    """银行卡号。"""

    def test_valid_cards(self):
        for number in ["62220212345678903", "6222 0212 3456 7890 3", "6212260200012345670"]:
            with self.subTest(number=number):
                spans = find("账号 %s" % number, SpanType.BANK_CARD)
                self.assertEqual(len(spans), 1)
                self.assertTrue(spans[0].meta["luhn"])

    def test_failed_luhn_rejected(self):
        self.assertEqual(find("账号 62220212345678904", SpanType.BANK_CARD), [])

    def test_long_digit_run_outside_range_rejected(self):
        self.assertEqual(find("流水号 12345678901234567890", SpanType.BANK_CARD), [])


class EmailIpMacTest(unittest.TestCase):
    """邮箱、IP、MAC。"""

    def test_email(self):
        spans = find("邮箱 zhang+work@example.com 可用", SpanType.EMAIL)
        self.assertEqual(spans[0].meta["domain"], "example.com")

    def test_ipv4(self):
        spans = find("来源 192.168.31.24 已记录", SpanType.IPV4)
        self.assertEqual([span.text for span in spans], ["192.168.31.24"])

    def test_ipv4_version_number_not_matched(self):
        detector = IpAddressDetector()
        for text in ["升级至 1.2.3.4 版本", "版本 1.2.3.4 已发布", "version 2.0.1.5"]:
            with self.subTest(text=text):
                self.assertEqual([s for s in detector.detect(text) if s.type == SpanType.IPV4], [])

    def test_ipv6_compressed_and_full(self):
        compressed = find("地址 2001:db8:85a3::8a2e:370:7334", SpanType.IPV6)
        full = find("地址 2001:0db8:85a3:0000:0000:8a2e:0370:7334", SpanType.IPV6)
        self.assertEqual(len(compressed), 1)
        self.assertEqual(len(full), 1)

    def test_time_string_is_not_ipv6(self):
        self.assertEqual(find("时间 03:12:07 触发告警", SpanType.IPV6), [])

    def test_mac(self):
        spans = find("设备 00:1B:44:11:3A:B7 已注册", SpanType.MAC)
        self.assertEqual([span.text for span in spans], ["00:1B:44:11:3A:B7"])

    def test_dot_notation_mac_not_supported(self):
        self.assertEqual(find("设备 001b.44aa.11b7", SpanType.MAC), [])


class PlateAndPassportTest(unittest.TestCase):
    """车牌与护照启发式。"""

    def test_conventional_plate(self):
        spans = find("车牌 京A12345 已登记", SpanType.PLATE)
        self.assertEqual(spans[0].meta["plate_type"], "conventional")

    def test_new_energy_plate(self):
        spans = find("车牌 沪AD12345 与 京A12345D", SpanType.PLATE)
        self.assertEqual(len(spans), 2)
        self.assertTrue(all(span.meta["plate_type"] == "new_energy" for span in spans))

    def test_all_letter_serial_rejected(self):
        self.assertEqual(find("编号 京ABCDEFG", SpanType.PLATE), [])

    def test_passport(self):
        spans = find("护照号 E12345678，旧版 G87654321", SpanType.PASSPORT)
        self.assertEqual([span.text for span in spans], ["E12345678", "G87654321"])


class AddressDetectorTest(unittest.TestCase):
    """地址启发式。"""

    def test_standard_address(self):
        spans = find("地址：北京市海淀区中关村大街27号。", SpanType.ADDRESS)
        self.assertEqual([span.text for span in spans], ["北京市海淀区中关村大街27号"])

    def test_address_with_building_and_room(self):
        spans = find("地址：上海市徐汇区漕溪北路88号圣爱大厦1502室。", SpanType.ADDRESS)
        self.assertEqual([span.text for span in spans], ["上海市徐汇区漕溪北路88号圣爱大厦1502室"])

    def test_lead_in_words_are_trimmed(self):
        detector = AddressDetector()
        spans = [s for s in detector.detect("开户行在杭州市西湖区文三路100号。")]
        self.assertEqual([s.text for s in spans], ["杭州市西湖区文三路100号"])
        self.assertTrue(spans[0].meta["trimmed"])

    def test_short_keyword_text_rejected(self):
        self.assertEqual(find("请到服务台咨询。", SpanType.ADDRESS), [])


class PersonNameDetectorTest(unittest.TestCase):
    """人名：词典 + 上下文双约束。"""

    def test_trigger_form(self):
        spans = find("姓名：李文博，男。", SpanType.PERSON_NAME)
        self.assertEqual([span.text for span in spans], ["李文博"])

    def test_honorific_form(self):
        spans = find("王涛先生已完成签收。", SpanType.PERSON_NAME)
        self.assertEqual([span.text for span in spans], ["王涛"])

    def test_markdown_bold_header(self):
        spans = find("**2026-09-15 14:02  客户 李娜**", SpanType.PERSON_NAME)
        self.assertEqual([span.text for span in spans], ["李娜"])

    def test_bare_name_without_context_is_not_detected(self):
        self.assertEqual(find("本次事项由赵鹏飞负责跟进。", SpanType.PERSON_NAME), [])

    def test_job_title_stopword_rejected(self):
        detector = PersonNameDetector()
        for text in ["安全工程师负责该模块", "数据工程师已到位", "客户服务经理到场"]:
            with self.subTest(text=text):
                self.assertEqual(detector.detect(text), [])

    def test_non_name_after_trigger_rejected(self):
        self.assertEqual(find("户名：上海云衡信息技术有限公司", SpanType.PERSON_NAME), [])


if __name__ == "__main__":
    unittest.main()
