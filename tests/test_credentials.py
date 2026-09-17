"""敏感凭据检测测试：API Key、JWT、PEM 私钥、口令键值对。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import detect  # noqa: E402
from pii_redactor.models import SpanType  # noqa: E402

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMDAwMSIsImV4cCI6MTc5MDAwMDAwMH0"
    ".7Xk2Qw9RtFzB4mNsPd8Uv6YaHcE1JgLo"
)
PEM_SAMPLE = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFAKEKEY001\n"
    "-----END PRIVATE KEY-----"
)


def find(text, span_type):
    return [span for span in detect(text) if span.type == span_type]


class ApiKeyTest(unittest.TestCase):
    """带前缀的 API Key / Access Key。"""

    def test_openai_style_key(self):
        spans = find("api_key=sk-proj-AbCdEfGhIjKlMnOpQrStUvWx1234", SpanType.API_KEY)
        self.assertEqual(len(spans), 1)
        self.assertTrue(spans[0].text.startswith("sk-proj-"))

    def test_aws_access_key_id(self):
        spans = find("AKIA2E7QPZFAKEEXAMPL region=cn-north-1", SpanType.API_KEY)
        self.assertEqual([span.text for span in spans], ["AKIA2E7QPZFAKEEXAMPL"])
        self.assertEqual(spans[0].meta["vendor"], "aws")

    def test_github_token(self):
        spans = find("token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", SpanType.API_KEY)
        self.assertEqual(spans[0].meta["vendor"], "github")

    def test_short_random_word_not_matched(self):
        self.assertEqual(find("说明文档里的 secret 字样", SpanType.API_KEY), [])

    def test_generic_key_value_requires_long_value(self):
        self.assertEqual(find("token=short", SpanType.API_KEY), [])
        spans = find("access_token=AbCdEfGhIjKlMnOpQrSt", SpanType.API_KEY)
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].meta["field"], "access_token")


class JwtTest(unittest.TestCase):
    """JWT 三段结构。"""

    def test_jwt_detected(self):
        spans = find("Authorization: Bearer %s" % JWT_SAMPLE, SpanType.JWT)
        self.assertEqual([span.text for span in spans], [JWT_SAMPLE])

    def test_two_segment_string_not_jwt(self):
        self.assertEqual(find("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0", SpanType.JWT), [])


class PrivateKeyTest(unittest.TestCase):
    """PEM 私钥块。"""

    def test_pem_block_detected_as_single_span(self):
        spans = find("私钥内容：\n%s\n（结束）" % PEM_SAMPLE, SpanType.PRIVATE_KEY)
        self.assertEqual(len(spans), 1)
        self.assertTrue(spans[0].text.startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertEqual(spans[0].text.count("\n"), 2)

    def test_public_key_is_not_reported_as_private_key(self):
        text = "-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----"
        self.assertEqual(find(text, SpanType.PRIVATE_KEY), [])


class PasswordKeyValueTest(unittest.TestCase):
    """口令键值对：只脱敏值本身。"""

    def test_password_with_equals(self):
        spans = find("password=Pr0d-Pass-2026! user=app_ro", SpanType.PASSWORD_KV)
        self.assertEqual([span.text for span in spans], ["Pr0d-Pass-2026!"])

    def test_chinese_key_with_colon(self):
        spans = find("登录密码：Passw0rd!2026。", SpanType.PASSWORD_KV)
        self.assertEqual([span.text for span in spans], ["Passw0rd!2026"])
        self.assertEqual(spans[0].meta["field"], "登录密码")

    def test_markdown_table_pipe_separator(self):
        spans = find("| 支付密码 | 889900 |", SpanType.PASSWORD_KV)
        self.assertEqual([span.text for span in spans], ["889900"])

    def test_masked_value_is_not_reported(self):
        self.assertEqual(find("password=********", SpanType.PASSWORD_KV), [])

    def test_too_short_value_ignored(self):
        self.assertEqual(find("密码：123", SpanType.PASSWORD_KV), [])

    def test_bare_word_password_without_separator(self):
        self.assertEqual(find("请勿在工单中粘贴密码或口令。", SpanType.PASSWORD_KV), [])


class CredentialPriorityTest(unittest.TestCase):
    """凭据与其它类型的重叠消歧。"""

    def test_jwt_not_split_into_api_key(self):
        spans = detect("token %s" % JWT_SAMPLE)
        jwt = [span for span in spans if span.type == SpanType.JWT]
        self.assertEqual(len(jwt), 1)
        self.assertTrue(all(
            not span.overlaps(jwt[0]) for span in spans if span.type != SpanType.JWT
        ))


if __name__ == "__main__":
    unittest.main()
