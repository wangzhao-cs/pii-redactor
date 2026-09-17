"""HTML 报告测试：结构完整、自包含、高亮后文本与原文一致。"""

import html.parser
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import Redactor  # noqa: E402
from pii_redactor.report import render_report, write_report  # noqa: E402

SAMPLE = (
    "客户 张明远 反馈：联系电话 13800138000，身份证 110101199003078515，"
    "收货地址：上海市浦东新区张江镇祖冲之路1500号。"
)


class _BalancedParser(html.parser.HTMLParser):
    """检查标签闭合情况，并收集 <pre> 块的文本。"""

    VOID = {"meta", "br", "img", "input", "link", "hr", "source", "col"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []
        self.pres = []
        self._in_pre = False

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)
        if tag == "pre":
            self._in_pre = True
            self.pres.append("")

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append("未闭合标签：%s（栈顶 %s）" % (tag, self.stack[-1] if self.stack else None))
        else:
            self.stack.pop()
        if tag == "pre":
            self._in_pre = False

    def handle_data(self, data):
        if self._in_pre and self.pres:
            self.pres[-1] += data


class ReportTest(unittest.TestCase):
    """报告渲染。"""

    @classmethod
    def setUpClass(cls):
        cls.result = Redactor(strategy="mask").redact(SAMPLE)
        cls.html = render_report(cls.result, title="测试报告", source_name="unit-test")

    def test_html_is_balanced_and_has_sections(self):
        parser = _BalancedParser()
        parser.feed(self.html)
        self.assertEqual(parser.errors, [])
        self.assertEqual(parser.stack, [])
        self.assertIn("<style>", self.html)
        self.assertIn("<script>", self.html)
        self.assertIn("实体明细", self.html)
        self.assertIn("残留二次校验", self.html)

    def test_no_external_resources(self):
        for marker in ['src="http', 'href="http', "<link", "@import", "url(http"]:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.html)

    def test_highlighted_text_matches_source(self):
        parser = _BalancedParser()
        parser.feed(self.html)
        self.assertEqual(len(parser.pres), 2)
        self.assertEqual(parser.pres[0], SAMPLE)
        self.assertEqual(parser.pres[1], self.result.redacted)

    def test_write_report_creates_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "nested", "report.html")
            path = write_report(target, self.result, source_name="x.md")
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            self.assertEqual(content, render_report(self.result, source_name="x.md"))

    def test_html_escapes_special_characters(self):
        result = Redactor(strategy="mask").redact("邮箱 a<b>c@example.com")
        rendered = render_report(result)
        self.assertNotIn("<b>c@example.com", rendered)
        self.assertIn("&lt;b&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
