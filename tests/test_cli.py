"""CLI 冒烟测试：detect / redact / report / eval 四个子命令。"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(REPO_ROOT, "data", "samples")
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))


def run_cli(*args, stdin=None):
    """以两个子进程无关的方式运行 CLI，返回 CompletedProcess。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(REPO_ROOT, "src")
    return subprocess.run(
        [sys.executable, "-m", "pii_redactor", *args],
        cwd=REPO_ROOT,
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=180,
    )


class DetectCommandTest(unittest.TestCase):
    """detect 子命令。"""

    def test_detect_file(self):
        proc = run_cli("detect", os.path.join(SAMPLES, "01_resume.md"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("身份证号", proc.stdout)
        self.assertIn("李文博", proc.stdout)

    def test_detect_json_output(self):
        proc = run_cli("detect", os.path.join(SAMPLES, "04_form.md"), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        types = {span["type"] for span in payload["spans"]}
        self.assertIn("ID_CARD", types)
        self.assertIn("PASSWORD_KV", types)

    def test_detect_types_filter(self):
        proc = run_cli("detect", os.path.join(SAMPLES, "02_support_ticket.md"), "--types", "PLATE,IPV4")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("京A12345", proc.stdout)
        self.assertNotIn("张明远", proc.stdout)

    def test_detect_unknown_type_exits_nonzero(self):
        proc = run_cli("detect", os.path.join(SAMPLES, "01_resume.md"), "--types", "NOPE")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("未知类型", proc.stderr)

    def test_detect_from_stdin(self):
        proc = run_cli("detect", "-", "--json", stdin="联系电话 13800138000\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["total"], 1)


class RedactCommandTest(unittest.TestCase):
    """redact 子命令。"""

    def test_redact_to_stdout_with_verify_summary(self):
        proc = run_cli("redact", os.path.join(SAMPLES, "01_resume.md"), "-s", "placeholder")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("<PHONE_1>", proc.stdout)
        self.assertNotIn("139 1234 5678", proc.stdout)
        self.assertIn("残留校验", proc.stderr)

    def test_redact_writes_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "out.md")
            proc = run_cli(
                "redact", os.path.join(SAMPLES, "03_chat_log.md"), "-s", "pseudonym", "-o", target
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(target, encoding="utf-8") as handle:
                content = handle.read()
            self.assertNotIn("13612345678", content)
            self.assertIn("某", content)

    def test_fail_on_leak_returns_code_two(self):
        proc = run_cli(
            "redact",
            os.path.join(SAMPLES, "01_resume.md"),
            "--types",
            "PHONE",
            "--fail-on-leak",
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_clean_redaction_exits_zero_with_fail_on_leak(self):
        proc = run_cli(
            "redact", os.path.join(SAMPLES, "06_system_log.md"), "--fail-on-leak", "-o", os.devnull
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


class ReportCommandTest(unittest.TestCase):
    """report 子命令：自包含 HTML。"""

    def test_report_is_self_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "report.html")
            proc = run_cli("report", os.path.join(SAMPLES, "02_support_ticket.md"), "-o", target)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(target, encoding="utf-8") as handle:
                html = handle.read()
            self.assertIn("<!DOCTYPE html>", html)
            self.assertIn("<style>", html)
            self.assertIn("<script>", html)
            # 不引用任何外部资源
            self.assertNotIn('src="http', html)
            self.assertNotIn('href="http', html)
            self.assertNotIn("<link", html)
            self.assertIn("残留二次校验", html)


class EvalCommandTest(unittest.TestCase):
    """eval 子命令与 --version。"""

    def test_eval_prints_table_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "eval.json")
            proc = run_cli("eval", "--json", target, "--no-leakage", "--types", "PHONE,ID_CARD")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("micro", proc.stdout)
            with open(target, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["config"]["mode"], "exact")
            self.assertIn("micro", payload)
            self.assertGreater(payload["micro"]["tp"], 0)

    def test_version_flag(self):
        proc = run_cli("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("pii-redactor", proc.stdout)

    def test_missing_file_reports_error(self):
        proc = run_cli("detect", "/nonexistent/file.txt")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("找不到文件", proc.stderr)


if __name__ == "__main__":
    unittest.main()
