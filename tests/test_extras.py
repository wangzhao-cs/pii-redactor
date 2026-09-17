"""可选依赖（jieba / FastAPI）的优雅降级测试。

未安装可选依赖时，核心功能与导入都不应受影响；只有显式调用相关能力时
才给出带安装提示的错误。
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import extras  # noqa: E402


class ExtrasDegradationTest(unittest.TestCase):
    """降级行为。"""

    def test_availability_checks_return_booleans(self):
        self.assertIsInstance(extras.jieba_available(), bool)
        self.assertIsInstance(extras.fastapi_available(), bool)

    def test_segment_always_works(self):
        tokens = extras.segment("联系人张伟，电话13800138000")
        self.assertTrue(any("张伟" in token for token in tokens))
        self.assertGreater(len(tokens), 0)

    def test_name_candidates_filters_by_surname(self):
        candidates = extras.name_candidates("申请人张伟，复核人李娜，公司部门")
        self.assertIn("张伟", candidates)
        self.assertIn("李娜", candidates)

    def test_create_app_without_fastapi_raises_install_hint(self):
        if extras.fastapi_available():  # pragma: no cover - 取决于环境
            app = extras.create_app()
            self.assertTrue(hasattr(app, "routes"))
            return
        with self.assertRaises(RuntimeError) as ctx:
            extras.create_app()
        self.assertIn("pip install", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
