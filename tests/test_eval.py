"""评测流程与标注集一致性测试。

注意：本文件中的数字是**回归基线**，与 README 中引用的指标一致。
如果检测器或语料发生变更导致这些数字变化，需要同步更新 README。
"""

import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from pii_redactor.evaluate import (  # noqa: E402
    default_data_dir,
    evaluate_corpus,
    format_table,
    load_documents,
    load_labels,
    match_spans,
)
from pii_redactor.models import TYPE_LABELS, Span  # noqa: E402

#: 当前基线（exact 匹配口径）
BASELINE_TP = 71
BASELINE_FP = 1
BASELINE_FN = 10
#: 金标 span 总数
BASELINE_GOLD = 81


class LabelSetTest(unittest.TestCase):
    """标注集自洽性。"""

    @classmethod
    def setUpClass(cls):
        cls.labels = load_labels()
        cls.documents = load_documents()

    def test_data_dir_resolves_inside_repo(self):
        self.assertTrue(os.path.isdir(str(default_data_dir())))

    def test_documents_loaded(self):
        self.assertEqual(len(self.documents), len(self.labels["documents"]))
        self.assertGreaterEqual(len(self.documents), 6)

    def test_offsets_match_text(self):
        for doc_id, text, spans, _path in self.documents:
            for span in spans:
                with self.subTest(doc_id=doc_id, start=span.start):
                    self.assertEqual(text[span.start : span.end], span.text)

    def test_span_types_are_known(self):
        for doc_id, _text, spans, _path in self.documents:
            for span in spans:
                with self.subTest(doc_id=doc_id, type=span.type):
                    self.assertIn(span.type, TYPE_LABELS)

    def test_spans_are_sorted_and_non_overlapping(self):
        for doc_id, _text, spans, _path in self.documents:
            previous_end = -1
            for span in spans:
                with self.subTest(doc_id=doc_id, start=span.start):
                    self.assertGreaterEqual(span.start, previous_end)
                previous_end = span.end

    def test_every_document_declares_synthetic_data(self):
        for doc_id, text, _spans, _path in self.documents:
            with self.subTest(doc_id=doc_id):
                self.assertIn("虚构", text)

    def test_gold_span_total(self):
        total = sum(len(spans) for _doc_id, _text, spans, _path in self.documents)
        self.assertEqual(total, BASELINE_GOLD)


class CorpusEvaluationTest(unittest.TestCase):
    """语料级评测。"""

    @classmethod
    def setUpClass(cls):
        cls.result = evaluate_corpus()

    def test_micro_metrics_match_baseline(self):
        self.assertEqual(self.result.micro.tp, BASELINE_TP)
        self.assertEqual(self.result.micro.fp, BASELINE_FP)
        self.assertEqual(self.result.micro.fn, BASELINE_FN)

    def test_macro_covers_all_types_in_gold(self):
        self.assertEqual(self.result.macro_types, len(self.result.per_type))
        self.assertGreater(self.result.macro_f1, 0.9)

    def test_per_type_metrics_present(self):
        for name in ["ID_CARD", "PHONE", "PERSON_NAME", "API_KEY", "JWT", "PRIVATE_KEY"]:
            with self.subTest(type=name):
                metrics = self.result.per_type[name]
                self.assertGreater(metrics.support, 0)
                self.assertEqual(metrics.tp + metrics.fn, metrics.support)

    def test_plain_text_sample_has_no_false_positive(self):
        """误报压测：普通中文文本必须零命中。"""
        for report in self.result.documents:
            if report["doc_id"] == "08_plain_text":
                self.assertEqual(report["predicted"], 0)
                self.assertEqual(report["false_positives"], [])
                break
        else:  # pragma: no cover
            self.fail("缺少 08_plain_text 样本")

    def test_core_documents_are_fully_detected(self):
        core = {"01_resume", "02_support_ticket", "03_chat_log", "04_form", "05_contract", "06_system_log"}
        for report in self.result.documents:
            if report["doc_id"] in core:
                with self.subTest(doc_id=report["doc_id"]):
                    self.assertEqual(report["fp"], 0)
                    self.assertEqual(report["fn"], 0)

    def test_edge_case_document_records_known_weaknesses(self):
        for report in self.result.documents:
            if report["doc_id"] == "07_edge_cases":
                self.assertGreater(report["fn"], 0)
                self.assertGreater(report["tp"], 0)
                break
        else:  # pragma: no cover
            self.fail("缺少 07_edge_cases 样本")

    def test_leakage_full_pipeline_below_partial(self):
        configs = self.result.leakage["configs"]
        full = configs["full_pipeline"]
        partial = configs["partial_pipeline_phone_id"]
        self.assertLess(full["leak_rate"], partial["leak_rate"])
        self.assertGreater(partial["recalled_by_residual_check"], 0)
        self.assertLess(full["hard_leaked"], partial["hard_leaked"])

    def test_relaxed_mode_is_not_worse_than_exact(self):
        relaxed = evaluate_corpus(mode="relaxed", check_leakage=False)
        self.assertGreaterEqual(relaxed.micro.tp, self.result.micro.tp)
        self.assertLessEqual(relaxed.micro.fp, self.result.micro.fp)

    def test_result_is_json_serializable(self):
        payload = json.loads(json.dumps(self.result.to_dict(), ensure_ascii=False))
        self.assertIn("micro", payload)
        self.assertIn("leakage", payload)

    def test_format_table_contains_key_sections(self):
        table = format_table(self.result)
        self.assertIn("micro", table)
        self.assertIn("macro", table)
        self.assertIn("泄漏率", table)


class MatchSpansTest(unittest.TestCase):
    """匹配口径单元测试。"""

    def _span(self, span_type, start, end):
        return Span(type=span_type, start=start, end=end, text="x" * (end - start))

    def test_exact_match_requires_identical_boundaries(self):
        gold = [self._span("PHONE", 0, 11)]
        shifted = [self._span("PHONE", 1, 12)]
        metrics, fps, fns = match_spans(gold, shifted, mode="exact")
        self.assertEqual((metrics.tp, len(fps), len(fns)), (0, 1, 1))

    def test_relaxed_match_accepts_overlap(self):
        gold = [self._span("PHONE", 0, 11)]
        shifted = [self._span("PHONE", 1, 12)]
        metrics, fps, fns = match_spans(gold, shifted, mode="relaxed")
        self.assertEqual((metrics.tp, len(fps), len(fns)), (1, 0, 0))

    def test_type_mismatch_is_not_a_match(self):
        gold = [self._span("PHONE", 0, 11)]
        other = [self._span("BANK_CARD", 0, 11)]
        metrics, _fps, fns = match_spans(gold, other, mode="relaxed")
        self.assertEqual((metrics.tp, len(fns)), (0, 1))

    def test_metrics_derived_values(self):
        metrics, _fps, _fns = match_spans([self._span("PHONE", 0, 11)], [self._span("PHONE", 0, 11)])
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.f1, 1.0)
        self.assertEqual(metrics.support, 1)

    def test_invalid_mode_raises(self):
        with self.assertRaises(ValueError):
            match_spans([], [], mode="fuzzy")


if __name__ == "__main__":
    unittest.main()
