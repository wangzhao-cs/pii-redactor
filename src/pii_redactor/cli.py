"""命令行入口：``detect`` / ``redact`` / ``eval`` / ``report``。

示例::

    python -m pii_redactor detect data/samples/01_resume.md
    python -m pii_redactor redact data/samples/02_support_ticket.md --strategy placeholder -o /tmp/out.md
    python -m pii_redactor report data/samples/01_resume.md -o results/demo.html
    python -m pii_redactor eval --json results/eval.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import __version__
from .detectors import default_detectors
from .evaluate import EvalResult, evaluate_corpus, format_table, load_labels
from .models import Span, SpanType, TYPE_LABELS
from .redactor import Redactor
from .report import write_report
from .strategies import STRATEGIES
from .textwidth import pad as _pad

__all__ = ["main", "build_parser"]

_TYPE_CHOICES = sorted(SpanType.ALL)


def _read_input(path: str) -> str:
    """读取输入：``-`` 表示标准输入。"""
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _parse_types(raw: Optional[str]) -> Optional[List[str]]:
    if not raw:
        return None
    types = [item.strip().upper() for item in raw.replace("，", ",").split(",") if item.strip()]
    unknown = [item for item in types if item not in TYPE_LABELS]
    if unknown:
        raise SystemExit("未知类型：%s\n可选类型：%s" % (", ".join(unknown), ", ".join(_TYPE_CHOICES)))
    return types


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""
    parser = argparse.ArgumentParser(
        prog="pii-redactor",
        description="敏感信息识别与脱敏工具箱：检测 / 脱敏 / 残留二次校验 / 评测",
    )
    parser.add_argument("--version", action="version", version="pii-redactor %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    detect = sub.add_parser("detect", help="检测文本中的敏感信息")
    detect.add_argument("input", help="输入文件路径，或 - 表示标准输入")
    detect.add_argument("--types", help="只检测这些类型（逗号分隔，如 PHONE,ID_CARD）")
    detect.add_argument("--json", action="store_true", help="以 JSON 输出")
    detect.add_argument("--min-confidence", type=float, default=0.0, help="过滤低置信度命中（0-1）")

    redact = sub.add_parser("redact", help="脱敏文本")
    redact.add_argument("input", help="输入文件路径，或 - 表示标准输入")
    redact.add_argument(
        "-s", "--strategy", default="mask", choices=sorted(STRATEGIES), help="脱敏策略（默认 mask）"
    )
    redact.add_argument("--types", help="只脱敏这些类型（逗号分隔）")
    redact.add_argument("-o", "--output", help="输出文件；省略则打印到标准输出")
    redact.add_argument("--report", help="同时生成 HTML 对比报告到该路径")
    redact.add_argument("--seed", default=None, help="假名种子（默认取内置值）")
    redact.add_argument("--no-verify", action="store_true", help="跳过残留二次校验")
    redact.add_argument("--json", action="store_true", help="以 JSON 输出结果摘要")
    redact.add_argument("--fail-on-leak", action="store_true", help="发现残留泄漏时以退出码 2 结束")

    report = sub.add_parser("report", help="生成自包含 HTML 对比报告")
    report.add_argument("input", help="输入文件路径，或 - 表示标准输入")
    report.add_argument("-o", "--output", default="results/report.html", help="报告输出路径")
    report.add_argument("-s", "--strategy", default="mask", choices=sorted(STRATEGIES))
    report.add_argument("--types", help="只处理这些类型")

    evaluate = sub.add_parser("eval", help="在内置合成标注集上评测")
    evaluate.add_argument("--labels", help="金标文件路径（默认 data/labels.json）")
    evaluate.add_argument("--data-dir", help="样本目录（默认仓库 data/）")
    evaluate.add_argument("--types", help="只评测这些类型")
    evaluate.add_argument("-s", "--strategy", default="mask", choices=sorted(STRATEGIES))
    evaluate.add_argument("--mode", default="exact", choices=["exact", "relaxed"])
    evaluate.add_argument("--no-leakage", action="store_true", help="跳过泄漏率评估")
    evaluate.add_argument("--json", nargs="?", const="-", help="输出 JSON 结果（可带文件路径）")
    evaluate.add_argument("--out", help="把 JSON 结果写入文件")
    return parser


def _cmd_detect(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    redactor = Redactor(types=_parse_types(args.types), min_confidence=args.min_confidence)
    spans = redactor.detect(text)
    if args.json:
        payload = {
            "input": args.input,
            "characters": len(text),
            "total": len(spans),
            "stats": _stats(spans),
            "spans": [span.to_dict() for span in spans],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print("输入：%s（%d 字符）" % (args.input, len(text)))
    if not spans:
        print("未检出敏感信息。")
        return 0
    print("检出 %d 处敏感信息：" % len(spans))
    print(
        "%s %s %s %s %s"
        % (_pad("#", 4), _pad("类型", 22), _pad("位置", 12), _pad("内容", 26), "检测器")
    )
    for index, span in enumerate(spans, 1):
        preview = span.text.replace("\n", "\\n")
        if len(preview) > 22:
            preview = preview[:21] + "…"
        label = "%s(%s)" % (span.type, TYPE_LABELS.get(span.type, ""))
        print(
            "%s %s %s %s %s"
            % (
                _pad(str(index), 4),
                _pad(label, 22),
                _pad("%d-%d" % (span.start, span.end), 12),
                _pad(preview, 26),
                span.detector,
            )
        )
    return 0


def _stats(spans: Sequence[Span]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for span in spans:
        counts[span.type] = counts.get(span.type, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _cmd_redact(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    redactor = Redactor(types=_parse_types(args.types), strategy=args.strategy)
    if args.seed:
        redactor.seed = args.seed
    result = redactor.redact(text, verify=not args.no_verify)

    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(result.redacted, encoding="utf-8")
    if args.report:
        write_report(args.report, result, source_name=args.input)
    if args.json:
        print(json.dumps(result.to_dict(include_text=not args.output), ensure_ascii=False, indent=2))
    elif not args.output:
        sys.stdout.write(result.redacted)
        if not result.redacted.endswith("\n"):
            sys.stdout.write("\n")
    if not args.json:
        sys.stderr.write(
            "策略=%s 命中=%d %s\n%s\n"
            % (
                result.strategy,
                result.total,
                _stats(result.spans),
                result.residual.summary() if result.residual else "（未做残留校验）",
            )
        )
        if args.output:
            sys.stderr.write("已写入：%s\n" % args.output)
        if args.report:
            sys.stderr.write("报告：%s\n" % args.report)
    if args.fail_on_leak and result.residual is not None and not result.residual.ok:
        return 2
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    redactor = Redactor(types=_parse_types(args.types), strategy=args.strategy)
    result = redactor.redact(text, verify=True)
    path = write_report(args.output, result, source_name=args.input)
    print("报告已生成：%s（命中 %d 处，策略 %s）" % (path, result.total, result.strategy))
    if result.residual is not None:
        print(result.residual.summary())
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    result: EvalResult = evaluate_corpus(
        labels_path=args.labels,
        data_dir=args.data_dir,
        types=_parse_types(args.types),
        strategy=args.strategy,
        mode=args.mode,
        check_leakage=not args.no_leakage,
    )
    print(format_table(result))
    payload = result.to_dict()
    if args.json:
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.json != "-":
            Path(args.json).parent.mkdir(parents=True, exist_ok=True)
            Path(args.json).write_text(text + "\n", encoding="utf-8")
            print("JSON 结果已写入：%s" % args.json)
        else:
            print(text)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("JSON 结果已写入：%s" % args.out)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI 主函数，返回退出码。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "detect": _cmd_detect,
        "redact": _cmd_redact,
        "report": _cmd_report,
        "eval": _cmd_eval,
    }
    try:
        return handlers[args.command](args)
    except FileNotFoundError as exc:
        sys.stderr.write("找不到文件：%s\n" % exc)
        return 1
    except ValueError as exc:
        sys.stderr.write("错误：%s\n" % exc)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
