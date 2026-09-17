"""Python API 示例（零第三方依赖）。

运行::

    python examples/api_demo.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor import (  # noqa: E402
    Redactor,
    check_residual,
    detect,
    redact,
    redact_text,
)


def main() -> None:
    text = (
        "姓名：李文博，手机 +86 139 1234 5678，身份证 110101199003078515，"
        "邮箱 liwenbo1990@example.com，工资卡 62220212345678903。"
    )
    print("=" * 72)
    print("原文：\n%s" % text)

    # 1) 只检测
    print("-" * 72)
    print("检测命中的 span：")
    for span in detect(text):
        print("  %-13s %-10s %s" % (span.type, "%d-%d" % (span.start, span.end), span.text))

    # 2) 五种策略一次跑全
    print("-" * 72)
    for strategy in ["mask", "placeholder", "pseudonym", "remove", "format_preserve"]:
        result = Redactor(strategy=strategy).redact(text)
        print("[%s]\n  %s" % (strategy, result.redacted.replace("\n", " ")))
        if result.residual is not None:
            print("  %s" % result.residual.summary())

    # 3) 一致性假名：同一原文 -> 同一假名
    print("-" * 72)
    sample = "申请人：王强；审核人：王强；担保人：李明。"
    print("假名策略：%s" % redact_text(sample, strategy="pseudonym"))

    # 4) 残留二次校验：故意只脱敏手机号
    print("-" * 72)
    spans = detect(text)
    partial = redact(text, strategy="format_preserve", types=["PHONE"], verify=False)
    report = check_residual(partial.redacted, original_spans=spans)
    print("只脱敏手机号后的残留校验：%s" % report.summary())
    print("残留明细（前 5 条）：%s" % json.dumps(
        [span.to_dict() for span in report.residual_spans[:5]], ensure_ascii=False, indent=2
    ))

    # 5) 结果结构化输出（可直接入库/上报）
    print("-" * 72)
    payload = Redactor(strategy="mask").redact(text).to_dict(include_text=False)
    print("结构化结果：%s" % json.dumps(payload["stats"], ensure_ascii=False))


if __name__ == "__main__":
    main()
