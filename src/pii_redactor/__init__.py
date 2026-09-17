"""pii-redactor：敏感信息识别与脱敏工具箱。

核心能力（零第三方依赖）：

* **检测**：中国大陆身份证号（GB 11643 校验位）、手机号、银行卡（Luhn）、
  邮箱、IPv4/IPv6、MAC、统一社会信用代码、车牌、护照号、地址、中文人名，
  以及 API Key / JWT / PEM 私钥 / 口令字段等敏感凭据；
* **消歧**：重叠 span 按"优先级 + 最长匹配"裁决；
* **脱敏**：``mask`` / ``placeholder`` / ``pseudonym`` / ``remove`` /
  ``format_preserve`` 五种策略；
* **残留二次校验**：对脱敏结果重扫 + 强校验类型专项判定，输出泄漏率；
* **评测**：内置合成标注集，输出 span 级 P/R/F1（分类型 + micro/macro）与泄漏率。

Example:
    >>> from pii_redactor import Redactor
    >>> Redactor(strategy="mask").redact("身份证 110101199003078515").redacted
    '身份证 110101********8515'
"""

from __future__ import annotations

__version__ = "0.1.0"

from .detectors import Detector, default_detectors, detect_spans
from .evaluate import EvalResult, Metrics, evaluate_corpus, load_labels, match_spans
from .models import HARD_TYPES, TYPE_LABELS, Span, SpanType
from .redactor import RedactionResult, Redactor, detect, redact, redact_text, verify
from .residual import ResidualReport, check_residual
from .strategies import DEFAULT_SEED, STRATEGIES, Replacement

__all__ = [
    "__version__",
    "Detector",
    "default_detectors",
    "detect_spans",
    "Redactor",
    "RedactionResult",
    "detect",
    "redact",
    "redact_text",
    "verify",
    "Span",
    "SpanType",
    "TYPE_LABELS",
    "HARD_TYPES",
    "check_residual",
    "ResidualReport",
    "STRATEGIES",
    "Replacement",
    "DEFAULT_SEED",
    "evaluate_corpus",
    "EvalResult",
    "Metrics",
    "match_spans",
    "load_labels",
]
