"""脱敏策略：掩码、占位符、一致性假名、删除、格式保留。

所有策略都实现为纯函数 ``(text, spans, context) -> List[Replacement]``，
再由 :func:`apply_replacements` 一次性重写文本；这样可以保证：

* span 之间不会互相干扰（例如替换后的文本不会再次被扫描）；
* 每个 span 的替换结果都可回溯，便于生成报告。

假名（pseudonym）策略使用"固定种子 + 原文哈希"，因此同一原文在任何时候
都会得到同一个假名，且**不依赖出现顺序**。假名全部为合成值（"张某"、
``user0f3a@example.com``、TEST-NET 网段等），与任何真实个体无关。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import checksums
from .models import Span, SpanType
from .names import PSEUDONYM_ORDINALS, PSEUDONYM_SURNAMES

__all__ = [
    "DEFAULT_SEED",
    "Replacement",
    "RedactionContext",
    "STRATEGIES",
    "apply_replacements",
    "redact_spans",
    "mask_strategy",
    "placeholder_strategy",
    "pseudonym_strategy",
    "remove_strategy",
    "format_preserve_strategy",
    "generate_pseudonym",
]

DEFAULT_SEED = "pii-redactor-v1"


@dataclass
class Replacement:
    """一个 span 的替换结果。"""

    span: Span
    replacement: str
    strategy: str = ""

    def to_dict(self) -> Dict[str, object]:
        data = self.span.to_dict()
        data["replacement"] = self.replacement
        data["strategy"] = self.strategy
        return data


@dataclass
class RedactionContext:
    """脱敏过程的共享状态（种子、计数器、假名映射）。"""

    seed: str = DEFAULT_SEED
    strategy: str = "mask"
    counters: Dict[str, int] = field(default_factory=dict)
    pseudonym_map: Dict[str, str] = field(default_factory=dict)
    used_pseudonyms: Dict[str, str] = field(default_factory=dict)

    # -- 工具 -------------------------------------------------------------
    def next_index(self, span_type: str) -> int:
        """返回该类型的下一个占位符序号（从 1 开始）。"""
        self.counters[span_type] = self.counters.get(span_type, 0) + 1
        return self.counters[span_type]

    def digest(self, payload: str, length: int = 8) -> str:
        """``seed + payload`` 的稳定摘要（十六进制）。"""
        raw = ("%s|%s" % (self.seed, payload)).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:length]

    def digits(self, payload: str, count: int) -> str:
        """由摘要派生的稳定数字串（逐位取自摘要）。"""
        digest = self.digest(payload, max(count, 16))
        out = []
        index = 0
        while len(out) < count:
            chunk = digest[index % len(digest)]
            index += 1
            out.append(str(int(chunk, 16) % 10))
        return "".join(out)


# ---------------------------------------------------------------------------
# 掩码
# ---------------------------------------------------------------------------

#: 类型 -> (保留头部字符数, 保留尾部字符数)；None 表示"整段替换为标记"
MASK_RULES: Dict[str, Tuple[int, int]] = {
    SpanType.ID_CARD: (6, 4),
    SpanType.BANK_CARD: (6, 4),
    SpanType.USCC: (4, 2),
    SpanType.PHONE: (3, 4),
    SpanType.EMAIL: (2, 0),          # 邮箱另外处理，域名保留
    SpanType.IPV4: (9, 0),           # 单独处理：保留前两段
    SpanType.IPV6: (4, 0),
    SpanType.MAC: (5, 2),
    SpanType.PLATE: (2, 0),
    SpanType.PASSPORT: (1, 0),
    SpanType.ADDRESS: (6, 2),
    SpanType.PERSON_NAME: (1, 0),
    SpanType.API_KEY: (4, 4),
    SpanType.JWT: (5, 0),
    SpanType.PASSWORD_KV: (0, 0),
    SpanType.PRIVATE_KEY: (0, 0),
}

#: 整段替换的固定标记（避免把私钥、口令掩码成一长串星号）
MASK_MARKERS: Dict[str, str] = {
    SpanType.PRIVATE_KEY: "[PRIVATE-KEY-REDACTED]",
    SpanType.PASSWORD_KV: "********",
}

MASK_CHAR = "*"


def _mask_keep(text: str, head: int, tail: int, filler: str = MASK_CHAR) -> str:
    """保留头部 ``head`` 与尾部 ``tail`` 个字符，中间用 ``filler`` 填充。"""
    length = len(text)
    if head + tail >= length:
        keep = max(1, length // 2)
        return text[:keep] + filler * (length - keep)
    return text[:head] + filler * (length - head - tail) + (text[length - tail:] if tail else "")


def mask_strategy(text: str, spans: Sequence[Span], context: RedactionContext) -> List[Replacement]:
    """掩码策略：保留头尾（如 ``138****1234``），不同类型的保留位数不同。"""
    out: List[Replacement] = []
    for span in spans:
        if span.type in MASK_MARKERS:
            value = MASK_MARKERS[span.type]
        elif span.type == SpanType.EMAIL:
            local, _, domain = span.text.partition("@")
            keep = local[:1] if len(local) <= 2 else local[:2]
            value = "%s%s@%s" % (keep, MASK_CHAR * max(1, len(local) - len(keep)), domain)
        elif span.type == SpanType.IPV4:
            parts = span.text.split(".")
            value = "%s.%s.%s.%s" % (parts[0], parts[1], MASK_CHAR, MASK_CHAR)
        elif span.type == SpanType.PHONE:
            digits = re.sub(r"\D", "", span.text)
            if digits.startswith("86") and len(digits) == 13:
                digits = digits[2:]
            head, tail = MASK_RULES[SpanType.PHONE]
            value = _mask_keep(digits, head, tail)
        else:
            head, tail = MASK_RULES.get(span.type, (2, 2))
            value = _mask_keep(span.text, head, tail)
        out.append(Replacement(span=span, replacement=value, strategy="mask"))
    return out


# ---------------------------------------------------------------------------
# 占位符
# ---------------------------------------------------------------------------


def placeholder_strategy(text: str, spans: Sequence[Span], context: RedactionContext) -> List[Replacement]:
    """占位符策略：``<PHONE_1>``、``<PERSON_NAME_2>``，同类型独立编号。"""
    out: List[Replacement] = []
    for span in spans:
        index = context.next_index(span.type)
        out.append(
            Replacement(
                span=span,
                replacement="<%s_%d>" % (span.type, index),
                strategy="placeholder",
            )
        )
    return out


# ---------------------------------------------------------------------------
# 假名
# ---------------------------------------------------------------------------

#: 凭据类字段不做假名化，统一整体掩码（避免产出看起来可用的假密钥）
_CREDENTIAL_TYPES = frozenset(
    (SpanType.API_KEY, SpanType.JWT, SpanType.PRIVATE_KEY, SpanType.PASSWORD_KV)
)


def _wrong_check_char(correct: str, charset: str, offset: int = 3) -> str:
    """取一个与 ``correct`` 不同的校验字符（保证合成号码不通过校验算法）。"""
    index = (charset.index(correct) + offset) % len(charset)
    return charset[index]


def generate_pseudonym(span: Span, context: RedactionContext) -> str:
    """为一个 span 生成稳定假名（同原文 -> 同假名）。"""
    payload = "%s:%s" % (span.type, span.text)
    if span.type == SpanType.PERSON_NAME:
        digest = context.digest(payload, 8)
        surname = PSEUDONYM_SURNAMES[int(digest[:4], 16) % len(PSEUDONYM_SURNAMES)]
        base = surname + "某"
        name = base
        if name in context.used_pseudonyms and context.used_pseudonyms[name] != payload:
            ordinal_index = int(digest[4:8], 16) % len(PSEUDONYM_ORDINALS)
            name = base + PSEUDONYM_ORDINALS[ordinal_index]
            salt = 1
            while name in context.used_pseudonyms and context.used_pseudonyms[name] != payload:
                ordinal_index = (ordinal_index + 1) % len(PSEUDONYM_ORDINALS)
                name = base + PSEUDONYM_ORDINALS[ordinal_index]
                salt += 1
                if salt > len(PSEUDONYM_ORDINALS):
                    name = base + str(salt)
                    break
        context.used_pseudonyms[name] = payload
        return name

    digits = context.digits(payload, 24)
    digest = context.digest(payload, 12)

    if span.type == SpanType.PHONE:
        prefix = "1" + str(3 + int(digest[0], 16) % 7)
        return prefix + "0000" + digits[:5]  # 11 位：1[3-9] + 4 个 0 + 5 位派生数字
    if span.type == SpanType.ID_CARD:
        body = "110101" + "19000101" + digits[:3]
        correct = checksums.id_card_check_char(body)
        return body + _wrong_check_char(correct, checksums.ID_CHECK_CHARS)
    if span.type == SpanType.BANK_CARD:
        return checksums.luhn_repair("6222" + digits[:12], invalidate=True)
    if span.type == SpanType.USCC:
        body = "91" + "110108" + "".join(
            checksums.USCC_CHARSET[int(ch, 16) % 31] for ch in digest
        )[:9]
        correct = checksums.uscc_check_char(body)
        return body + _wrong_check_char(correct, checksums.USCC_CHARSET, offset=5)
    if span.type == SpanType.EMAIL:
        return "user%s@example.com" % digest[:4]
    if span.type == SpanType.IPV4:
        return "203.0.113.%d" % (int(digest[:2], 16) % 254 + 1)
    if span.type == SpanType.IPV6:
        return "2001:db8::%s" % (digest[:3],)
    if span.type == SpanType.MAC:
        octets = ["02", "00", "00"] + [
            "%02x" % int(digest[i : i + 2], 16) for i in (0, 2, 4)
        ]
        return ":".join(octets)
    if span.type == SpanType.PLATE:
        return "京A%05d" % (int(digest[:5], 16) % 100000)
    if span.type == SpanType.PASSPORT:
        return "E%s" % digits[:8]
    if span.type == SpanType.ADDRESS:
        return "某省某市某区某路%d号" % (int(digest[:4], 16) % 500 + 1)
    return "<%s_%s>" % (span.type, digest[:6])


def pseudonym_strategy(text: str, spans: Sequence[Span], context: RedactionContext) -> List[Replacement]:
    """一致性假名：同原文 -> 同假名（固定种子）；凭据类退化为整体掩码。"""
    out: List[Replacement] = []
    for span in spans:
        if span.type in _CREDENTIAL_TYPES:
            value = MASK_MARKERS.get(span.type, MASK_CHAR * 8)
            out.append(Replacement(span=span, replacement=value, strategy="pseudonym(mask)"))
            continue
        key = "%s:%s" % (span.type, span.text)
        value = context.pseudonym_map.get(key)
        if value is None:
            value = generate_pseudonym(span, context)
            context.pseudonym_map[key] = value
        out.append(Replacement(span=span, replacement=value, strategy="pseudonym"))
    return out


# ---------------------------------------------------------------------------
# 删除 / 格式保留
# ---------------------------------------------------------------------------


def remove_strategy(text: str, spans: Sequence[Span], context: RedactionContext) -> List[Replacement]:
    """删除策略：直接移除敏感片段。"""
    return [Replacement(span=span, replacement="", strategy="remove") for span in spans]


#: 格式保留时保留的结构字符（分隔符/标点），其余（含中文）统一替换为 ``*``
_PRESERVE_CHARS = frozenset(" \t\r\n.\-_/@:;,+()[]{}\"'\\|?&=%<>#*")


def format_preserve_strategy(
    text: str, spans: Sequence[Span], context: RedactionContext
) -> List[Replacement]:
    """格式保留策略：等长替换，每个字符换成 ``*``，仅保留分隔符。"""
    out: List[Replacement] = []
    for span in spans:
        value = "".join(ch if ch in _PRESERVE_CHARS else MASK_CHAR for ch in span.text)
        out.append(Replacement(span=span, replacement=value, strategy="format_preserve"))
    return out


# ---------------------------------------------------------------------------
# 调度
# ---------------------------------------------------------------------------

Strategy = Callable[[str, Sequence[Span], RedactionContext], List[Replacement]]

STRATEGIES: Dict[str, Strategy] = {
    "mask": mask_strategy,
    "placeholder": placeholder_strategy,
    "pseudonym": pseudonym_strategy,
    "remove": remove_strategy,
    "format_preserve": format_preserve_strategy,
}


def apply_replacements(text: str, replacements: Sequence[Replacement]) -> str:
    """把替换结果写回文本（替换区间必须互不重叠）。"""
    out: List[str] = []
    cursor = 0
    for rep in sorted(replacements, key=lambda r: (r.span.start, r.span.end)):
        if rep.span.start < cursor:
            raise ValueError("替换区间重叠: %r" % (rep.span,))
        out.append(text[cursor : rep.span.start])
        out.append(rep.replacement)
        cursor = rep.span.end
    out.append(text[cursor:])
    return "".join(out)


def redact_spans(
    text: str,
    spans: Sequence[Span],
    strategy: str = "mask",
    *,
    seed: str = DEFAULT_SEED,
    context: Optional[RedactionContext] = None,
) -> Tuple[str, List[Replacement]]:
    """按指定策略脱敏，返回 ``(脱敏后文本, 替换明细)``。"""
    if strategy not in STRATEGIES:
        raise ValueError("未知策略 %r，可选：%s" % (strategy, ", ".join(sorted(STRATEGIES))))
    ctx = context if context is not None else RedactionContext(seed=seed, strategy=strategy)
    replacements = STRATEGIES[strategy](text, list(spans), ctx)
    return apply_replacements(text, replacements), replacements
