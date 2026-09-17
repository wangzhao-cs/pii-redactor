"""检测器实现：正则粗筛 + 校验算法复核。

设计约定
--------
* 每个检测器只负责一类（或一类里的两个形态）敏感信息，互不耦合；
* 校验型检测器（身份证、银行卡、统一社会信用代码）必须通过
  :mod:`pii_redactor.checksums` 中的算法才产出 span；
* 启发式检测器（车牌、护照、地址、人名）输出较低的 ``confidence``，
  并尽可能叠加上下文约束，把误报压在可控范围。
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import checksums, names, patterns
from .models import Span, SpanType, is_mask_like, sort_spans

__all__ = [
    "Detector",
    "PhoneDetector",
    "IdCardDetector",
    "BankCardDetector",
    "EmailDetector",
    "IpAddressDetector",
    "MacDetector",
    "UsccDetector",
    "PlateDetector",
    "PassportDetector",
    "AddressDetector",
    "PersonNameDetector",
    "CredentialDetector",
    "default_detectors",
    "detect_spans",
]

_SURNAME_SET = frozenset(names.SURNAMES)
_MOBILE_RE = re.compile(r"^1[3-9]\d{9}$")
_BANK_BIN_HEAD = frozenset("234569")


class Detector:
    """检测器基类。"""

    #: 检测器名称（写入 ``Span.detector``，便于排查误报来源）
    name: str = "detector"
    #: 该检测器可能产出的类型
    types: Tuple[str, ...] = ()

    def detect(self, text: str) -> List[Span]:
        """在 ``text`` 上执行检测，返回 span 列表（不保证互不重叠）。"""
        raise NotImplementedError

    # -- 工具方法 ---------------------------------------------------------
    def _make(
        self,
        span_type: str,
        text: str,
        start: int,
        end: int,
        confidence: float = 1.0,
        meta: Optional[Dict[str, object]] = None,
    ) -> Span:
        return Span(
            type=span_type,
            start=start,
            end=end,
            text=text[start:end],
            confidence=confidence,
            detector=self.name,
            meta=dict(meta or {}),
        )


# ---------------------------------------------------------------------------
# 个人身份信息
# ---------------------------------------------------------------------------


class PhoneDetector(Detector):
    """手机号（支持 +86 / 86 前缀与空格、短横线分隔）与带分隔符的固话。"""

    name = "phone"
    types = (SpanType.PHONE,)

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for match in patterns.PHONE_RE.finditer(text):
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if digits.startswith("86") and len(digits) == 13:
                digits = digits[2:]
            if not _MOBILE_RE.match(digits):
                continue
            separated = raw != digits
            spans.append(
                self._make(
                    SpanType.PHONE,
                    text,
                    match.start(),
                    match.end(),
                    confidence=0.95 if separated else 1.0,
                    meta={"normalized": digits, "kind": "mobile", "separated": separated},
                )
            )
        for match in patterns.LANDLINE_RE.finditer(text):
            normalized = match.group(1) + match.group(2)
            spans.append(
                self._make(
                    SpanType.PHONE,
                    text,
                    match.start(),
                    match.end(),
                    confidence=0.9,
                    meta={"normalized": normalized, "kind": "landline"},
                )
            )
        return spans


class IdCardDetector(Detector):
    """18 位居民身份证号：结构 + ISO 7064 MOD 11-2 校验位 + 出生日期合理性。"""

    name = "id_card"
    types = (SpanType.ID_CARD,)

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for match in patterns.ID_CARD_RE.finditer(text):
            raw = match.group(0)
            if not checksums.is_valid_id_card(raw):
                continue
            birth = checksums.id_card_birthdate(raw)
            spans.append(
                self._make(
                    SpanType.ID_CARD,
                    text,
                    match.start(),
                    match.end(),
                    confidence=1.0,
                    meta={
                        "normalized": raw.upper(),
                        "birthdate": birth.isoformat() if birth else None,
                        "region_code": raw[:6],
                    },
                )
            )
        return spans


class BankCardDetector(Detector):
    """银行卡号：16-19 位数字 + Luhn 校验 + 首位 BIN 合理性。"""

    name = "bank_card"
    types = (SpanType.BANK_CARD,)

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for match in patterns.BANK_CARD_RE.finditer(text):
            raw = match.group(0)
            digits = checksums.normalize_digits(raw)
            if not (16 <= len(digits) <= 19):
                continue
            if digits[0] not in _BANK_BIN_HEAD:
                continue
            if not checksums.is_luhn_valid(digits):
                continue
            spans.append(
                self._make(
                    SpanType.BANK_CARD,
                    text,
                    match.start(),
                    match.end(),
                    confidence=0.98,
                    meta={"normalized": digits, "bin": digits[:6], "luhn": True},
                )
            )
        return spans


class EmailDetector(Detector):
    """电子邮箱地址。"""

    name = "email"
    types = (SpanType.EMAIL,)

    def detect(self, text: str) -> List[Span]:
        return [
            self._make(
                SpanType.EMAIL,
                text,
                m.start(),
                m.end(),
                confidence=1.0,
                meta={"domain": m.group(0).split("@", 1)[1].lower()},
            )
            for m in patterns.EMAIL_RE.finditer(text)
        ]


class IpAddressDetector(Detector):
    """IPv4 / IPv6 地址，统一用 :mod:`ipaddress` 复核，过滤时间戳等伪命中。"""

    name = "ip"
    types = (SpanType.IPV4, SpanType.IPV6)

    #: 版本号线索（"版本 1.2.3.4""v1.2.3.4""1.2.3.4 版本"）不是 IP ——
    #: 这是 IPv4 检测最常见的误报来源，两侧都要看
    _VERSION_BEFORE_RE = re.compile(r"(?:版本|version|ver\.?|v)[\s:：]?$", re.IGNORECASE)
    _VERSION_AFTER_RE = re.compile(r"^\s*(?:版本|version)\b", re.IGNORECASE)

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for match in patterns.IPV4_RE.finditer(text):
            raw = match.group(0)
            if self._VERSION_BEFORE_RE.search(text[max(0, match.start() - 8) : match.start()]):
                continue
            if self._VERSION_AFTER_RE.match(text[match.end() : match.end() + 8]):
                continue
            try:
                ipaddress.IPv4Address(raw)
            except ValueError:
                continue
            spans.append(self._make(SpanType.IPV4, text, match.start(), match.end()))
        for match in patterns.IPV6_RE.finditer(text):
            raw = match.group(0)
            try:
                ipaddress.IPv6Address(raw)
            except ValueError:
                continue
            spans.append(
                self._make(
                    SpanType.IPV6,
                    text,
                    match.start(),
                    match.end(),
                    confidence=0.95,
                )
            )
        return spans


class MacDetector(Detector):
    """MAC 地址（冒号或短横线分隔）。"""

    name = "mac"
    types = (SpanType.MAC,)

    def detect(self, text: str) -> List[Span]:
        return [
            self._make(SpanType.MAC, text, m.start(), m.end(), confidence=0.95)
            for m in patterns.MAC_RE.finditer(text)
        ]


class UsccDetector(Detector):
    """统一社会信用代码（18 位，GB 32100 校验字符）。

    纯数字候选若同时满足身份证或银行卡校验，则让位给对应检测器，
    避免把"身份证/银行卡"误判成"信用代码"。
    """

    name = "uscc"
    types = (SpanType.USCC,)

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for match in patterns.USCC_RE.finditer(text):
            raw = match.group(0)
            if not checksums.is_valid_uscc(raw):
                continue
            if raw.isdigit() and (
                checksums.is_valid_id_card(raw) or checksums.is_luhn_valid(raw)
            ):
                continue
            spans.append(
                self._make(
                    SpanType.USCC,
                    text,
                    match.start(),
                    match.end(),
                    confidence=1.0,
                    meta={"normalized": raw.upper()},
                )
            )
        return spans


class PlateDetector(Detector):
    """机动车号牌：普通牌（7 位）与新能源牌（8 位，含 D/F）。"""

    name = "plate"
    types = (SpanType.PLATE,)

    #: 完整短横线/空格分隔的号牌（如「京 A·12345」）暂不支持，属已知局限
    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for match in patterns.PLATE_RE.finditer(text):
            raw = match.group(0)
            province, letter = match.group(1), match.group(2)
            serial = match.group(3) or match.group(4) or match.group(5) or ""
            digit_count = sum(ch.isdigit() for ch in serial)
            if digit_count < 2:  # 纯字母序号不是合法号牌
                continue
            is_new_energy = match.group(4) is not None or match.group(5) is not None
            if is_new_energy and not (serial.startswith(("D", "F")) or serial.endswith(("D", "F"))):
                continue
            confidence = 0.9 if is_new_energy else 0.85
            spans.append(
                self._make(
                    SpanType.PLATE,
                    text,
                    match.start(),
                    match.end(),
                    confidence=confidence,
                    meta={
                        "province": province,
                        "plate_type": "new_energy" if is_new_energy else "conventional",
                    },
                )
            )
        return spans


class PassportDetector(Detector):
    """护照号启发式：``E``/``G`` + 8 位数字（保守，易漏，标注 confidence 较低）。"""

    name = "passport"
    types = (SpanType.PASSPORT,)

    def detect(self, text: str) -> List[Span]:
        return [
            self._make(SpanType.PASSPORT, text, m.start(), m.end(), confidence=0.6)
            for m in patterns.PASSPORT_RE.finditer(text)
        ]


class AddressDetector(Detector):
    """中文地址启发式：省/市/区县 + 街道/路/镇 + 门牌号。"""

    name = "address"
    types = (SpanType.ADDRESS,)

    _ADMIN_KW = ("省", "市", "区", "县", "旗", "自治区", "自治州")
    _STREET_KW = ("路", "街", "道", "巷", "镇", "乡", "村")
    _TAIL_KW = ("号", "室", "楼", "栋", "单元", "层")

    #: 常见"地址引导词"，命中后从引导词之后开始算地址（避免把"开户行在""位于"算进地址）
    _LEAD_INS = (
        "收货地址", "收件地址", "联系地址", "注册地址", "办公地址", "家庭住址", "现住址",
        "所在地", "居住地", "开户行在", "开户行", "地址", "位于", "寄到", "送到", "发到", "住址",
    )
    #: 地址前的助词/动词，逐字剥掉
    _PARTICLES = frozenset("在的于到是了给由从为和与把被对也就都还")
    _LOCALITY_HEAD_RE = re.compile(
        r"[\u4e00-\u9fa5]{2,8}(?:省|市|区|县|旗|自治州|地区|自治区)"
    )

    def _trim_lead(self, raw: str) -> str:
        """剥掉"开户行在""位于"等前缀，返回真正的地址串。"""
        text = raw
        for _ in range(4):
            trimmed = text
            for lead in self._LEAD_INS:
                if text.startswith(lead) and len(text) > len(lead) + 5:
                    trimmed = text[len(lead):]
                    break
            if trimmed == text and text and text[0] in self._PARTICLES and len(text) > 6:
                trimmed = text[1:]
            if trimmed == text:
                break
            text = trimmed
        return text

    def _plausible(self, raw: str) -> bool:
        if len(raw) < 8:
            return False
        has_admin = any(kw in raw for kw in self._ADMIN_KW)
        has_street = any(kw in raw for kw in self._STREET_KW)
        has_tail = raw.endswith(self._TAIL_KW)
        return has_tail and (has_admin or has_street)

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for match in patterns.ADDRESS_RE.finditer(text):
            raw = match.group(0)
            cleaned = self._trim_lead(raw)
            # 仅在裁剪结果仍以行政区划名开头时接受裁剪，避免误伤
            if cleaned != raw and not self._LOCALITY_HEAD_RE.match(cleaned):
                cleaned = raw
            if not self._plausible(cleaned):
                continue
            start = match.start() + (len(raw) - len(cleaned))
            spans.append(
                self._make(
                    SpanType.ADDRESS,
                    text,
                    start,
                    match.end(),
                    confidence=0.7,
                    meta={"length": len(cleaned), "trimmed": cleaned != raw},
                )
            )
        return spans


class PersonNameDetector(Detector):
    """中文人名（保守）：姓氏词典 + 上下文触发词/敬称双约束。

    约束越严，误报越低、漏报越高。本检测器刻意选择"宁可漏，不可错"，
    只在明确的"姓名："类上下文或"某某先生/女士"结构上产出 span。
    """

    name = "person_name"
    types = (SpanType.PERSON_NAME,)

    _HONORIFIC_SET = tuple(sorted(names.NAME_HONORIFICS, key=len, reverse=True))
    _FORBIDDEN = ("某", "先生", "女士", "公司", "有限")
    #: 以姓氏字开头但基本不会是人名的常见词（职位/领域词），用于压制"安全工程师"类误报
    _STOPWORDS = frozenset(
        {
            "安全", "数据", "网络", "系统", "质量", "研发", "产品", "项目", "客户", "服务",
            "销售", "市场", "人力", "教务", "行政", "运营", "设计", "采购", "客服", "物流",
            "仓储", "质检", "财务", "法务", "资产", "风险", "公关", "商务", "渠道", "品牌",
            "内容", "技术", "工程", "管理", "咨询", "培训", "业务", "支撑", "维护", "监控",
            "信息", "知识", "资源", "环境", "智能", "平台", "档案", "统计", "审计", "监察",
        }
    )

    def _looks_like_name(self, candidate: str) -> bool:
        if not (2 <= len(candidate) <= 4):
            return False
        if any(bad in candidate for bad in self._FORBIDDEN):
            return False
        if candidate in self._STOPWORDS:
            return False
        for compound in names.COMPOUND_SURNAMES:
            if candidate.startswith(compound):
                return 1 <= len(candidate) - len(compound) <= 2
        return candidate[0] in _SURNAME_SET and len(candidate) in (2, 3)

    def _trim(self, candidate: str) -> str:
        for honorific in self._HONORIFIC_SET:
            if candidate.endswith(honorific):
                return candidate[: -len(honorific)]
        return candidate

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        seen = set()
        for match in patterns.NAME_AFTER_TRIGGER_RE.finditer(text):
            candidate = self._trim(match.group(1))
            if not self._looks_like_name(candidate):
                continue
            start = match.start(1)
            end = start + len(candidate)
            if (start, end) in seen:
                continue
            seen.add((start, end))
            spans.append(
                self._make(
                    SpanType.PERSON_NAME,
                    text,
                    start,
                    end,
                    confidence=0.75,
                    meta={"context": match.group(0)[: len(match.group(0)) - len(match.group(1))].strip()},
                )
            )
        for match in patterns.NAME_BEFORE_HONORIFIC_RE.finditer(text):
            candidate = match.group(1)
            if not self._looks_like_name(candidate):
                continue
            start, end = match.span(1)
            if (start, end) in seen:
                continue
            seen.add((start, end))
            spans.append(
                self._make(
                    SpanType.PERSON_NAME,
                    text,
                    start,
                    end,
                    confidence=0.8,
                    meta={"context": "honorific"},
                )
            )
        return spans


class CredentialDetector(Detector):
    """敏感凭据：PEM 私钥、JWT、带前缀的 API Key、键值型口令/密钥。"""

    name = "credential"
    types = (SpanType.API_KEY, SpanType.JWT, SpanType.PRIVATE_KEY, SpanType.PASSWORD_KV)

    def detect(self, text: str) -> List[Span]:
        spans: List[Span] = []
        for match in patterns.PEM_PRIVATE_KEY_RE.finditer(text):
            spans.append(
                self._make(
                    SpanType.PRIVATE_KEY,
                    text,
                    match.start(),
                    match.end(),
                    confidence=1.0,
                    meta={"lines": match.group(0).count("\n") + 1},
                )
            )
        for match in patterns.JWT_RE.finditer(text):
            spans.append(
                self._make(SpanType.JWT, text, match.start(), match.end(), meta={"algo_hint": "eyJ"})
            )
        for vendor, pattern in patterns.API_KEY_PATTERNS:
            for match in pattern.finditer(text):
                spans.append(
                    self._make(
                        SpanType.API_KEY,
                        text,
                        match.start(),
                        match.end(),
                        meta={"vendor": vendor},
                    )
                )
        for match in patterns.GENERIC_KEY_VALUE_RE.finditer(text):
            field, value = match.group(1), match.group(2)
            if is_mask_like(value):  # 已脱敏的占位符（apikey=****）不是凭据
                continue
            start, end = match.span(2)
            spans.append(
                self._make(
                    SpanType.API_KEY,
                    text,
                    start,
                    end,
                    confidence=0.8,
                    meta={"field": field.lower().replace(" ", "_"), "match": "key_value"},
                )
            )
        for match in patterns.PASSWORD_KV_RE.finditer(text):
            if is_mask_like(match.group(2)):  # password=******** 已是掩码
                continue
            field, start, end = match.group(1), *match.span(2)
            spans.append(
                self._make(
                    SpanType.PASSWORD_KV,
                    text,
                    start,
                    end,
                    confidence=0.85,
                    meta={"field": field.strip()},
                )
            )
        return spans


#: 默认检测器集合（顺序即注册顺序，不影响消歧，消歧由优先级表决定）
DEFAULT_DETECTOR_CLASSES: Tuple[type, ...] = (
    CredentialDetector,
    IdCardDetector,
    BankCardDetector,
    UsccDetector,
    EmailDetector,
    IpAddressDetector,
    MacDetector,
    PlateDetector,
    PassportDetector,
    PhoneDetector,
    AddressDetector,
    PersonNameDetector,
)


def default_detectors() -> List[Detector]:
    """构造默认检测器列表。"""
    return [cls() for cls in DEFAULT_DETECTOR_CLASSES]


def detect_spans(
    text: str,
    *,
    types: Optional[Iterable[str]] = None,
    detectors: Optional[Sequence[Detector]] = None,
) -> List[Span]:
    """运行全部检测器并把结果交给 :mod:`pii_redactor.merge` 消歧。

    Args:
        text: 待检测文本。
        types: 只保留这些类型（``None`` 表示全部）。
        detectors: 自定义检测器列表，默认使用 :func:`default_detectors`。

    Returns:
        按位置排序、互不重叠的 span 列表。
    """
    from .merge import resolve_overlaps  # 延迟导入，避免循环依赖

    active = list(detectors) if detectors is not None else default_detectors()
    wanted = set(types) if types is not None else None
    raw: List[Span] = []
    for detector in active:
        if wanted is not None and not (set(detector.types) & wanted):
            continue
        raw.extend(detector.detect(text))
    if wanted is not None:
        raw = [span for span in raw if span.type in wanted]
    merged = resolve_overlaps(raw)
    return sort_spans(merged)
