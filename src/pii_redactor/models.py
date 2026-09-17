"""核心数据模型：敏感信息片段（``Span``）与类型常量。

本模块只依赖标准库，定义整个工具箱共享的最小数据结构。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

__all__ = [
    "SpanType",
    "TYPE_LABELS",
    "HARD_TYPES",
    "DEFAULT_PRIORITY",
    "Span",
    "is_mask_like",
]


class SpanType:
    """全部受支持的敏感信息类型名（字符串常量集合）。"""

    # ---- 个人身份信息（PII）----
    ID_CARD = "ID_CARD"          # 中国大陆居民身份证号（18 位，含校验位）
    PHONE = "PHONE"              # 手机号 / 带区号固定电话
    BANK_CARD = "BANK_CARD"      # 银行卡号（16-19 位，Luhn 校验）
    EMAIL = "EMAIL"              # 电子邮箱
    IPV4 = "IPV4"                # IPv4 地址
    IPV6 = "IPV6"                # IPv6 地址
    MAC = "MAC"                  # MAC 地址
    USCC = "USCC"                # 统一社会信用代码
    PLATE = "PLATE"              # 机动车号牌（含新能源）
    PASSPORT = "PASSPORT"        # 护照号（启发式）
    ADDRESS = "ADDRESS"          # 中文地址（启发式）
    PERSON_NAME = "PERSON_NAME"  # 中文人名（词典 + 上下文启发式）

    # ---- 敏感凭据 ----
    API_KEY = "API_KEY"          # API Key / Access Key
    JWT = "JWT"                  # JSON Web Token
    PRIVATE_KEY = "PRIVATE_KEY"  # PEM 私钥块
    PASSWORD_KV = "PASSWORD_KV"  # password / 密码 键值对

    ALL: Tuple[str, ...] = (
        ID_CARD, PHONE, BANK_CARD, EMAIL, IPV4, IPV6, MAC,
        USCC, PLATE, PASSPORT, ADDRESS, PERSON_NAME,
        API_KEY, JWT, PRIVATE_KEY, PASSWORD_KV,
    )


#: 类型 -> 中文显示名（用于 CLI / HTML 报告）
TYPE_LABELS: Dict[str, str] = {
    SpanType.ID_CARD: "身份证号",
    SpanType.PHONE: "电话号码",
    SpanType.BANK_CARD: "银行卡号",
    SpanType.EMAIL: "电子邮箱",
    SpanType.IPV4: "IPv4 地址",
    SpanType.IPV6: "IPv6 地址",
    SpanType.MAC: "MAC 地址",
    SpanType.USCC: "统一社会信用代码",
    SpanType.PLATE: "车牌号",
    SpanType.PASSPORT: "护照号",
    SpanType.ADDRESS: "地址",
    SpanType.PERSON_NAME: "中文人名",
    SpanType.API_KEY: "API 密钥",
    SpanType.JWT: "JWT 令牌",
    SpanType.PRIVATE_KEY: "私钥块",
    SpanType.PASSWORD_KV: "口令字段",
}

#: "硬"类型：命中即代表经过校验算法（校验位 / Luhn / 结构）验证，残留即为泄漏。
HARD_TYPES: Tuple[str, ...] = (
    SpanType.ID_CARD,
    SpanType.BANK_CARD,
    SpanType.USCC,
    SpanType.API_KEY,
    SpanType.JWT,
    SpanType.PRIVATE_KEY,
    SpanType.PASSWORD_KV,
)

#: 类型优先级，数值越大越优先（用于重叠消歧）。凭据 > 强校验标识 > 弱启发式。
DEFAULT_PRIORITY: Dict[str, int] = {
    SpanType.PRIVATE_KEY: 100,
    SpanType.JWT: 96,
    SpanType.API_KEY: 92,
    SpanType.PASSWORD_KV: 88,
    SpanType.USCC: 80,
    SpanType.ID_CARD: 78,
    SpanType.BANK_CARD: 74,
    SpanType.EMAIL: 70,
    SpanType.IPV6: 62,
    SpanType.IPV4: 60,
    SpanType.MAC: 58,
    SpanType.PLATE: 55,
    SpanType.PASSPORT: 50,
    SpanType.PHONE: 45,
    SpanType.ADDRESS: 30,
    SpanType.PERSON_NAME: 20,
}


@dataclass
class Span:
    """一段被识别出的敏感信息。

    Attributes:
        type: :class:`SpanType` 中的类型常量。
        start: 在原文本中的起始下标（含）。
        end: 在原文本中的结束下标（不含）。
        text: 命中文本，恒等于 ``original[start:end]``。
        confidence: 置信度，0.0-1.0；强校验命中为 1.0，启发式为 0.5-0.9。
        detector: 产生该 span 的检测器名称，便于排查误报来源。
        meta: 附加信息（如密码字段名、命中的前缀模式等）。
    """

    type: str
    start: int
    end: int
    text: str
    confidence: float = 1.0
    detector: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError("非法的 span 区间: [%r, %r)" % (self.start, self.end))
        if self.type not in TYPE_LABELS:
            raise ValueError("未知的敏感信息类型: %r" % (self.type,))

    # -- 基本操作 ---------------------------------------------------------
    @property
    def length(self) -> int:
        """span 覆盖的字符数。"""
        return self.end - self.start

    def overlaps(self, other: "Span") -> bool:
        """两个 span 是否有重叠字符。"""
        return self.start < other.end and other.start < self.end

    def contains(self, other: "Span") -> bool:
        """本 span 是否完整包含 ``other``。"""
        return self.start <= other.start and other.end <= self.end

    def same_region(self, other: "Span") -> bool:
        """类型与区间完全一致（用于评测中的精确匹配）。"""
        return self.type == other.type and self.start == other.start and self.end == other.end

    def to_dict(self) -> Dict[str, Any]:
        """转换为可 JSON 序列化的字典。"""
        data: Dict[str, Any] = {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "text": self.text,
            "confidence": round(self.confidence, 4),
        }
        if self.detector:
            data["detector"] = self.detector
        if self.meta:
            data["meta"] = dict(self.meta)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Span":
        """从 :meth:`to_dict` 的输出还原 span。"""
        return cls(
            type=data["type"],
            start=int(data["start"]),
            end=int(data["end"]),
            text=data["text"],
            confidence=float(data.get("confidence", 1.0)),
            detector=data.get("detector", ""),
            meta=dict(data.get("meta", {})),
        )


def sort_spans(spans: Iterable[Span]) -> List[Span]:
    """按 (start, -length) 排序，输出稳定顺序。"""
    return sorted(spans, key=lambda s: (s.start, -s.length, s.type))


#: 判定"掩码痕迹"的字符集合
MASK_CHARS = "*•·#─-"


def is_mask_like(text: str) -> bool:
    """判断字符串是否只是掩码符号（如 ``****``）。

    已经脱敏的字段（``password=********``）在二次校验里会再次"命中"，
    但它们是掩码而不是泄漏，需要排除。
    """
    stripped = text.strip()
    if not stripped:
        return False
    return all(ch in MASK_CHARS for ch in stripped)
