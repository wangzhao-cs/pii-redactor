"""校验算法实现：身份证校验位（GB 11643 / ISO 7064 MOD 11-2）、
Luhn（银行卡）、统一社会信用代码（GB 32100）。

这些算法是本工具箱抑制误报的关键：正则只负责"长得像"，
校验算法负责"真的是"。全部实现仅依赖标准库。
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Optional

__all__ = [
    "ID_WEIGHTS",
    "ID_CHECK_CHARS",
    "ID_CARD_PATTERN",
    "USCC_CHARSET",
    "USCC_WEIGHTS",
    "USCC_PATTERN",
    "normalize_digits",
    "id_card_check_char",
    "is_valid_id_card",
    "id_card_birthdate",
    "luhn_check_digit",
    "luhn_complete",
    "is_luhn_valid",
    "luhn_repair",
    "uscc_check_char",
    "is_valid_uscc",
]

# ---------------------------------------------------------------------------
# 中国大陆居民身份证号（18 位）
# ---------------------------------------------------------------------------

#: ISO 7064 MOD 11-2 加权因子
ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
#: 余数 -> 校验字符映射表
ID_CHECK_CHARS = "10X98765432"

#: 18 位身份证号结构：6 位行政区划 + 8 位出生日期 + 3 位顺序码 + 1 位校验位
ID_CARD_PATTERN = re.compile(
    r"^[1-9]\d{5}"              # 行政区划码不以 0 开头
    r"(?:18|19|20)\d{2}"        # 出生年份（1800-2099）
    r"(?:0[1-9]|1[0-2])"        # 月份
    r"(?:0[1-9]|[12]\d|3[01])"  # 日期
    r"\d{3}"                    # 顺序码
    r"[\dXx]$"                  # 校验位
)


def normalize_digits(raw: str) -> str:
    """去掉分隔符（空格、短横线、点），返回纯数字串。"""
    return re.sub(r"[\s\-.]", "", raw or "")


def id_card_check_char(first17: str) -> str:
    """由身份证前 17 位计算校验字符（GB 11643 / ISO 7064 MOD 11-2）。"""
    if len(first17) != 17 or not first17.isdigit():
        raise ValueError("身份证前 17 位必须是 17 位数字")
    total = sum(int(ch) * w for ch, w in zip(first17, ID_WEIGHTS))
    return ID_CHECK_CHARS[total % 11]


def id_card_birthdate(raw: str) -> Optional[_dt.date]:
    """提取身份证中的出生日期；格式或日期非法时返回 ``None``。"""
    text = normalize_digits(raw).upper()
    if len(text) != 18:
        return None
    try:
        year, month, day = int(text[6:10]), int(text[10:12]), int(text[12:14])
        return _dt.date(year, month, day)
    except ValueError:
        return None


def is_valid_id_card(raw: str, *, check_date: bool = True) -> bool:
    """校验 18 位身份证号：结构 + 校验位（可选出生日期合理性）。

    Args:
        raw: 待校验的号码，允许带空格/短横线分隔。
        check_date: 是否校验出生日期是否为真实存在的日期。

    Returns:
        通过全部启用检查返回 ``True``。
    """
    text = normalize_digits(raw).upper()
    if len(text) != 18 or not ID_CARD_PATTERN.match(text):
        return False
    if id_card_check_char(text[:17]) != text[17]:
        return False
    if check_date:
        born = id_card_birthdate(text)
        if born is None or born > _dt.date.today() or born.year < 1900:
            return False
    return True


# ---------------------------------------------------------------------------
# Luhn（ISO/IEC 7812）—— 银行卡号
# ---------------------------------------------------------------------------


def luhn_check_digit(payload: str) -> str:
    """给定不含校验位的数字串，计算 Luhn 校验位。"""
    digits = normalize_digits(payload)
    if not digits.isdigit():
        raise ValueError("Luhn 输入必须是数字")
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 0:  # 从右往左，偶数位（即原串校验位左侧第一位）翻倍
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return str((10 - total % 10) % 10)


def is_luhn_valid(raw: str) -> bool:
    """校验 Luhn 校验位。"""
    digits = normalize_digits(raw)
    if not digits.isdigit() or len(digits) < 2:
        return False
    return luhn_check_digit(digits[:-1]) == digits[-1]


def luhn_repair(raw: str, *, invalidate: bool = False) -> str:
    """改写数字串末位，使其通过（或故意不通过）Luhn 校验。

    ``invalidate=True`` 时返回一个**故意不满足** Luhn 的末位，
    用于生成"看起来像但不会被校验算法接受"的假数据。
    """
    digits = normalize_digits(raw)
    if len(digits) < 2:
        raise ValueError("长度不足")
    correct = int(luhn_check_digit(digits[:-1]))
    if invalidate:
        return digits[:-1] + str((correct + 1) % 10)
    return digits[:-1] + str(correct)


def luhn_complete(payload: str) -> str:
    """在数字串末尾**追加**正确的 Luhn 校验位（生成合法号码时使用）。"""
    digits = normalize_digits(payload)
    if not digits.isdigit():
        raise ValueError("Luhn 输入必须是数字")
    return digits + luhn_check_digit(digits)


# ---------------------------------------------------------------------------
# 统一社会信用代码（GB 32100-2015）
# ---------------------------------------------------------------------------

#: 31 进制字符集（去掉了易混淆的 I、O、S、V、Z）
USCC_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
#: 加权因子
USCC_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)

#: 18 位：1 位登记管理部门 + 1 位机构类别 + 6 位登记管理机关行政区划 + 9 位主体标识码 + 1 位校验码
USCC_PATTERN = re.compile(
    r"^[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{9}[0-9A-HJ-NPQRTUWXY]$"
)


def uscc_check_char(first17: str) -> str:
    """由统一社会信用代码前 17 位计算校验字符。"""
    text = first17.upper()
    if len(text) != 17:
        raise ValueError("统一社会信用代码前 17 位长度不正确")
    total = 0
    for char, weight in zip(text, USCC_WEIGHTS):
        try:
            value = USCC_CHARSET.index(char)
        except ValueError as exc:  # pragma: no cover - 由调用方保证字符集
            raise ValueError("非法字符 %r" % (char,)) from exc
        total += value * weight
    remainder = 31 - total % 31
    if remainder == 31:
        remainder = 0
    return USCC_CHARSET[remainder]


def is_valid_uscc(raw: str) -> bool:
    """校验 18 位统一社会信用代码（结构 + 校验字符）。"""
    text = (raw or "").strip().upper()
    if len(text) != 18 or not USCC_PATTERN.match(text):
        return False
    return uscc_check_char(text[:17]) == text[17]
