"""正则模式集中定义。

全部模式均为标准库 ``re`` 语法，配合 :mod:`pii_redactor.checksums` 的
校验算法使用（先粗筛"长得像"，再校验"真的是"）。
"""

from __future__ import annotations

import re

from .names import NAME_HONORIFICS, NAME_TRIGGERS

__all__ = [
    "PHONE_RE",
    "LANDLINE_RE",
    "ID_CARD_RE",
    "BANK_CARD_RE",
    "EMAIL_RE",
    "IPV4_RE",
    "IPV6_RE",
    "MAC_RE",
    "USCC_RE",
    "PLATE_RE",
    "PASSPORT_RE",
    "ADDRESS_RE",
    "NAME_AFTER_TRIGGER_RE",
    "NAME_BEFORE_HONORIFIC_RE",
    "JWT_RE",
    "PEM_PRIVATE_KEY_RE",
    "API_KEY_PATTERNS",
    "GENERIC_KEY_VALUE_RE",
    "PASSWORD_KV_RE",
]

# ---------------------------------------------------------------------------
# 电话号码
# ---------------------------------------------------------------------------

#: 手机号：可选 +86 / 86 前缀，允许空格或短横线分隔；11 位，1[3-9] 开头
PHONE_RE = re.compile(
    r"(?<![\d])"
    r"(?:(?:\+?86)[\s\-]?)?"
    r"(1[3-9]\d)[\s\-]?(\d{4})[\s\-]?(\d{4})"
    r"(?![\d])"
)

#: 固定电话：区号 + 号码（必须带短横线，降低误报）
LANDLINE_RE = re.compile(
    r"(?<![\d\-])"
    r"(0\d{2,3})[\s\-](\d{7,8})"
    r"(?![\d\-])"
)

# ---------------------------------------------------------------------------
# 身份证 / 银行卡 / 统一社会信用代码
# ---------------------------------------------------------------------------

#: 身份证号粗筛（结构合法即可，校验位交给算法复核）
ID_CARD_RE = re.compile(
    r"(?<![\d])"
    r"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]"
    r"(?![\dXx])"
)

#: 银行卡号粗筛：16-19 位，允许空格/短横线分隔
BANK_CARD_RE = re.compile(
    r"(?<![\d\-])"
    r"\d(?:[ \-]?\d){15,18}"
    r"(?![\d\-])"
)

#: 统一社会信用代码粗筛
USCC_RE = re.compile(
    r"(?<![0-9A-Za-z])"
    r"[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{9}[0-9A-HJ-NPQRTUWXY]"
    r"(?![0-9A-Za-z])"
)

# ---------------------------------------------------------------------------
# 网络标识
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+"
)

_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?:" + _IPV4_OCTET + r"\.){3}" + _IPV4_OCTET +
    r"(?![\w.])"
)

_IPV6_H = r"[0-9A-Fa-f]{1,4}"
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:"
    r"(?:" + _IPV6_H + r":){7}" + _IPV6_H + r"|"
    r"(?:" + _IPV6_H + r":){1,7}:|"
    r"(?:" + _IPV6_H + r":){1,6}:" + _IPV6_H + r"|"
    r"(?:" + _IPV6_H + r":){1,5}(?::" + _IPV6_H + r"){1,2}|"
    r"(?:" + _IPV6_H + r":){1,4}(?::" + _IPV6_H + r"){1,3}|"
    r"(?:" + _IPV6_H + r":){1,3}(?::" + _IPV6_H + r"){1,4}|"
    r"(?:" + _IPV6_H + r":){1,2}(?::" + _IPV6_H + r"){1,5}|"
    r"" + _IPV6_H + r":(?::" + _IPV6_H + r"){1,6}|"
    r":(?:(?::" + _IPV6_H + r"){1,7}|:)"
    r")"
    r"(?![0-9A-Fa-f:])"
)

MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:\-])"
    r"[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}"
    r"(?![0-9A-Fa-f:\-])"
)

# ---------------------------------------------------------------------------
# 车辆 / 证件
# ---------------------------------------------------------------------------

#: 省份简称 + 发牌机关字母 + 序号（普通 5 位 / 新能源 6 位含 D、F）
PLATE_RE = re.compile(
    r"(?<![0-9A-Za-z\u4e00-\u9fa5])"
    r"([京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川贵云藏陕甘青宁新])"
    r"([A-HJ-NP-Z])"
    r"(?:"
    r"([A-HJ-NP-Z0-9]{5})|"                 # 普通牌：5 位序号
    r"([A-HJ-NP-Z0-9]{5}[DF])|"             # 新能源（D/F 在末位）
    r"([DF][A-HJ-NP-Z0-9]{5})"              # 新能源（D/F 在首位）
    r")"
    r"(?![0-9A-Za-z\u4e00-\u9fa5])"
)

#: 护照号启发式：E/G + 8 位数字（现行普通护照、旧版因私护照）
PASSPORT_RE = re.compile(
    r"(?<![0-9A-Za-z])"
    r"[EG]\d{8}"
    r"(?![0-9A-Za-z])"
)

# ---------------------------------------------------------------------------
# 地址
# ---------------------------------------------------------------------------

_ADDR_KW = r"(?:街道|镇|乡|路|街|大道|巷|村|社区|小区|苑|花园|广场|大厦|公寓)"
_ADDR_NO = r"\d{1,5}(?:号楼|栋|单元|室|层|楼|号)"
_ADDR_FILLER = r"[\u4e00-\u9fa5A-Za-z0-9]{0,12}?"

#: 省/市/区县 + 道路村镇 + 门牌号；尾部允许继续吞掉同一地址里的楼/室
ADDRESS_RE = re.compile(
    "".join(
        [
            r"(?<![\u4e00-\u9fa5])",
            r"(?:[\u4e00-\u9fa5]{2,8}(?:省|自治区|特别行政区))?",
            r"(?:[\u4e00-\u9fa5]{2,10}(?:市|自治州|地区))?",
            r"(?:[\u4e00-\u9fa5]{2,10}(?:区|县|旗|市))?",
            _ADDR_FILLER,
            _ADDR_KW,
            _ADDR_FILLER,
            _ADDR_NO,
            r"(?:",
            _ADDR_FILLER,
            _ADDR_NO,
            r")*",
        ]
    )
)

# ---------------------------------------------------------------------------
# 中文人名（词典 + 上下文，保守策略）
# ---------------------------------------------------------------------------

_NAME_BODY = r"([\u4e00-\u9fa5]{2,4})"

#: 「姓名：张伟」「联系人李娜」式：前置关键词 + 可选分隔符 + 姓名
NAME_AFTER_TRIGGER_RE = re.compile(
    r"(?:"
    + "|".join(NAME_TRIGGERS)
    + r")\s*[:：=＝|｜]?\s*"
    + _NAME_BODY
    + r"(?=[\s，,。;；、)）\]】（【\*#>]|$)"
)

#: 「张伟先生」「李娜女士」式：姓名 + 敬称
NAME_BEFORE_HONORIFIC_RE = re.compile(
    _NAME_BODY
    + r"\s*(?:"
    + "|".join(NAME_HONORIFICS)
    + r")"
)

# ---------------------------------------------------------------------------
# 敏感凭据
# ---------------------------------------------------------------------------

#: JWT：三段 Base64URL，首段以 eyJ 开头（{" 的 Base64 编码）
JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"
)

#: PEM 私钥块（含 BEGIN/END 整体）
PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    r".*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    re.DOTALL,
)

#: 带明确前缀的 API Key / Access Key（前缀 -> 正则）
API_KEY_PATTERNS = (
    ("openai", re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:proj-)?[A-Za-z0-9_\-]{16,}")),
    ("stripe", re.compile(r"(?<![A-Za-z0-9_\-])(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("aws", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])")),
    ("github", re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("google", re.compile(r"(?<![A-Za-z0-9_\-])AIza[0-9A-Za-z_\-]{30,}(?![A-Za-z0-9_\-])")),
    ("slack", re.compile(r"(?<![A-Za-z0-9])(?:xox[abprs]-[A-Za-z0-9\-]{10,})")),
    ("aliyun", re.compile(r"(?<![A-Za-z0-9])LTAI[0-9A-Za-z]{12,}(?![A-Za-z0-9])")),
    ("tencent", re.compile(r"(?<![A-Za-z0-9])AKID[0-9A-Za-z]{16,}(?![A-Za-z0-9])")),
)

#: 通用键值型密钥：api_key/secret/token = "xxxx"，值需足够长才判定
GENERIC_KEY_VALUE_RE = re.compile(
    r"(?i)\b(api[_\-\s]?key|apikey|access[_\-\s]?key|secret[_\-\s]?key|"
    r"client[_\-\s]?secret|auth[_\-\s]?token|access[_\-\s]?token|token|secret)\b"
    r"\s*[:：=＝|｜]\s*[\"']?([A-Za-z0-9_\-./+]{16,})[\"']?"
)

#: 口令字段键值对：password / passwd / pwd / 密码，值长度 >= 4（只脱敏值本身）
#: group(1) = 字段名（含"登录/支付"等修饰），group(2) = 值
_PASSWORD_WORDS = r"(?:\b(?:password|passwd|pwd|passphrase|pass)\b|密码|口令)"
_PASSWORD_MODIFIERS = r"(?:登录|登陆|支付|交易|账户|账号|系统|初始|默认|临时|管理员|超级)"
PASSWORD_KV_RE = re.compile(
    r"(?i)(" + _PASSWORD_MODIFIERS + r"?\s*" + _PASSWORD_WORDS + r")"
    r"\s*[:：=＝|｜]\s*[\"']?([^\s\"'，,;；。|]{4,64})[\"']?"
)
