"""终端显示宽度工具：中文字符占 2 列，直接 ``str.ljust`` 会错位。"""

from __future__ import annotations

import unicodedata
from typing import Iterable, List, Sequence

__all__ = ["display_width", "pad", "render_table"]


def display_width(text: str) -> int:
    """返回字符串在等宽终端中的显示列数（CJK 全角算 2 列）。"""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


def pad(text: str, width: int, align: str = "left") -> str:
    """按显示宽度补空格。

    Args:
        text: 待补齐的文本。
        width: 目标显示宽度（列）。
        align: ``left`` 或 ``right``。
    """
    gap = " " * max(0, width - display_width(text))
    return gap + text if align == "right" else text + gap


def render_table(rows: Sequence[Sequence[str]], aligns: Iterable[str] = ()) -> List[str]:
    """把二维字符串渲染成对齐的文本表格行。"""
    if not rows:
        return []
    alignment = list(aligns) or ["left"] * len(rows[0])
    widths = [max(display_width(row[index]) for row in rows) for index in range(len(rows[0]))]
    lines = []
    for row in rows:
        cells = [pad(cell, widths[index], alignment[index]) for index, cell in enumerate(row)]
        lines.append(" ".join(cells).rstrip())
    return lines
