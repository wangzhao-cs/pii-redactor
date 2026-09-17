"""HTML 对比报告：单文件、内联 CSS/JS、零外部资源。

生成的报告包含：统计卡片、原文/脱敏结果并排视图（命中片段高亮）、
类型筛选器、实体明细表、残留校验结论。
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .models import Span, TYPE_LABELS
from .redactor import RedactionResult
from .residual import ResidualReport

__all__ = ["render_report", "write_report", "TYPE_COLORS"]

#: 类型 -> 高亮颜色（低饱和，打印友好）
TYPE_COLORS: Dict[str, str] = {
    "ID_CARD": "#ffd6a5",
    "PHONE": "#a0e7e5",
    "BANK_CARD": "#ffadad",
    "EMAIL": "#bdb2ff",
    "IPV4": "#caffbf",
    "IPV6": "#b5ead7",
    "MAC": "#d0f4de",
    "USCC": "#fdcb6e",
    "PLATE": "#f9c74f",
    "PASSPORT": "#cdb4db",
    "ADDRESS": "#ffe066",
    "PERSON_NAME": "#ffc6ff",
    "API_KEY": "#ff8fab",
    "JWT": "#f28482",
    "PRIVATE_KEY": "#e07a5f",
    "PASSWORD_KV": "#ef476f",
}

_STYLE = """
:root{--bg:#f7f8fa;--fg:#1f2328;--muted:#6b7280;--line:#e5e7eb;--card:#ffffff;}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
     font-family:-apple-system,"PingFang SC","Helvetica Neue","Microsoft YaHei",sans-serif;
     font-size:14px;line-height:1.7}
h1{font-size:20px;margin:0 0 4px}
h2{font-size:15px;margin:24px 0 8px;color:#111827}
.sub{color:var(--muted);font-size:12px;margin-bottom:16px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:120px}
.card b{display:block;font-size:20px;font-weight:600}
.card span{color:var(--muted);font-size:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media (max-width:900px){.grid{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:15px}
.panel h3{margin:0 0 10px;font-size:13px;color:var(--muted);font-weight:600;letter-spacing:.04em}
pre{margin:0;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
mark{border-radius:3px;padding:1px 0;background:#ffe8a3}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:12.5px}
th,td{border-bottom:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
th{background:#f3f4f6;font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:none}
code{font-family:ui-monospace,Menlo,monospace;background:#f3f4f6;padding:1px 4px;border-radius:4px}
.filters{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}
.filters label{background:var(--card);border:1px solid var(--line);border-radius:999px;
               padding:3px 10px;font-size:12px;cursor:pointer;user-select:none;display:flex;align-items:center;gap:6px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.ok{color:#0f7b3f;font-weight:600}
.bad{color:#c1121f;font-weight:600}
.note{color:var(--muted);font-size:12px;margin-top:8px}
.legend{display:flex;flex-wrap:wrap;gap:8px;font-size:12px;color:var(--muted);margin-top:8px}
.empty{color:var(--muted)}
"""

_SCRIPT = """
(function(){
  var boxes = document.querySelectorAll('.filters input[type=checkbox]');
  boxes.forEach(function(box){
    box.addEventListener('change', function(){
      var t = box.getAttribute('data-type');
      document.querySelectorAll('mark[data-t="'+t+'"]').forEach(function(el){
        el.style.opacity = box.checked ? '1' : '0.15';
        el.style.background = box.checked ? '' : 'transparent';
      });
      document.querySelectorAll('tr[data-t="'+t+'"]').forEach(function(el){
        el.style.display = box.checked ? '' : 'none';
      });
    });
  });
  var toggle = document.getElementById('toggle-plain');
  if (toggle) {
    toggle.addEventListener('change', function(){
      document.querySelectorAll('mark').forEach(function(el){
        el.style.background = toggle.checked ? 'transparent' : '';
      });
    });
  }
})();
"""


def _highlight(text: str, spans: Sequence[Span], *, css_class: str, attr: str = "data-t") -> str:
    """把 span 区间包成 ``<mark>``，其余部分转义。"""
    out: List[str] = []
    cursor = 0
    for span in sorted(spans, key=lambda s: (s.start, s.end)):
        if span.start < cursor:
            continue
        out.append(html.escape(text[cursor : span.start]))
        color = TYPE_COLORS.get(span.type, "#ffe8a3")
        label = TYPE_LABELS.get(span.type, span.type)
        out.append(
            '<mark class="%s" %s="%s" title="%s" style="background:%s">%s</mark>'
            % (
                css_class,
                attr,
                html.escape(span.type),
                html.escape("%s · %s" % (label, span.detector or "gold")),
                color,
                html.escape(text[span.start : span.end]),
            )
        )
        cursor = span.end
    out.append(html.escape(text[cursor:]))
    return "".join(out)


def _replacement_spans(result: RedactionResult) -> List[Span]:
    """把"替换结果"包装成 span，用于在脱敏视图里高亮。"""
    out: List[Span] = []
    for rep in result.replacements:
        if not rep.replacement:
            continue
        out.append(
            Span(
                type=rep.span.type,
                start=rep.span.start,
                end=rep.span.start + len(rep.replacement),
                text=rep.replacement,
                confidence=rep.span.confidence,
                detector=rep.span.detector,
            )
        )
    return out


def _residual_block(residual: Optional[ResidualReport]) -> str:
    if residual is None:
        return ""
    status = '<span class="ok">通过</span>' if residual.ok else '<span class="bad">未通过</span>'
    rows = []
    for span in residual.residual_spans[:50]:
        rows.append(
            "<tr><td>%s</td><td><code>%s</code></td><td>%d</td><td>%s</td></tr>"
            % (
                html.escape(TYPE_LABELS.get(span.type, span.type)),
                html.escape(span.text[:60]),
                span.start,
                "强校验类型（判定为泄漏）" if span.type in
                ("ID_CARD", "BANK_CARD", "USCC", "API_KEY", "JWT", "PRIVATE_KEY", "PASSWORD_KV")
                else "启发式类型",
            )
        )
    table = (
        '<table><thead><tr><th>类型</th><th>残留内容</th><th>位置</th><th>判定</th></tr></thead>'
        "<tbody>%s</tbody></table>" % "".join(rows)
        if rows
        else '<p class="empty">未发现残留命中。</p>'
    )
    return (
        "<h2>残留二次校验</h2><p>结论：%s　泄漏率 <b>%.2f%%</b>（%d/%d）　"
        "强校验类型残留 %d 处　启发式残留 %d 处</p>%s"
        % (
            status,
            100.0 * residual.leak_rate,
            len(residual.leaked_spans),
            len(residual.original_spans),
            len(residual.hard_hits),
            len(residual.soft_hits),
            table,
        )
    )


def render_report(
    result: RedactionResult,
    *,
    title: str = "敏感信息脱敏报告",
    source_name: str = "input.txt",
) -> str:
    """渲染自包含 HTML 报告。"""
    spans = result.spans
    types_present = sorted({span.type for span in spans})
    filters = "".join(
        '<label><input type="checkbox" data-type="%s" checked>'
        '<span class="dot" style="background:%s"></span>%s (%d)</label>'
        % (
            html.escape(name),
            TYPE_COLORS.get(name, "#ffe8a3"),
            html.escape(TYPE_LABELS.get(name, name)),
            sum(1 for s in spans if s.type == name),
        )
        for name in types_present
    )
    rows = []
    for index, rep in enumerate(result.replacements, 1):
        rows.append(
            '<tr data-t="%s"><td>%d</td><td>%s</td><td><code>%s</code></td>'
            "<td>%d–%d</td><td><code>%s</code></td><td>%s</td><td>%.2f</td></tr>"
            % (
                html.escape(rep.span.type),
                index,
                html.escape(TYPE_LABELS.get(rep.span.type, rep.span.type)),
                html.escape(rep.span.text),
                rep.span.start,
                rep.span.end,
                html.escape(rep.replacement) or "(删除)",
                html.escape(rep.span.detector),
                rep.span.confidence,
            )
        )
    table = (
        "<table><thead><tr><th>#</th><th>类型</th><th>原文片段</th><th>位置</th>"
        "<th>替换为</th><th>检测器</th><th>置信度</th></tr></thead><tbody>%s</tbody></table>"
        % "".join(rows)
        if rows
        else '<p class="empty">未检出敏感信息。</p>'
    )
    summary = "、".join(
        "%s %d" % (TYPE_LABELS.get(name, name), count) for name, count in result.stats.items()
    ) or "无"

    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>%s</style>
</head>
<body>
<h1>%s</h1>
<div class="sub">来源：%s　策略：<code>%s</code>　种子：<code>%s</code>　生成工具：pii-redactor</div>
<div class="cards">
  <div class="card"><b>%d</b><span>检出敏感片段</span></div>
  <div class="card"><b>%d</b><span>类型数</span></div>
  <div class="card"><b>%s</b><span>原文长度</span></div>
  <div class="card"><b>%s</b><span>脱敏后长度</span></div>
</div>
<p class="sub">命中明细：%s</p>
<div class="filters">%s<label><input type="checkbox" id="toggle-plain">仅看纯文本（关闭高亮）</label></div>
<h2>原文 / 脱敏结果对比</h2>
<div class="grid">
  <div class="panel"><h3>原文（高亮为检出片段）</h3><pre>%s</pre></div>
  <div class="panel"><h3>脱敏结果（高亮为替换内容）</h3><pre>%s</pre></div>
</div>
%s
<h2>实体明细</h2>
%s
<p class="note">本报告由 pii-redactor 自动生成，单文件、零外部依赖；所有数据均来自输入文本。</p>
<script>%s</script>
</body>
</html>
""" % (
        html.escape(title),
        _STYLE,
        html.escape(title),
        html.escape(source_name),
        html.escape(result.strategy),
        html.escape(result.seed),
        len(spans),
        len(types_present),
        len(result.original),
        len(result.redacted),
        html.escape(summary),
        filters,
        _highlight(result.original, spans, css_class="pii"),
        _highlight(result.redacted, _replacement_spans(result), css_class="rep"),
        _residual_block(result.residual),
        table,
        _SCRIPT,
    )


def write_report(path: str, result: RedactionResult, **kwargs) -> str:
    """写出报告文件，返回实际写入的路径。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_report(result, **kwargs), encoding="utf-8")
    return str(target)
