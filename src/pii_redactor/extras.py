"""可选增强：jieba 分词、FastAPI 包装。

核心功能不依赖任何第三方库；本模块只在被显式调用时才尝试导入可选依赖，
导入失败时给出明确的安装提示并降级（而不是让整个包崩掉）。

安装::

    pip install "pii-redactor[fastapi]"      # 提供 HTTP 接口
    pip install "pii-redactor[jieba]"        # 提供分词辅助
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = [
    "jieba_available",
    "fastapi_available",
    "segment",
    "name_candidates",
    "create_app",
    "INSTALL_HINT",
]

INSTALL_HINT = (
    "缺少可选依赖，请先安装：pip install 'pii-redactor[fastapi]' 或 "
    "pip install 'pii-redactor[jieba]'"
)


def jieba_available() -> bool:
    """是否安装了 jieba。"""
    try:
        import jieba  # noqa: F401
    except ImportError:
        return False
    return True


def fastapi_available() -> bool:
    """是否安装了 FastAPI（含 uvicorn）。"""
    try:
        import fastapi  # noqa: F401
    except ImportError:
        return False
    return True


def segment(text: str) -> List[str]:
    """中文分词：装了 jieba 用 jieba，否则退化为"按非中文/非字母数字切分"。

    降级实现只用于辅助人名检测，不参与核心判定，因此粗糙是可接受的。
    """
    try:
        import jieba  # type: ignore
    except ImportError:
        return _fallback_segment(text)
    return [token for token in jieba.lcut(text) if token.strip()]


def _fallback_segment(text: str) -> List[str]:
    """无第三方依赖的退化分词。"""
    tokens: List[str] = []
    buffer = ""
    for char in text:
        if "\u4e00" <= char <= "\u9fff":
            buffer += char
        else:
            if buffer:
                tokens.append(buffer)
                buffer = ""
            if char.strip():
                tokens.append(char)
    if buffer:
        tokens.append(buffer)
    return tokens


def name_candidates(text: str) -> List[str]:
    """用分词结果辅助筛出"像人名"的片段（需同时通过姓氏词典检查）。

    该函数只提供候选，最终是否认定为敏感信息仍由
    :class:`pii_redactor.detectors.PersonNameDetector` 的保守规则决定。

    由于分词器可能把"申请人张伟"切成一个整体，这里对每个中文片段再做一次
    滑窗扫描：凡是以姓氏字（或复姓）开头的 2-3 字子串都作为候选。
    """
    from .names import COMPOUND_SURNAMES, SURNAMES

    surnames = set(SURNAMES)
    compounds = tuple(COMPOUND_SURNAMES)
    out: List[str] = []
    seen = set()

    def push(candidate: str) -> None:
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)

    for token in segment(text):
        if not all("\u4e00" <= ch <= "\u9fff" for ch in token):
            continue
        for start in range(len(token)):
            head = token[start:]
            if not (head[0] in surnames or head.startswith(compounds)):
                continue
            for size in (3, 2):
                if len(head) >= size:
                    push(head[:size])
    return out


def create_app():
    """创建 FastAPI 应用（惰性导入；未安装时抛出带安装提示的 ``RuntimeError``）。

    Returns:
        FastAPI 应用实例，提供 ``POST /detect``、``POST /redact``、
        ``POST /verify``、``GET /health`` 四个接口。
    """
    try:
        from fastapi import FastAPI
        from pydantic import BaseModel  # type: ignore
    except ImportError as exc:  # pragma: no cover - 取决于运行环境
        raise RuntimeError(INSTALL_HINT) from exc

    from .detectors import detect_spans
    from .redactor import Redactor
    from .residual import check_residual
    from .strategies import STRATEGIES

    class TextIn(BaseModel):  # type: ignore[misc]
        text: str
        types: Optional[List[str]] = None

    class RedactIn(TextIn):  # type: ignore[misc]
        strategy: str = "mask"
        seed: str = "pii-redactor-v1"

    app = FastAPI(title="pii-redactor", version="0.1.0", description="敏感信息识别与脱敏服务")

    @app.get("/health")
    def health() -> Dict[str, Any]:  # pragma: no cover - 需运行服务
        return {"status": "ok", "strategies": sorted(STRATEGIES)}

    @app.post("/detect")
    def detect_endpoint(payload: TextIn) -> Dict[str, Any]:  # pragma: no cover
        spans = detect_spans(payload.text, types=payload.types)
        return {"total": len(spans), "spans": [span.to_dict() for span in spans]}

    @app.post("/redact")
    def redact_endpoint(payload: RedactIn) -> Dict[str, Any]:  # pragma: no cover
        result = Redactor(types=payload.types, strategy=payload.strategy, seed=payload.seed).redact(
            payload.text
        )
        return result.to_dict()

    @app.post("/verify")
    def verify_endpoint(payload: TextIn) -> Dict[str, Any]:  # pragma: no cover
        report = check_residual(payload.text, types=payload.types)
        return report.to_dict()

    return app
