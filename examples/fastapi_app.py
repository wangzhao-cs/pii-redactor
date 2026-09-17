"""FastAPI 服务示例（可选依赖，核心功能不依赖它）。

安装与运行::

    uv pip install --python .venv/bin/python "fastapi" "uvicorn"
    .venv/bin/uvicorn examples.fastapi_app:app --port 8000

随后可试::

    curl -s localhost:8000/detect -H 'content-type: application/json' \\
        -d '{"text": "联系 13800138000"}'
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from pii_redactor.extras import INSTALL_HINT, create_app, fastapi_available  # noqa: E402

if not fastapi_available():
    raise SystemExit(INSTALL_HINT)

app = create_app()
