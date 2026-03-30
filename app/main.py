from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone

from flask import Flask, render_template, request

from app.core.models import ScanRequest, ScanResult
from app.core.plugin_manager import PluginManager
from app.plugins.nmap_tool import NmapTool

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("cadmux-security")

app = Flask(__name__)
plugins = PluginManager()
plugins.register(NmapTool())
recent_scans: deque[ScanResult] = deque(maxlen=30)


@app.get("/")
def home() -> str:
    return render_template(
        "index.html",
        tool_options=plugins.list_tools(),
        scan_options=sorted(NmapTool.SCAN_TYPES.keys()),
        recent_scans=list(recent_scans),
        now=datetime.now(timezone.utc),
    )


@app.post("/scan")
def run_scan() -> str:
    tool_name = request.form.get("tool", "nmap")
    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "quick").strip()
    extra = request.form.get("extra_args", "").strip()
    extra_args = [a for a in extra.split() if a]

    try:
        plugin = plugins.get(tool_name)
        scan_request = ScanRequest(target=target, scan_type=scan_type, extra_args=extra_args)
        result = plugin.scan(scan_request)
        recent_scans.appendleft(result)
        logger.info("scan completed status=%s target=%s", result.status, target)
    except Exception as exc:
        logger.exception("scan failed")
        failure = ScanResult(
            tool=tool_name,
            target=target,
            command="",
            status="error",
            error=str(exc),
        )
        failure.finished_at = datetime.now(timezone.utc)
        recent_scans.appendleft(failure)

    return render_template(
        "index.html",
        tool_options=plugins.list_tools(),
        scan_options=sorted(NmapTool.SCAN_TYPES.keys()),
        recent_scans=list(recent_scans),
        now=datetime.now(timezone.utc),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
