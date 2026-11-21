"""Serve the built WebUI with an SPA fallback to index.html for non-API paths."""
from pathlib import Path

from fastapi.responses import FileResponse, HTMLResponse

from .service import ApiError

PLACEHOLDER = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CRAB server</title></head>
<body style="font-family: sans-serif; max-width: 40rem; margin: 3rem auto">
<h1>CRAB server is running</h1>
<p>The WebUI assets are not installed. The API is available under <code>/api/v1</code>.</p>
<p>Build the WebUI from a source checkout, then restart the server:</p>
<pre>cd web
npm ci
npm run build</pre>
<p>The build writes to <code>crab_risk_scan/server/static/</code>. Release wheels and the server image include it.</p>
</body></html>
"""
IMMUTABLE = {"Cache-Control": "public, max-age=31536000, immutable"}
NO_CACHE = {"Cache-Control": "no-cache"}


def register(app, static_dir):
    static_dir = Path(static_dir)

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def webui(path: str):
        if path == "api" or path.startswith("api/"):
            raise ApiError(404, "Not Found")
        index = static_dir / "index.html"
        if not index.is_file():
            if path == "":
                return HTMLResponse(PLACEHOLDER)
            raise ApiError(404, "Not Found")
        root = static_dir.resolve()
        if path:
            candidate = (static_dir / path).resolve()
            if candidate.is_relative_to(root) and candidate.is_file():
                headers = IMMUTABLE if path.startswith("assets/") else NO_CACHE
                return FileResponse(candidate, headers=headers)
            if path.startswith("assets/"):
                raise ApiError(404, "Not Found")
        return FileResponse(index, headers=NO_CACHE)
