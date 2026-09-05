#!/usr/bin/env python3
"""Два синтетических MCP-сервера для проверки самого overreach.

🔴 OPSEC: это СИНТЕТИКА — свои же серверы на localhost, не реальные цели. Инструмент проверяется
на них, а не на чужих системах. Рамка авторизации: тестируем только своё.

  уязвимый — MCP-сервер с избыточными правами: `run_shell` без ограничения аргумента,
             `delete_records` (деструктив), пустые/широкие схемы;
  чистый   — тот же по форме, но строгий: операции безопасные, аргументы с enum/pattern/maxLength.

overreach на уязвимом обязан дать «критический», на чистом — «низкий». Одинаково — сломан overreach.

Отвечает по MCP JSON-RPC (POST /mcp): initialize · tools/list.
Запуск: python3 подопытный_mcp.py уязвимый 8299   |   python3 подопытный_mcp.py чистый 8298
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ИНСТРУМЕНТЫ = {
    "уязвимый": [
        {"name": "run_shell", "description": "Execute an arbitrary shell command on the host.",
         "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}},
        {"name": "delete_records", "description": "Delete records from the production database.",
         "inputSchema": {}},
        {"name": "fetch_url", "description": "Download any URL and return its body.",
         "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
        {"name": "get_weather", "description": "Return the weather for a city.",
         "inputSchema": {"type": "object",
                         "properties": {"city": {"type": "string", "enum": ["MX", "US"]}}}},
    ],
    "чистый": [
        {"name": "get_weather", "description": "Return the weather for a supported city.",
         "inputSchema": {"type": "object",
                         "properties": {"city": {"type": "string", "enum": ["MX", "US", "CA"]}}}},
        {"name": "lookup_order", "description": "Look up an order by its id.",
         "inputSchema": {"type": "object",
                         "properties": {"order_id": {"type": "string", "pattern": "^ORD-[0-9]{6}$"}}}},
        {"name": "list_products", "description": "List catalog products by category.",
         "inputSchema": {"type": "object",
                         "properties": {"category": {"type": "string", "maxLength": 32}}}},
    ],
}


def обработчик(режим: str):
    tools = ИНСТРУМЕНТЫ[режим]

    class Ручка(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            сырое = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            try:
                req = json.loads(сырое)
            except Exception:
                self.send_response(400); self.end_headers(); return
            метод = req.get("method")
            rid = req.get("id", 1)
            if метод == "initialize":
                res = {"protocolVersion": "2024-11-05",
                       "serverInfo": {"name": f"подопытный-{режим}", "version": "0.1.0"},
                       "capabilities": {"tools": {}}}
            elif метод == "tools/list":
                res = {"tools": tools}
            else:
                res = {}
            тело = json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(тело)))
            self.end_headers()
            self.wfile.write(тело)

    return Ручка


if __name__ == "__main__":
    режим = sys.argv[1] if len(sys.argv) > 1 else "чистый"
    порт = int(sys.argv[2]) if len(sys.argv) > 2 else 8298
    HTTPServer(("127.0.0.1", порт), обработчик(режим)).serve_forever()
