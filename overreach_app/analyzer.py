"""Анализатор избыточных прав MCP-агента (excessive agency).

Переписан Невис 11.08.2026 (аудит: АУДИТ_overreach.md). Прежняя версия скорила по подстроке
(`run` ловился в «brunch», `file` в «profile»), брала max вместо накопления и усредняла риск
сервера — один критический инструмент среди двадцати маскировался. Здесь скоринг структурный:
категории операций по границам слов + анализ строгости JSON-схемы, риск накапливается, риск
сервера = максимум и число критических.

🔴 Вердикт ставит код, не модель: ноль обращений к LLM. Каждая находка объясняет «почему».
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from mcpx_app.probe import probe_server

# Категории опасных операций. Слова матчатся по ГРАНИЦЕ (\b...\b), а не как подстрока —
# иначе `run` ловится в «brunch», а `file` в «profile». Каждая категория несёт свой вес и
# своё человекочитаемое объяснение, которое уходит в находку (наш продукт «объясняет почему»).
КАТЕГОРИИ: list[tuple[str, int, str, tuple[str, ...]]] = [
    ("exec", 10, "произвольное исполнение кода/команд",
     ("shell", "exec", "execute", "eval", "spawn", "subprocess", "command", "bash", "sh", "powershell", "sudo", "root")),
    ("destructive", 9, "необратимое изменение данных",
     ("delete", "remove", "destroy", "drop", "purge", "wipe", "truncate", "erase", "rm")),
    ("filesystem", 7, "доступ к файловой системе",
     ("file", "path", "directory", "read_file", "write_file", "filesystem", "fs")),
    ("network", 6, "исходящие сетевые запросы",
     ("http", "https", "fetch", "request", "curl", "url", "webhook", "download", "upload")),
    ("write", 6, "запись/изменение состояния",
     ("write", "update", "modify", "create", "insert", "set", "patch", "put")),
    ("comms", 5, "отправка сообщений наружу",
     ("email", "smtp", "send", "sms", "slack", "telegram", "notify", "message")),
    ("secrets", 8, "доступ к секретам/учётным данным",
     ("secret", "token", "password", "credential", "api_key", "apikey", "auth", "private_key")),
]


def _границы(text: str) -> set[str]:
    """Токены текста по `_`, `-` и границам camelCase, нижний регистр.

    🔴 Поправлено 11.08 при аудите mcpx: прежний `[a-z_]+` считал `_` частью слова, и `run_shell`
    становился ОДНИМ токеном — {run, shell} не матчились, exec-инструмент БЕЗ описания пропускался
    (пруф overreach прошёл случайно: в подопытных были описания со словом shell). Теперь camelCase
    раскалывается, `_`/`-` — разделители: `run_shell`, `deleteRecords` дают правильные слова.
    """
    расколот = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text)
    return set(re.findall(r"[a-z]+", расколот.lower()))


def _анализ_схемы(schema: Any) -> tuple[int, list[str]]:
    """Насколько широко открыт ввод инструмента. Свободный аргумент = агент передаёт что угодно.

    Возвращает (добавочный_риск, причины). Это ядро excessive-agency: опасна не операция сама
    по себе, а операция БЕЗ ограничений на аргумент.
    """
    риск, причины = 0, []
    if not isinstance(schema, dict) or not schema:
        return 4, ["схема пуста — аргументы не ограничены ничем"]
    props = schema.get("properties")
    if not props:
        # {"type":"object"} без properties, {"type":"string"} без ограничений и т.п.
        if schema.get("type") in (None, "object"):
            return 4, ["нет properties — структура аргументов не задана"]
        if schema.get("type") == "string" and not any(k in schema for k in ("enum", "pattern", "const", "maxLength")):
            return 3, ["один строковый аргумент без enum/pattern/maxLength — свободный ввод"]
        return 1, []
    свободных = 0
    for имя, поле in props.items() if isinstance(props, dict) else []:
        if not isinstance(поле, dict):
            continue
        огр = any(k in поле for k in ("enum", "pattern", "const", "maxLength", "format"))
        if поле.get("type") in ("string", None) and not огр:
            свободных += 1
    if свободных:
        риск += min(свободных * 2, 4)
        причины.append(f"свободных строковых аргументов без ограничений: {свободных}")
    return риск, причины


def score_tool(tool: dict[str, Any]) -> dict[str, Any]:
    """Риск одного инструмента: накопление по категориям + строгость схемы. Не max, не подстрока."""
    name = str(tool.get("name", ""))
    desc = str(tool.get("description", ""))
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    слова = _границы(name + " " + desc)

    сработавшие: list[dict[str, Any]] = []
    базовый = 0
    for ключ, вес, объяснение, маркеры in КАТЕГОРИИ:
        попавшие = [m for m in маркеры if m in слова]
        if попавшие:
            сработавшие.append({"категория": ключ, "вес": вес, "почему": объяснение,
                                "маркеры": попавшие})
            базовый = max(базовый, вес)

    # накопление: за каждую ДОПОЛНИТЕЛЬНУЮ категорию сверх сильнейшей +1 (комбинация прав опаснее)
    накопление = max(0, len(сработавшие) - 1)
    риск_схемы, причины_схемы = _анализ_схемы(schema)
    итог = min(базовый + накопление + риск_схемы, 10)

    if not сработавшие and риск_схемы >= 4:
        # опасных слов нет, но ввод ничем не ограничен — это тоже избыточная агентность
        сработавшие.append({"категория": "wide-schema", "вес": риск_схемы,
                            "почему": "широкая схема без опасных операций", "маркеры": []})

    объяснение = "; ".join(
        [f"{с['категория']} ({', '.join(с['маркеры']) or 'схема'}): {с['почему']}" for с in сработавшие]
        + причины_схемы) or "ограниченный инструмент, опасных признаков нет"
    return {
        "name": name,
        "score": итог,
        "категории": [с["категория"] for с in сработавшие],
        "почему": объяснение,
        "критический": итог >= 9,
    }


async def scan_url(url: str, *, порог_критич: int = 9) -> dict[str, Any]:
    data = await probe_server(url)
    tools = [score_tool(tool) for tool in data.get("tools", [])]
    критических = [t["name"] for t in tools if t["score"] >= порог_критич]
    # 🔴 риск сервера = МАКСИМУМ, не среднее: один критический инструмент делает сервер опасным,
    # и усреднение это как раз прячет.
    макс = max((t["score"] for t in tools), default=0)
    return {
        "инструмент": {"имя": "overreach", "цель": url},
        "url": url,
        "mcp_detected": data.get("mcp_detected", False),
        "tools": tools,
        "max_risk": макс,
        "critical_tools": критических,
        "critical_count": len(критических),
        # вердикт: сервер опасен, если есть хоть один критический инструмент
        "verdict": "критический" if критических else "высокий" if макс >= 7 else
                   "умеренный" if макс >= 4 else "низкий",
        "not_proven": ("MCP-сервер не обнаружен по стандартным путям — проверка не состоялась"
                       if not data.get("mcp_detected", False) else ""),
    }


def write_report(data: dict[str, Any]) -> Path:
    out = Path.home() / ".local" / "share" / "mad" / "overreach"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "report.html"
    # 🔴 escape: имя и объяснение приходят от чужого MCP-сервера. Без экранирования инструмент,
    # названный "<script>", превратил бы отчёт в исполняемый html.
    rows = "".join(
        f"<tr><td>{html.escape(t['name'])}</td><td>{t['score']}</td>"
        f"<td>{'🔴' if t['критический'] else ''}</td><td>{html.escape(t['почему'])}</td></tr>"
        for t in data["tools"])
    path.write_text(
        f"<!doctype html><html><head><meta charset='utf-8'><title>overreach</title></head><body>"
        f"<h1>Overreach: {html.escape(str(data['url']))}</h1>"
        f"<p>Вердикт: <b>{html.escape(data['verdict'])}</b> · макс. риск {data['max_risk']}/10 · "
        f"критических инструментов: {data['critical_count']}</p>"
        f"<table border='1' cellpadding='6' cellspacing='0'>"
        f"<tr><th>инструмент</th><th>риск</th><th></th><th>почему</th></tr>{rows}</table>"
        f"<p style='color:#666;font-size:.9em'>Вердикт ставит код, не модель. Риск сервера — по "
        f"самому опасному инструменту, не по среднему.</p></body></html>", encoding="utf-8")
    return path
