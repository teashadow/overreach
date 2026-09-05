from __future__ import annotations

import asyncio
import json

import click
from rich.console import Console
from rich.table import Table

from .analyzer import scan_url, write_report
from .banner import OVERREACH_BANNER

console = Console()


def _banner() -> None:
    console.print(f"[bold yellow]{OVERREACH_BANNER}[/bold yellow]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD excessive-agency analyzer."""


@main.command("scan")
@click.argument("url")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-находки по этому пути (контракт пайплайна)")
def scan_cmd(url: str, as_json: str | None) -> None:
    data = asyncio.run(scan_url(url))
    # 🔴 Различаю «проверка не прошла» (rc=1) и «проверка НЕ СОСТОЯЛАСЬ» (rc=2). Вторая опаснее:
    # если MCP-сервер не обнаружен, «низкий риск» — это ложь о безопасности, а не результат.
    # Не печатаю вердикт как итог и выхожу кодом 2 — несостоявшееся не выдаём за чистое.
    if data.get("not_proven"):
        console.print(f"[yellow]НЕ ПРОВЕРЕНО[/yellow]: {data['not_proven']}")
        if as_json:
            __import__("pathlib").Path(as_json).write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        raise SystemExit(2)
    table = Table(title=f"Overreach: {url}")
    table.add_column("инструмент")
    table.add_column("риск")
    table.add_column("")
    table.add_column("почему")
    for item in data["tools"]:
        table.add_row(item["name"], str(item["score"]),
                      "[red]🔴[/red]" if item["критический"] else "", item["почему"])
    console.print(table)
    цвет = {"критический": "red", "высокий": "yellow", "умеренный": "yellow"}.get(data["verdict"], "green")
    console.print(f"Вердикт сервера: [{цвет}]{data['verdict']}[/{цвет}]  ·  "
                  f"макс. риск {data['max_risk']}/10  ·  критических: {data['critical_count']}")
    if as_json:
        __import__("pathlib").Path(as_json).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"JSON: {as_json}")
    # код возврата — тоже вердикт: критический сервер роняет проверку в пайплайне
    if data["critical_count"]:
        raise SystemExit(1)


@main.command("check")
@click.argument("url")
@click.option("--tool", required=True)
def check_cmd(url: str, tool: str) -> None:
    data = asyncio.run(scan_url(url))
    for item in data["tools"]:
        if item["name"] == tool:
            console.print(item)
            return
    console.print(f"tool not found: {tool}")


@main.command("report")
@click.argument("url")
def report_cmd(url: str) -> None:
    path = write_report(asyncio.run(scan_url(url)))
    console.print(f"[green]Report[/green] {path}")


if __name__ == "__main__":
    main()
