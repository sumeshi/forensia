from __future__ import annotations

from rich import print as _rich_print


_LOG_COLORS = {
    "PLAN": "bold cyan",
    "HYPOTHESIS": "bold magenta",
    "QUERY": "bold blue",
    "EXEC": "bold green",
    "CHECK": "bold yellow",
    "RESOLVE": "bold green",
    "REPORT": "bold white",
    "MEMORY": "dim",
    "FALLBACK": "bold yellow",
    "PIVOT": "dim",
    "CAP": "bold red",
}


def log(tag: str, message: str) -> None:
    """Print a color-tagged log message using the investigator._log format.

    This function reproduces the exact print format used by
    ai/investigator.py's _log function::
        [{color}][{tag}[/{color}] {message}
    
    The tag must be one of the keys in _LOG_COLORS.
    """
    color = _LOG_COLORS.get(tag, "white")
    _rich_print(f"[{color}][{tag}][/{color}] {message}")
