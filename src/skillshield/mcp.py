"""
MCP tool listings, read into one shared format.

An MCP server publishes a list of tools, and an agent reads every tool's name,
description and input schema. SkillShield recognises three ways a listing is
saved to a file:

- a manifest: a JSON object with a "tools" array, which may also carry
  "serverInfo", "auth" or "authentication", and "transport" or "url";
- a JSON-RPC tools/list response: {"jsonrpc": "2.0", "result": {"tools": [...]}};
- a .jsonl file with one tool object per line.

A JSON file is only a listing when it also has a sign that it comes from MCP:
a top-level "serverInfo" or "jsonrpc", or a tool with an "inputSchema". A file
such as {"tools": [{"name": "eslint"}]} is ordinary JSON.

Zero external dependencies, and no network access.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from json.decoder import scanstring
from typing import Any


@dataclass
class McpTool:
    """
    One tool in a listing.

    Attributes:
        name:         The tool's name
        description:  Its description, or None when it is missing or not a string
        input_schema: Its "inputSchema", or None when it is missing or not an object
        annotations:  Its "annotations", or None when they are missing or not an object
        line:         The line where the tool's object starts in the file (1 when unknown)
        raw:          The tool's whole object, as it was in the file
    """

    name: str
    description: str | None = None
    input_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None
    line: int = 1
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolListing:
    """
    A parsed MCP tool listing.

    Attributes:
        tools:       The tools, in file order
        format:      "manifest", "jsonrpc" or "jsonl"
        server_info: The "serverInfo" object, or None
        auth:        The "auth" (or "authentication") value, as given, or None
        transport:   The "transport" value, as given, or None
        url:         The "url" value, as given, or None
    """

    tools: list[McpTool]
    format: str
    server_info: dict[str, Any] | None = None
    auth: Any = None
    transport: Any = None
    url: Any = None


class ListingError(ValueError):
    """A file is an MCP tool listing, but it cannot be read as one."""


# Invalid JSON that names one of these keys is a broken listing, not a text file.
_LISTING_KEY = re.compile(r'"(?:tools"\s*:|jsonrpc")')
_WHITESPACE = re.compile(r"[ \t\n\r]*")


def parse_listing(text: str, suffix: str) -> ToolListing | None:
    """
    Read a file's text as an MCP tool listing.

    Args:
        text:   The file's text, with line endings normalised to "\\n"
        suffix: The file's extension, such as ".json" or ".jsonl"

    Returns:
        The listing, or None when the file is not a tool listing.

    Raises:
        ListingError: The file is a tool listing that cannot be read.
    """
    text = text[1:] if text.startswith("\ufeff") else text
    suffix = suffix.lower()
    if suffix == ".json":
        return _parse_json(text)
    if suffix == ".jsonl":
        return _parse_jsonl(text)
    return None


def _parse_json(text: str) -> ToolListing | None:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        if not _LISTING_KEY.search(text):
            return None
        where = f"line {exc.lineno}: {exc.msg}" if isinstance(exc, json.JSONDecodeError) else exc
        raise ListingError(f"invalid JSON: {where}") from None
    if not isinstance(data, dict):
        return None

    holder, key_path, form = data, ["tools"], "manifest"
    result = data.get("result")
    if "jsonrpc" in data and isinstance(result, dict) and "tools" in result:
        holder, key_path, form = result, ["result", "tools"], "jsonrpc"
    if "tools" not in holder:
        return None
    items = holder["tools"]
    signed = (
        "serverInfo" in data
        or "jsonrpc" in data
        or (
            isinstance(items, list)
            and any(isinstance(item, dict) and "inputSchema" in item for item in items)
        )
    )
    if not signed:
        return None
    if not isinstance(items, list):
        raise ListingError(f'"tools" is a {type(items).__name__}, not a list')
    for i, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ListingError(f"tool {i + 1} is not an object with a name")

    tools = [_tool(item) for item in items]
    for tool, line in zip(tools, _tool_lines(text, key_path, len(tools))):
        tool.line = line

    def server_field(*names: str) -> Any:
        for source in (data, result if isinstance(result, dict) else {}):
            for name in names:
                if name in source:
                    return source[name]
        return None

    server_info = server_field("serverInfo")
    return ToolListing(
        tools=tools,
        format=form,
        server_info=server_info if isinstance(server_info, dict) else None,
        auth=server_field("auth", "authentication"),
        transport=server_field("transport"),
        url=server_field("url"),
    )


def _parse_jsonl(text: str) -> ToolListing | None:
    """A .jsonl file is a listing when its first line is a named tool and one tool has a schema."""
    tools: list[McpTool] = []
    problem = ""
    for lineno, line in enumerate(text.split("\n"), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (ValueError, RecursionError) as exc:
            item, reason = None, f"invalid JSON: {getattr(exc, 'msg', exc)}"
        else:
            reason = "not an object with a name"
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            if not tools:
                return None
            problem = problem or f"line {lineno}: {reason}"
            continue
        tool = _tool(item)
        tool.line = lineno
        tools.append(tool)
    if not any("inputSchema" in tool.raw for tool in tools):
        return None
    if problem:
        raise ListingError(problem)
    return ToolListing(tools=tools, format="jsonl")


def _tool(item: dict[str, Any]) -> McpTool:
    description = item.get("description")
    schema = item.get("inputSchema")
    annotations = item.get("annotations")
    return McpTool(
        name=item["name"],
        description=description if isinstance(description, str) else None,
        input_schema=schema if isinstance(schema, dict) else None,
        annotations=annotations if isinstance(annotations, dict) else None,
        raw=item,
    )


def _tool_lines(text: str, key_path: list[str], count: int) -> list[int]:
    """The line where each tool starts, or line 1 for every tool if they cannot be found.

    json.loads keeps no positions, so the walk below steps over the same JSON with
    the standard library's decoder, which runs in C, and records where each element
    of the tools array starts. Offsets become lines with one running count.
    """
    try:
        starts = _array_starts(text, key_path)
    except Exception:
        starts = []
    if len(starts) != count:
        return [1] * count
    lines: list[int] = []
    lineno, last = 1, 0
    for start in starts:
        lineno += text.count("\n", last, start)
        last = start
        lines.append(lineno)
    return lines


def _skip(text: str, i: int) -> int:
    return _WHITESPACE.match(text, i).end()


def _array_starts(text: str, key_path: list[str]) -> list[int]:
    decoder = json.JSONDecoder()
    i = _skip(text, 0)
    for key in key_path:
        i = _member_value(text, i, key, decoder)
    if text[i] != "[":
        raise ValueError("not an array")
    starts: list[int] = []
    i = _skip(text, i + 1)
    if text[i] == "]":
        return starts
    while True:
        starts.append(i)
        _, i = decoder.raw_decode(text, i)
        i = _skip(text, i)
        if text[i] == "]":
            return starts
        if text[i] != ",":
            raise ValueError("expected , or ]")
        i = _skip(text, i + 1)


def _member_value(text: str, i: int, key: str, decoder: json.JSONDecoder) -> int:
    """Where the value of a key starts in the object at i. The last one wins, as in json.loads."""
    if text[i] != "{":
        raise ValueError("not an object")
    found = -1
    i = _skip(text, i + 1)
    while text[i] != "}":
        if text[i] != '"':
            raise ValueError("expected a key")
        name, i = scanstring(text, i + 1)
        i = _skip(text, i)
        if text[i] != ":":
            raise ValueError("expected :")
        i = _skip(text, i + 1)
        if name == key:
            found = i
        _, i = decoder.raw_decode(text, i)
        i = _skip(text, i)
        if text[i] == ",":
            i = _skip(text, i + 1)
        elif text[i] != "}":
            raise ValueError("expected , or }")
    if found < 0:
        raise ValueError(f"no {key!r} key")
    return found
