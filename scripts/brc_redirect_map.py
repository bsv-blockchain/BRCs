#!/usr/bin/env python3
"""Build the brc.dev number-to-path map from this repository.

brc.dev stores one Vercel KV entry per BRC number and redirects
``/{number}`` to ``https://bsv.brc.dev`` plus that path. The writer that
runs today is ``POST /sync/readme`` in ``sirdeggen/brc-url``
(``app/sync/readme/route.js``). It decides a line is the table header
when the line contains both ``BRC`` and ``Standard``:

    if (line.includes('BRC') && line.includes('Standard')) {
      inTable = true
      headerSeen = true
      continue
    }

The BRC-87 README row contains both substrings (``Standardized`` and
``BRC-22``), so every sync skips it and never writes key 87. A missing
key makes ``app/[brc]/route.js`` concatenate ``null``:

    const path = 'https://bsv.brc.dev' + p || ''

which is the string ``https://bsv.brc.devnull`` and a 307. This script
publishes from the numbered files instead, so a title cannot drop a BRC.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SET_URL = "https://brc.dev/set/url"
FOUR_DIGIT_MARKDOWN = re.compile(r"^(\d{4})\.md$")
NUMBERED_MARKDOWN = re.compile(r"^(\d+)\.md$")
README_ROW = re.compile(r"^(\d+)\s*\|\s*(.*?)\s*$")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SKIP_DIRECTORIES = {".git", "node_modules"}


def deployed_sync_skips_line(line: str) -> bool:
    """Return whether the deployed ``/sync/readme`` parser drops this line.

    Kept in step with ``sirdeggen/brc-url`` ``app/sync/readme/route.js``.
    ``Standardized`` contains ``Standard``, so a normal BRC title can match.
    """

    return "BRC" in line and "Standard" in line


def link_target_to_path(target: str) -> str | None:
    """Convert a README link target to a ``bsv.brc.dev`` path."""

    value = target.strip()
    if not value or value in {"—", "-", "(unused)"}:
        return None
    if value.startswith("./"):
        value = value[2:]
    if value.endswith(".md"):
        value = value[:-3]
    value = value.strip("/")
    if not value:
        return None
    return "/" + value


def parse_readme(markdown: str) -> dict[int, str]:
    """Parse numbered README rows without the deployed header heuristic."""

    rows: dict[int, str] = {}
    for raw in markdown.splitlines():
        line = raw.strip()
        match = README_ROW.match(line)
        if not match:
            continue
        link = MARKDOWN_LINK.search(match.group(2))
        if not link:
            continue
        path = link_target_to_path(link.group(1))
        if path:
            rows[int(match.group(1))] = path
    return rows


def iter_numbered_markdown(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRECTORIES]
        for name in filenames:
            if NUMBERED_MARKDOWN.fullmatch(name):
                yield Path(dirpath) / name


def build_redirect_map(root: Path) -> dict[int, str]:
    """Map each BRC number to the path brc.dev should redirect to.

    Numbered ``NNNN.md`` files are authoritative. README rows fill numbers
    that have no file (BRC 0, the example). A README title is never consulted,
    so wording such as "Standardized ... BRC-22" cannot omit a file.
    """

    mapping: dict[int, str] = {}
    for file in iter_numbered_markdown(root):
        if not FOUR_DIGIT_MARKDOWN.fullmatch(file.name):
            relative = file.relative_to(root).as_posix()
            raise ValueError(f"numbered BRC file must use four digits: {relative}")
        number = int(file.name[:4])
        relative = file.relative_to(root).as_posix()
        path = "/" + relative[: -len(".md")]
        if number in mapping:
            raise ValueError(
                f"duplicate BRC-{number}: {mapping[number]} and {path}"
            )
        mapping[number] = path

    readme = root / "README.md"
    if readme.is_file():
        for number, path in parse_readme(readme.read_text(encoding="utf-8")).items():
            mapping.setdefault(number, path)
    return mapping


def validate_repository(root: Path) -> list[str]:
    """Return problems that would make the published map drop or mis-point a BRC."""

    errors: list[str] = []
    try:
        mapping = build_redirect_map(root)
    except ValueError as exc:
        return [str(exc)]

    files: dict[int, str] = {}
    for file in iter_numbered_markdown(root):
        number = int(file.name[:4])
        files[number] = "/" + file.relative_to(root).as_posix()[: -len(".md")]

    for number, path in sorted(files.items()):
        if mapping.get(number) != path:
            errors.append(
                f"BRC-{number} file {path} is absent from the short-link map "
                f"(map has {mapping.get(number)!r})"
            )

    readme = root / "README.md"
    readme_rows = (
        parse_readme(readme.read_text(encoding="utf-8")) if readme.is_file() else {}
    )
    for number, path in sorted(readme_rows.items()):
        if number not in mapping:
            errors.append(f"README row BRC-{number} is absent from the short-link map")
        elif number in files and mapping[number] != path:
            errors.append(
                f"BRC-{number} README path {path} disagrees with file {mapping[number]}"
            )

    if readme.is_file():
        for raw in readme.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            match = README_ROW.match(line)
            if not match or not deployed_sync_skips_line(line):
                continue
            number = int(match.group(1))
            if number not in mapping:
                errors.append(
                    f"BRC-{number} would be skipped by brc.dev /sync/readme and "
                    "is also missing from the file-based map"
                )

    for number, path in sorted(mapping.items()):
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path in {"/null", "/"}
            or path.endswith(".md")
            or any(character.isspace() for character in path)
        ):
            errors.append(f"BRC-{number} has unusable short-link path {path!r}")
    return errors


def validate_set_response(brc: int, path: str, payload: object) -> str | None:
    """Return an error when ``POST /set/url`` did not store this mapping."""

    if not isinstance(payload, dict):
        return "response was not a JSON object"
    if payload.get("error"):
        return str(payload["error"])
    if payload.get("brc") != brc or payload.get("path") != path:
        return "response did not confirm the mapping"
    return None


def post_mapping(brc: int, path: str, key: str) -> object:
    """Store one mapping. The admin key stays in the request body and is not logged."""

    body = json.dumps({"brc": brc, "path": path, "key": key}).encode()
    last_error = "request failed"
    for attempt in range(3):
        request = urllib.request.Request(
            SET_URL,
            data=body,
            headers={
                "accept": "*/*",
                "content-type": "application/json",
                "user-agent": "brc-redirect-map",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode()
            return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                return json.loads(raw) if raw else {"error": f"HTTP {exc.code}"}
            except json.JSONDecodeError:
                last_error = f"HTTP {exc.code}"
        except urllib.error.URLError as exc:
            last_error = str(getattr(exc, "reason", exc))
        if attempt < 2:
            time.sleep(1 + attempt)
    return {"error": last_error}


def publish_map(mapping: dict[int, str], key: str, post=post_mapping) -> list[str]:
    """Write every mapping. Stop when the admin key is rejected."""

    errors: list[str] = []
    for brc, path in sorted(mapping.items()):
        error = validate_set_response(brc, path, post(brc, path, key))
        if error == "key is invalid":
            return ["BRC short-link sync rejected BRC_AUTH_KEY"]
        if error:
            errors.append(f"BRC-{brc}: {error}")
    return errors


def check_fixtures() -> None:
    """Fail when a title that trips the deployed parser can omit a BRC file."""

    brc_87_row = (
        "87   | [Standardized Naming Conventions for BRC-22 Topic Managers "
        "and BRC-24 Lookup Services](./overlays/0087.md)"
    )
    if not deployed_sync_skips_line(brc_87_row):
        raise RuntimeError("fixture no longer models the deployed header heuristic")
    if deployed_sync_skips_line(
        "88   | [Overlay Services Synchronization Architecture](./overlays/0088.md)"
    ):
        raise RuntimeError("ordinary README rows must stay visible to the parser")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "overlays").mkdir()
        (root / "tokens").mkdir()
        (root / "overlays" / "0087.md").write_text("# BRC-87\n", encoding="utf-8")
        (root / "tokens" / "0092.md").write_text("withdrawn\n", encoding="utf-8")
        (root / "README.md").write_text(
            "\n".join(
                [
                    "BRC | Standard",
                    "-----|------------------",
                    "0    | [Banana-Powered Bitcoin Wallet Control Protocol](./EXAMPLE.md)",
                    brc_87_row,
                    "88   | [Overlay Services Synchronization Architecture](./overlays/0088.md)",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        mapping = build_redirect_map(root)
        expected = {
            0: "/EXAMPLE",
            87: "/overlays/0087",
            88: "/overlays/0088",
            92: "/tokens/0092",
        }
        if mapping != expected:
            raise RuntimeError(f"fixture map was {mapping!r}, expected {expected!r}")
        if validate_repository(root):
            raise RuntimeError(
                "fixture repository reported errors: "
                + "; ".join(validate_repository(root))
            )

        (root / "README.md").write_text(
            "87   | [Standardized Naming Conventions for BRC-22](./wallet/0087.md)\n",
            encoding="utf-8",
        )
        mismatch = validate_repository(root)
        if not any("disagrees" in error for error in mismatch):
            raise RuntimeError("a README path that disagrees with the file must fail")

        (root / "87.md").write_text("short name\n", encoding="utf-8")
        try:
            build_redirect_map(root)
        except ValueError as exc:
            if "four digits" not in str(exc):
                raise RuntimeError(f"unexpected numbering error: {exc}") from exc
        else:
            raise RuntimeError("a BRC file that is not four digits must fail")
        (root / "87.md").unlink()

        (root / "wallet").mkdir()
        (root / "wallet" / "0087.md").write_text("other\n", encoding="utf-8")
        try:
            build_redirect_map(root)
        except ValueError as exc:
            if "duplicate" not in str(exc):
                raise RuntimeError(f"unexpected duplicate error: {exc}") from exc
        else:
            raise RuntimeError("duplicate BRC numbers must fail")

    if validate_set_response(87, "/overlays/0087", {"brc": 87, "path": "/overlays/0087"}):
        raise RuntimeError("a confirmed set response must be accepted")
    if validate_set_response(87, "/overlays/0087", {"error": "key is invalid"}) != "key is invalid":
        raise RuntimeError("an invalid-key response must surface")
    null_redirect = validate_set_response(87, "/overlays/0087", {"brc": 87, "path": None})
    if null_redirect is None:
        raise RuntimeError("a null path confirmation must be rejected")

    recorded: list[tuple[int, str]] = []

    def fake_post(brc: int, path: str, key: str):
        if key != "test-key":
            return {"error": "key is invalid"}
        recorded.append((brc, path))
        return {"brc": brc, "path": path}

    errors = publish_map({88: "/overlays/0088", 87: "/overlays/0087"}, "test-key", fake_post)
    if errors:
        raise RuntimeError("; ".join(errors))
    if recorded != [(87, "/overlays/0087"), (88, "/overlays/0088")]:
        raise RuntimeError(f"publish order was {recorded!r}")

    rejected = publish_map({87: "/overlays/0087"}, "wrong", fake_post)
    if rejected != ["BRC short-link sync rejected BRC_AUTH_KEY"]:
        raise RuntimeError(f"auth failure was {rejected!r}")


def check(root: Path = REPO_ROOT) -> dict[int, str]:
    check_fixtures()
    errors = validate_repository(root)
    mapping = build_redirect_map(root)
    if mapping.get(87) != "/overlays/0087":
        errors.append(
            f"BRC-87 must map to /overlays/0087 (map has {mapping.get(87)!r})"
        )
    if errors:
        raise SystemExit("BRC short-link map check failed:\n- " + "\n- ".join(errors))
    print(f"BRC short-link map contains {len(mapping)} entries, including 87 -> /overlays/0087")
    return mapping


def publish(root: Path = REPO_ROOT) -> None:
    mapping = check(root)
    key = os.environ.get("BRC_AUTH_KEY", "")
    if not key:
        raise SystemExit("BRC_AUTH_KEY is required to publish short links")
    print(f"Publishing {len(mapping)} short links, including BRC-87 -> {mapping[87]}")
    errors = publish_map(mapping, key)
    if errors:
        raise SystemExit("BRC short-link publish failed:\n- " + "\n- ".join(errors))
    print("Published brc.dev short links")


def main(argv: list[str]) -> None:
    command = argv[1] if len(argv) > 1 else "check"
    if command == "check":
        check()
    elif command == "publish":
        publish()
    else:
        raise SystemExit("usage: brc_redirect_map.py [check|publish]")


if __name__ == "__main__":
    main(sys.argv)
