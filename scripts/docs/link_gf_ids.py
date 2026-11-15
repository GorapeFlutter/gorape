#!/usr/bin/env python3
"""Link backend GF IDs in Markdown to their source comments on GitHub."""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit


ID_RE = re.compile(r"GF-\d{5}")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
INLINE_CODE_RE = re.compile(r"(`+)([^`]*?)\1")
GITHUB_LINK_RE = re.compile(r"\[(GF-\d{5})\]\(https://github\.com/[^)]+\)")
NESTED_GITHUB_LINK_RE = re.compile(
    r"\[\[(GF-\d{5})\]\((https://github\.com/[^)]+)\)\]"
)
DEFAULT_GITHUB_ROOT = "https://github.com/Gorapeflutter/gorape"
SOURCE_DIRS = ("cmd", "pkg", "migrations")


def github_root() -> str:
    remote = os.environ.get("GORAPE_DOCS_GITHUB_ROOT", DEFAULT_GITHUB_ROOT).strip()
    if remote.startswith("git@github.com:"):
        remote = "https://github.com/" + remote.removeprefix("git@github.com:")
    elif remote.startswith("ssh://git@github.com/"):
        remote = "https://github.com/" + remote.removeprefix("ssh://git@github.com/")
    parsed = urlsplit(remote.rstrip("/"))
    if parsed.hostname == "github.com":
        path = parsed.path.strip("/").removesuffix(".git")
        return f"https://github.com/{path}"
    return remote.removesuffix(".git").rstrip("/")


def source_comment_locations(repo: Path) -> dict[str, list[tuple[str, int]]]:
    locations: dict[str, list[tuple[str, int]]] = defaultdict(list)
    source_files: list[Path] = []
    for source_dir in SOURCE_DIRS:
        root = repo / source_dir
        if root.exists():
            source_files.extend(sorted(root.rglob("*.go")))
            if source_dir == "migrations":
                source_files.extend(sorted(root.rglob("*.sql")))

    for path in source_files:
        relative_path = path.relative_to(repo).as_posix()
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            for match in ID_RE.finditer(line):
                prefix = line[: match.start()]
                stripped = line.lstrip()
                is_comment = (
                    prefix.rfind("//") >= 0
                    or prefix.rfind("/*") >= 0
                    or prefix.rfind("--") >= 0
                    or stripped.startswith("*")
                )
                if is_comment:
                    locations[match.group()].append((relative_path, line_number))
    return locations


def make_link(
    identifier: str,
    locations: dict[str, list[tuple[str, int]]],
    github: str,
    ref: str,
) -> str:
    candidates = locations.get(identifier, [])
    if not candidates:
        raise KeyError(f"No backend source comment found for {identifier}")
    source_path, line_number = candidates[0]
    url = f"{github}/blob/{ref}/{source_path}#L{line_number}"
    return f"[{identifier}]({url})"


def link_line(
    line: str,
    locations: dict[str, list[tuple[str, int]]],
    github: str,
    ref: str,
) -> tuple[str, int]:
    replacements = 0

    def link_plain_text(text: str) -> str:
        nonlocal replacements

        def flatten_nested_link(match: re.Match[str]) -> str:
            nonlocal replacements
            replacements += 1
            return make_link(match.group(1), locations, github, ref)

        text = NESTED_GITHUB_LINK_RE.sub(flatten_nested_link, text)

        def refresh_link(match: re.Match[str]) -> str:
            nonlocal replacements
            current = match.group(0)
            updated = make_link(match.group(1), locations, github, ref)
            if updated != current:
                replacements += 1
            return updated

        text = GITHUB_LINK_RE.sub(refresh_link, text)

        def replace_plain(match: re.Match[str]) -> str:
            nonlocal replacements
            identifier = match.group()
            start, end = match.span()
            if start > 0 and text[start - 1] == "[" and text[end : end + 1] == "]":
                if text[end : end + 2] == "](":
                    return identifier
                replacements += 1
                return make_link(identifier, locations, github, ref)[1:-1]
            replacements += 1
            return make_link(identifier, locations, github, ref)

        return ID_RE.sub(replace_plain, text)

    output: list[str] = []
    cursor = 0
    for match in INLINE_CODE_RE.finditer(line):
        output.append(link_plain_text(line[cursor : match.start()]))
        if ID_RE.fullmatch(match.group(2)):
            replacements += 1
            output.append(make_link(match.group(2), locations, github, ref))
        else:
            output.append(match.group(0))
        cursor = match.end()
    output.append(link_plain_text(line[cursor:]))
    return "".join(output), replacements


def link_document(
    text: str,
    locations: dict[str, list[tuple[str, int]]],
    github: str,
    ref: str,
) -> tuple[str, int]:
    output: list[str] = []
    active_fence: tuple[str, int] | None = None
    replacements = 0
    for line in text.splitlines(keepends=True):
        fence = FENCE_RE.match(line)
        if active_fence is not None:
            output.append(line)
            if fence and fence.group(1)[0] == active_fence[0]:
                if len(fence.group(1)) >= active_fence[1]:
                    active_fence = None
            continue
        if fence:
            active_fence = (fence.group(1)[0], len(fence.group(1)))
            output.append(line)
            continue
        linked, count = link_line(line, locations, github, ref)
        output.append(linked)
        replacements += count
    return "".join(output), replacements


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ref",
        default=os.environ.get("GORAPE_DOCS_GITHUB_REF", "main"),
        help="GitHub branch, tag, or commit to link to (default: main)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report Markdown files that need link updates without editing them",
    )
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    markdown_files = sorted(
        {
            repo / "README.md",
            repo / "SECURITY.md",
            repo / "etc/README.md",
            *(repo / "docs").rglob("*.md"),
        }
    )
    github = github_root()
    locations = source_comment_locations(repo)
    changed: list[str] = []
    missing: set[str] = set()

    for path in markdown_files:
        if not path.is_file():
            continue
        original = path.read_text()
        try:
            linked, count = link_document(original, locations, github, args.ref)
        except KeyError as error:
            missing.add(str(error))
            continue
        if linked == original:
            continue
        relative = path.relative_to(repo).as_posix()
        changed.append(f"{relative}: {count} ID links")
        if not args.check:
            path.write_text(linked)

    if missing:
        print("Missing source IDs:", file=sys.stderr)
        print("\n".join(sorted(missing)), file=sys.stderr)
        return 1
    if args.check:
        if changed:
            print("Documents need GF ID links:")
            print("\n".join(changed))
            return 1
        print("GF ID links are up to date.")
        return 0
    if changed:
        print("Updated GF ID links:")
        print("\n".join(changed))
    else:
        print("No GF ID links needed updating.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
