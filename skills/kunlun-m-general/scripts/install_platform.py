# -*- coding: utf-8 -*-

import argparse
import os
import shutil
import sys
from typing import Optional


def _copytree(src: str, dst: str, force: bool) -> None:
    if os.path.exists(dst):
        if not force:
            raise FileExistsError(dst)
        shutil.rmtree(dst)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copytree(src, dst)


def _skill_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _home() -> str:
    return os.path.expanduser("~")


def _default_dst(platform: str, scope: str, repo_root: Optional[str], category: Optional[str]) -> str:
    p = platform.strip().lower()
    s = scope.strip().lower()
    name = "kunlun-m-general"

    if p == "openclaw":
        if s == "project":
            if not repo_root:
                raise ValueError("repo_root required for project scope")
            return os.path.join(os.path.abspath(repo_root), "skills", name)
        return os.path.join(_home(), ".openclaw", "skills", name)

    if p == "codex":
        if s == "project":
            if not repo_root:
                raise ValueError("repo_root required for project scope")
            return os.path.join(os.path.abspath(repo_root), ".agents", "skills", name)
        return os.path.join(_home(), ".agents", "skills", name)

    if p == "claude-code":
        if s == "project":
            if not repo_root:
                raise ValueError("repo_root required for project scope")
            return os.path.join(os.path.abspath(repo_root), ".claude", "skills", name)
        return os.path.join(_home(), ".claude", "skills", name)

    if p == "hermes":
        c = (category or "security").strip()
        if s == "project":
            if not repo_root:
                raise ValueError("repo_root required for project scope")
            return os.path.join(os.path.abspath(repo_root), ".hermes", "skills", c, name)
        return os.path.join(_home(), ".hermes", "skills", c, name)

    raise ValueError("unsupported platform: {}".format(platform))


def main(argv):
    parser = argparse.ArgumentParser(prog="install_platform")
    parser.add_argument("--platform", dest="platform", required=True, choices=["openclaw", "codex", "claude-code", "hermes"])
    parser.add_argument("--scope", dest="scope", default="user", choices=["user", "project"])
    parser.add_argument("--repo-root", dest="repo_root", default=None)
    parser.add_argument("--category", dest="category", default=None)
    parser.add_argument("--dst", dest="dst", default=None)
    parser.add_argument("--force", dest="force", action="store_true", default=False)
    args = parser.parse_args(argv)

    src = _skill_root()
    dst = args.dst or _default_dst(args.platform, args.scope, args.repo_root, args.category)
    _copytree(src, dst, args.force)
    print(dst)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

