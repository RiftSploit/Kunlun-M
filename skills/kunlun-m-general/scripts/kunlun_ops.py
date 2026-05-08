# -*- coding: utf-8 -*-

import argparse
import os
import subprocess
import sys
from typing import List, Optional


def _repo_root(path: Optional[str]) -> str:
    root = os.path.abspath(path or os.getcwd())
    if not os.path.isfile(os.path.join(root, "kunlun.py")):
        raise FileNotFoundError("kunlun.py not found in {}".format(root))
    return root


def _run(cmd: List[str], cwd: str) -> int:
    p = subprocess.run(cmd, cwd=cwd)
    return int(p.returncode)


def _scan(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo_root)
    cmd: List[str] = [args.python, "kunlun.py", "scan", "-t", args.target]
    if args.language:
        cmd += ["-lan", args.language]
    if args.rule:
        cmd += ["-r", args.rule]
    if args.tamper:
        cmd += ["-tp", args.tamper]
    if args.blackpath:
        cmd += ["-b", args.blackpath]
    if args.format:
        cmd += ["-f", args.format]
    if args.output:
        cmd += ["-o", args.output]
    if args.without_vendor:
        cmd += ["--without-vendor"]
    if args.debug:
        cmd += ["-d"]
    return _run(cmd, cwd=root)


def _gen_rule(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo_root)
    cmd: List[str] = [args.python, "kunlun.py", "generate", "rule", "-lan", args.language, "--name", args.name]
    if args.author:
        cmd += ["--author", args.author]
    if args.description:
        cmd += ["--description", args.description]
    if args.level is not None:
        cmd += ["--level", str(args.level)]
    if args.disable:
        cmd += ["--disable"]
    if args.match_mode:
        cmd += ["--match-mode", args.match_mode]
    if args.match:
        cmd += ["--match", args.match]
    if args.unmatch:
        cmd += ["--unmatch", args.unmatch]
    if args.svid is not None:
        cmd += ["--svid", str(args.svid)]
    if args.sync:
        cmd += ["--sync"]
    if args.force:
        cmd += ["--force"]
    return _run(cmd, cwd=root)


def _gen_tamper(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo_root)
    cmd: List[str] = [args.python, "kunlun.py", "generate", "tamper", "--name", args.name]
    if args.filter_func:
        cmd += ["--filter-func", args.filter_func]
    if args.controlled:
        cmd += ["--controlled", args.controlled]
    if args.sync:
        cmd += ["--sync"]
    if args.force:
        cmd += ["--force"]
    return _run(cmd, cwd=root)


def _sync(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo_root)
    rc = 0
    if args.rule:
        rc = max(rc, _run([args.python, "kunlun.py", "config", "load"], cwd=root))
    if args.tamper:
        rc = max(rc, _run([args.python, "kunlun.py", "config", "loadtamper"], cwd=root))
    return rc


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="kunlun_ops")
    parser.add_argument("--repo-root", dest="repo_root", default=None)
    parser.add_argument("--python", dest="python", default=sys.executable)

    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("-t", "--target", dest="target", required=True)
    p_scan.add_argument("-lan", "--language", dest="language", default=None)
    p_scan.add_argument("-r", "--rule", dest="rule", default=None)
    p_scan.add_argument("-tp", "--tamper", dest="tamper", default=None)
    p_scan.add_argument("-b", "--blackpath", dest="blackpath", default=None)
    p_scan.add_argument("-f", "--format", dest="format", default=None)
    p_scan.add_argument("-o", "--output", dest="output", default=None)
    p_scan.add_argument("--without-vendor", dest="without_vendor", action="store_true", default=False)
    p_scan.add_argument("-d", "--debug", dest="debug", action="store_true", default=False)

    p_rule = sub.add_parser("gen-rule")
    p_rule.add_argument("-lan", "--language", dest="language", required=True)
    p_rule.add_argument("--name", dest="name", required=True)
    p_rule.add_argument("--author", dest="author", default=None)
    p_rule.add_argument("--description", dest="description", default=None)
    p_rule.add_argument("--level", dest="level", type=int, default=1)
    p_rule.add_argument("--disable", dest="disable", action="store_true", default=False)
    p_rule.add_argument("--match-mode", dest="match_mode", default="function-param-regex")
    p_rule.add_argument("--match", dest="match", default=None)
    p_rule.add_argument("--unmatch", dest="unmatch", default=None)
    p_rule.add_argument("--svid", dest="svid", type=int, default=None)
    p_rule.add_argument("--sync", dest="sync", action="store_true", default=False)
    p_rule.add_argument("--force", dest="force", action="store_true", default=False)

    p_tamper = sub.add_parser("gen-tamper")
    p_tamper.add_argument("--name", dest="name", required=True)
    p_tamper.add_argument("--filter-func", dest="filter_func", default=None)
    p_tamper.add_argument("--controlled", dest="controlled", default=None)
    p_tamper.add_argument("--sync", dest="sync", action="store_true", default=False)
    p_tamper.add_argument("--force", dest="force", action="store_true", default=False)

    p_sync = sub.add_parser("sync")
    p_sync.add_argument("--rule", dest="rule", action="store_true", default=False)
    p_sync.add_argument("--tamper", dest="tamper", action="store_true", default=False)

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return _scan(args)
    if args.cmd == "gen-rule":
        return _gen_rule(args)
    if args.cmd == "gen-tamper":
        return _gen_tamper(args)
    if args.cmd == "sync":
        return _sync(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

