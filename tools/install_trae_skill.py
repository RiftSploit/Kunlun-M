# -*- coding: utf-8 -*-

import argparse
import os
import shutil
import sys


def _copytree(src: str, dst: str, force: bool) -> None:
    if os.path.exists(dst):
        if not force:
            raise FileExistsError(dst)
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def main(argv):
    parser = argparse.ArgumentParser(prog="install_trae_skill")
    parser.add_argument("--name", dest="name", default="kunlun-m-general")
    parser.add_argument("--repo-root", dest="repo_root", default=os.getcwd())
    parser.add_argument("--force", dest="force", action="store_true", default=False)
    args = parser.parse_args(argv)

    repo_root = os.path.abspath(args.repo_root)
    src = os.path.join(repo_root, "skills", args.name)
    if not os.path.isdir(src):
        raise FileNotFoundError(src)

    home = os.path.expanduser("~")
    dst = os.path.join(home, ".trae", "skills", args.name)
    os.makedirs(os.path.dirname(dst), exist_ok=True)

    _copytree(src, dst, args.force)
    print(dst)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

