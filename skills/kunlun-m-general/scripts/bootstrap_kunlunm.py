# -*- coding: utf-8 -*-

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from typing import Optional


DEFAULT_GIT_URL = "https://github.com/LoRexxar/Kunlun-M.git"
DEFAULT_ZIP_URL = "https://github.com/LoRexxar/Kunlun-M/archive/refs/heads/master.zip"


def _run(cmd, cwd: Optional[str] = None) -> int:
    p = subprocess.run(cmd, cwd=cwd)
    return int(p.returncode)


def _which(cmd: str) -> Optional[str]:
    from shutil import which

    return which(cmd)


def _download(url: str, out_path: str) -> None:
    try:
        import urllib.request

        with urllib.request.urlopen(url) as r, open(out_path, "wb") as f:
            shutil.copyfileobj(r, f)
    except Exception:
        raise


def _extract_zip(zip_path: str, dst_dir: str) -> str:
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dst_dir)
        names = [n for n in zf.namelist() if n.endswith("/") or n.endswith("\\")]
        top = None
        for n in names:
            s = n.strip("/\\")
            if not s:
                continue
            top = s.split("/")[0].split("\\")[0]
            break
    if not top:
        raise RuntimeError("invalid zip layout")
    return os.path.join(dst_dir, top)


def _has_kunlun_repo(path: str) -> bool:
    return os.path.isfile(os.path.join(path, "kunlun.py"))


def ensure_repo(repo_dir: str, git_url: str, zip_url: str, prefer_git: bool = True, force: bool = False) -> str:
    repo_dir = os.path.abspath(repo_dir)
    if _has_kunlun_repo(repo_dir) and not force:
        return repo_dir

    if os.path.exists(repo_dir) and force:
        shutil.rmtree(repo_dir)

    parent = os.path.dirname(repo_dir)
    os.makedirs(parent, exist_ok=True)

    git = _which("git")
    if prefer_git and git:
        rc = _run([git, "clone", git_url, repo_dir])
        if rc == 0 and _has_kunlun_repo(repo_dir):
            return repo_dir

    tmp_zip = os.path.join(parent, "Kunlun-M.zip")
    if os.path.exists(tmp_zip):
        os.remove(tmp_zip)
    _download(zip_url, tmp_zip)
    extracted_root = _extract_zip(tmp_zip, parent)
    if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir)
    shutil.move(extracted_root, repo_dir)
    if not _has_kunlun_repo(repo_dir):
        raise FileNotFoundError("kunlun.py not found after download")
    return repo_dir


def bootstrap(repo_dir: str, python: str, init_db: bool, load_rules: bool, load_tamper: bool) -> int:
    if not _has_kunlun_repo(repo_dir):
        raise FileNotFoundError("kunlun.py not found: {}".format(repo_dir))

    settings_dst = os.path.join(repo_dir, "Kunlun_M", "settings.py")
    settings_bak = os.path.join(repo_dir, "Kunlun_M", "settings.py.bak")
    if not os.path.isfile(settings_dst) and os.path.isfile(settings_bak):
        shutil.copyfile(settings_bak, settings_dst)

    req = os.path.join(repo_dir, "requirements.txt")
    if os.path.isfile(req):
        rc = _run([python, "-m", "pip", "install", "-r", "requirements.txt"], cwd=repo_dir)
        if rc != 0:
            return rc

    if init_db:
        rc = _run([python, "kunlun.py", "init", "initialize"], cwd=repo_dir)
        if rc != 0:
            return rc

    if load_rules:
        rc = _run([python, "kunlun.py", "config", "load"], cwd=repo_dir)
        if rc != 0:
            return rc

    if load_tamper:
        rc = _run([python, "kunlun.py", "config", "loadtamper"], cwd=repo_dir)
        if rc != 0:
            return rc

    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="bootstrap_kunlunm")
    p.add_argument("--repo-dir", dest="repo_dir", default=os.path.join(os.getcwd(), "Kunlun-M"))
    p.add_argument("--python", dest="python", default=sys.executable)
    p.add_argument("--git-url", dest="git_url", default=DEFAULT_GIT_URL)
    p.add_argument("--zip-url", dest="zip_url", default=DEFAULT_ZIP_URL)
    p.add_argument("--prefer-git", dest="prefer_git", action="store_true", default=True)
    p.add_argument("--no-prefer-git", dest="prefer_git", action="store_false")
    p.add_argument("--force", dest="force", action="store_true", default=False)
    p.add_argument("--init-db", dest="init_db", action="store_true", default=True)
    p.add_argument("--no-init-db", dest="init_db", action="store_false")
    p.add_argument("--load-rules", dest="load_rules", action="store_true", default=True)
    p.add_argument("--no-load-rules", dest="load_rules", action="store_false")
    p.add_argument("--load-tamper", dest="load_tamper", action="store_true", default=True)
    p.add_argument("--no-load-tamper", dest="load_tamper", action="store_false")
    args = p.parse_args(argv)

    repo_dir = ensure_repo(
        repo_dir=args.repo_dir,
        git_url=args.git_url,
        zip_url=args.zip_url,
        prefer_git=args.prefer_git,
        force=args.force,
    )
    rc = bootstrap(
        repo_dir=repo_dir,
        python=args.python,
        init_db=args.init_db,
        load_rules=args.load_rules,
        load_tamper=args.load_tamper,
    )
    print(repo_dir)
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

