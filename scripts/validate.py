"""Stage, build, install, and test this source-only project under Build.

Every generated environment, copy, package, log, and receipt stays below the
caller-selected Build directory.  No installed third-party package is copied
into the project source tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile
from datetime import datetime, timezone
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
PACKAGE = "jwt_verifier_confusion_review"
PINNED_TOOLS = ["build==1.3.0", "setuptools==84.0.0", "wheel==0.48.0"]
PINNED_RUNTIME = ["PyJWT==2.15.1", "cryptography==50.0.2"]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files() -> list[Path]:
    result = []
    for path in PROJECT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(PROJECT)
        if any(part in {".git", "Build", "__pycache__", ".pytest_cache"} or part.endswith(".egg-info") for part in rel.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        result.append(path)
    return sorted(result)


def run_step(label: str, args: list[str], cwd: Path, env: dict[str, str], logs: Path, steps: list[dict[str, object]]) -> None:
    proc = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = logs / f"{label}.log"
    log.write_text(proc.stdout, encoding="utf-8")
    steps.append({"step": label, "command": args, "cwd": str(cwd), "exit_code": proc.returncode, "log": str(log)})
    if proc.returncode != 0:
        raise RuntimeError(f"{label} failed; see {log}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", type=Path, required=True, help="An absolute or relative directory under Build")
    parser.add_argument("--run-id", default=None)
    opts = parser.parse_args()
    base = opts.build_root.resolve()
    if "Build" not in base.parts or base == PROJECT or PROJECT in base.parents:
        raise SystemExit("--build-root must be outside the source checkout under a Build directory")
    base.mkdir(parents=True, exist_ok=True)
    run_id = opts.run_id or datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    run_dir = base / run_id
    run_dir.mkdir(exist_ok=False)
    logs = run_dir / "logs"
    logs.mkdir()
    (run_dir / "tmp").mkdir()
    (run_dir / "cache").mkdir()
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(run_dir / "tmp"),
        "PIP_CACHE_DIR": str(run_dir / "cache"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    })
    steps: list[dict[str, object]] = []
    manifest = {str(p.relative_to(PROJECT)): digest(p) for p in source_files()}
    receipt: dict[str, object] = {
        "schema": "jwt-verifier-confusion-validation-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "candidate_version": "0.1.0",
        "python_version": sys.version.split()[0],
        "source_root": str(PROJECT),
        "source_files_sha256": manifest,
        "steps": steps,
        "status": "FAIL",
    }
    try:
        stage = run_dir / "staged-source"
        stage.mkdir()
        for path in source_files():
            rel = path.relative_to(PROJECT)
            target = stage / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            if digest(target) != manifest[str(rel)]:
                raise RuntimeError(f"source copy changed: {rel}")
        receipt["staged_files_exact"] = len(manifest)

        source_env = run_dir / "source-env"
        venv.EnvBuilder(with_pip=True).create(source_env)
        py = str(source_env / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
        run_step("install-test-and-build-dependencies", [py, "-m", "pip", "install", *PINNED_RUNTIME, *PINNED_TOOLS], run_dir, env, logs, steps)
        source_test_env = env | {"PYTHONPATH": str(PROJECT / "src")}
        run_step("source-unittest", [py, "-m", "unittest", "discover", "-s", "tests", "-v"], PROJECT, source_test_env, logs, steps)
        run_step("source-live-http", [py, "tests/run_local_experiment.py", "--output", str(run_dir / "source-lab.json")], PROJECT, source_test_env, logs, steps)

        dist = run_dir / "dist"
        dist.mkdir()
        run_step("build-staged-distributions", [py, "-m", "build", "--no-isolation", "--outdir", str(dist), str(stage)], run_dir, env, logs, steps)
        wheel = next(dist.glob("*.whl"), None)
        sdist = next(dist.glob("*.tar.gz"), None)
        if wheel is None or sdist is None:
            raise RuntimeError("both wheel and source distribution are required")
        receipt["artifacts"] = {p.name: {"sha256": digest(p), "bytes": p.stat().st_size} for p in (wheel, sdist)}
        sdist_source = run_dir / "sdist-source"
        sdist_source.mkdir()
        with tarfile.open(sdist, "r:gz") as tf:
            archive_files: dict[str, bytes] = {}
            for member in tf.getmembers():
                parts = Path(member.name).parts
                if len(parts) == 1 and parts[0] == "jwt_verifier_confusion_review-0.1.0" and member.isdir():
                    continue
                if len(parts) < 2 or parts[0] != "jwt_verifier_confusion_review-0.1.0" or ".." in parts:
                    raise RuntimeError("unsafe or unexpected sdist member path")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise RuntimeError("nonregular sdist member")
                rel = Path(*parts[1:])
                data = tf.extractfile(member).read()
                archive_files[str(rel)] = data
                target = sdist_source / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        for rel, expected in manifest.items():
            if rel not in archive_files or hashlib.sha256(archive_files[rel]).hexdigest() != expected:
                raise RuntimeError(f"sdist omits or changes source file: {rel}")
        receipt["sdist_source_files_exact"] = len(manifest)
        sdist_test_env = env | {"PYTHONPATH": str(sdist_source / "src")}
        run_step("sdist-unittest", [py, "-m", "unittest", "discover", "-s", "tests", "-v"], sdist_source, sdist_test_env, logs, steps)
        run_step("sdist-live-http", [py, "tests/run_local_experiment.py", "--output", str(run_dir / "sdist-lab.json")], sdist_source, sdist_test_env, logs, steps)
        with zipfile.ZipFile(wheel) as zf:
            names = zf.namelist()
            if any("weak_baseline" in name or "tests/" in name for name in names):
                raise RuntimeError("test-only weak helper leaked into wheel")
            for rel, expected in manifest.items():
                if rel.startswith(f"src/{PACKAGE}/") and rel.endswith(".py"):
                    packaged = rel.removeprefix("src/")
                    if packaged not in names or hashlib.sha256(zf.read(packaged)).hexdigest() != expected:
                        raise RuntimeError(f"wheel package file differs from source: {rel}")
            receipt["wheel_source_files_exact"] = sum(1 for rel in manifest if rel.startswith(f"src/{PACKAGE}/") and rel.endswith(".py"))

        consumer_env = run_dir / "consumer-env"
        venv.EnvBuilder(with_pip=True).create(consumer_env)
        consumer_py = str(consumer_env / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
        run_step("install-wheel", [consumer_py, "-m", "pip", "install", str(wheel)], run_dir, env, logs, steps)
        consumer_tests = run_dir / "consumer-tests"
        shutil.copytree(PROJECT / "tests", consumer_tests, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        run_step("installed-unittest", [consumer_py, "-m", "unittest", "discover", "-s", str(consumer_tests), "-v"], run_dir, env, logs, steps)
        run_step("installed-live-http", [consumer_py, str(consumer_tests / "run_local_experiment.py"), "--output", str(run_dir / "installed-lab.json")], run_dir, env, logs, steps)
        run_step(
            "installed-version-check",
            [consumer_py, "-c", "import jwt,cryptography,importlib.metadata as m,jwt_verifier_confusion_review as p; assert (jwt.__version__,cryptography.__version__,p.__version__)==('2.15.1','50.0.2','0.1.0'); print(jwt.__version__,cryptography.__version__,m.version('cffi'),m.version('pycparser'),p.__version__)"],
            run_dir, env, logs, steps,
        )
        version_parts = (logs / "installed-version-check.log").read_text().strip().splitlines()[-1].split()
        receipt["installed_versions"] = dict(zip(("PyJWT", "cryptography", "cffi", "pycparser", "project"), version_parts, strict=True))
        labs = [json.loads((run_dir / label).read_text()) for label in ("source-lab.json", "sdist-lab.json", "installed-lab.json")]
        if any(lab["status"] != "PASS" or len(lab["cases"]) != 10 for lab in labs):
            raise RuntimeError("local HTTP experiment failed")
        receipt["source_sdist_and_installed_http_cases"] = [len(lab["cases"]) for lab in labs]
        receipt["status"] = "PASS_LOCAL_ENGINEERING"
    except Exception as exc:
        receipt["error"] = str(exc)
    finally:
        receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
        receipt_path = run_dir / "validation.json"
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": receipt["status"], "receipt": str(receipt_path), "steps": len(steps)}, ensure_ascii=False))
    return 0 if receipt["status"] == "PASS_LOCAL_ENGINEERING" else 1


if __name__ == "__main__":
    raise SystemExit(main())
