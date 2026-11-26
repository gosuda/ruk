from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

WORKSPACE = Path(os.environ["GITHUB_WORKSPACE"])
SOURCE = WORKSPACE / "candidate"
PROOF = WORKSPACE / "probe"
EVIDENCE = WORKSPACE / "evidence"
EVIDENCE.mkdir(exist_ok=True)
STAGE = "crates/ruk/src/cli/verbs_stage.rs"
TEST_FILTER = "test(lexical_paths)"
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=SOURCE, text=True).strip()


def run(label: str, command: list[str], timeout: int = 3600) -> int:
    print(f"RUN {label}: {json.dumps(command)}", flush=True)
    output = EVIDENCE / f"{label}.log"
    environment = dict(os.environ)
    environment["RUSTC_WRAPPER"] = ""
    with output.open("w", encoding="utf-8") as stream:
        try:
            status = subprocess.run(
                command, cwd=SOURCE, env=environment, stdout=stream,
                stderr=subprocess.STDOUT, check=False, timeout=timeout,
            ).returncode
        except subprocess.TimeoutExpired:
            stream.write(f"\nTimed out after {timeout} seconds.\n")
            status = 124
    text = output.read_text(encoding="utf-8", errors="replace")
    print(f"EXIT {label}: {status}", flush=True)
    print(text[-24000:] if status else text[-5000:], flush=True)
    return status


def function_text(source: str) -> str:
    start = source.index("pub(crate) fn repo_path_lexical(")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def test_statuses(name: str, status: str, expected: list[str]) -> bool:
    raw = (EVIDENCE / f"{name}.log").read_text(encoding="utf-8", errors="replace")
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw)
    return all(
        any(re.search(rf"\b{status}\b", line) and test in line for line in clean.splitlines())
        for test in expected
    )


def main() -> int:
    manifest = json.loads((PROOF / ".github/verification/ruk20.json").read_text())
    assert git("rev-parse", "HEAD") == manifest["head"]
    patch = PROOF / ".github/verification/ruk20.patch"
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == manifest["patch_sha256"]
    git("apply", "--index", "--whitespace=error", str(patch))
    assert git("write-tree") == manifest["input_tree"]
    paths = sorted(manifest["files"])
    assert git("diff", "--cached", "--name-only").splitlines() == paths
    for name, expected in manifest["files"].items():
        assert hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() == expected
    version = subprocess.check_output(["rustc", "--version"], cwd=SOURCE, text=True).strip()
    assert version.startswith("rustc 1.99.1 "), version
    print(f"RUST_TOOLCHAIN {version}", flush=True)
    assert run("prepare-format", ["cargo", "fmt", "--all"]) == 0
    changed = git("diff", "--name-only").splitlines()
    assert set(changed).issubset(paths), changed
    for name in paths:
        data = (SOURCE / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest["files"][name]:
            encoded = base64.b64encode(data).decode("ascii")
            for offset in range(0, len(encoded), 4000):
                print(f"FORMATTED_B64 {name} {offset // 4000} {encoded[offset:offset + 4000]}", flush=True)
        destination = EVIDENCE / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, destination)
    git("add", "--", *paths)
    git("diff", "--cached", "--check")
    git("diff", "--exit-code")
    final_tree = git("write-tree")
    source_hashes = {name: hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() for name in paths}
    identity = {
        "head": manifest["head"], "input_tree": manifest["input_tree"],
        "final_tree": final_tree, "patch_sha256": manifest["patch_sha256"],
        "files": source_hashes, "platform": os.environ["RUNNER_OS"],
        "rustc": version,
    }
    print(f"SOURCE_IDENTITY {json.dumps(identity, sort_keys=True)}", flush=True)
    (EVIDENCE / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    candidate_stage = (SOURCE / STAGE).read_text(encoding="utf-8")
    current_function = function_text(candidate_stage)
    assert not any(line.lstrip().startswith("//") for line in current_function.splitlines())
    results: dict[str, object] = {"identity": identity}
    results["format"] = run("format", ["cargo", "fmt", "--all", "--", "--check"])
    selected = [
        "cargo", "nextest", "run", "-p", "ruk", "--locked",
        "--no-fail-fast", "--status-level", "all", "-E", TEST_FILTER,
    ]
    expected = ["staged_restore_rejects_untraversable_outside_prefixes"]
    if os.name == "nt":
        expected += [
            "staged_restore_accepts_a_missing_file_at_drive_root",
            "relative_reentry_resolves_a_junction_after_dash_c",
        ]
        results["native_windows_paths"] = run("native-windows-paths", selected)
        assert results["native_windows_paths"] == 0 and test_statuses("native-windows-paths", "PASS", expected)
    else:
        results["clippy"] = run("clippy", [
            "cargo", "clippy", "--workspace", "--all-targets", "--all-features",
            "--locked", "--", "-D", "warnings",
        ])
        results["nextest"] = run("nextest", ["cargo", "nextest", "run", "--workspace", "--locked"])
        if any(results[name] != 0 for name in ("format", "clippy", "nextest")):
            (EVIDENCE / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            print(f"RUK_PATH_RESULT {json.dumps(results, sort_keys=True)}", flush=True)
            return 1
    previous_stage = git("show", f"HEAD:{STAGE}") + "\n"
    previous_function = function_text(previous_stage)
    assert current_function != previous_function
    try:
        (SOURCE / STAGE).write_text(candidate_stage.replace(current_function, previous_function), encoding="utf-8", newline="\n")
        red = run("previous-walker-red", selected)
        reproduced = red != 0 and test_statuses("previous-walker-red", "FAIL", expected)
    finally:
        (SOURCE / STAGE).write_text(candidate_stage, encoding="utf-8", newline="\n")
    green = run("restored-walker-green", selected)
    restored = green == 0 and test_statuses("restored-walker-green", "PASS", expected)
    results["controls"] = {"red": red, "reproduced": reproduced, "green": green, "restored": restored, "tests": expected}
    git("diff", "--exit-code")
    assert git("write-tree") == final_tree
    (EVIDENCE / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"RUK_PATH_RESULT {json.dumps(results, sort_keys=True)}", flush=True)
    return int(not (results["format"] == 0 and reproduced and restored))


if __name__ == "__main__":
    raise SystemExit(main())
