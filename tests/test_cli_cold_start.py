#!/usr/bin/env python3
"""Cross-process cold-start integration test:
Process A builds index & encrypted cipher archive and exits.
Process B starts fresh with `--search-only`, verifies wrong/right password,
searches, and decrypts a matched document back to plaintext matching original bytes.
"""

import hashlib
import os
import subprocess
import sys
import tempfile


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: test_cli_cold_start.py <binary_path> <repo_root>", file=sys.stderr)
        return 2

    binary_path = os.path.abspath(sys.argv[1])
    repo_root = os.path.abspath(sys.argv[2])

    with tempfile.TemporaryDirectory(prefix="es_cold_start_") as tmp_dir:
        corpus_dir = os.path.join(tmp_dir, "corpus")
        work_dir = os.path.join(tmp_dir, "workdir")
        os.makedirs(corpus_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)
        os.symlink(os.path.join(repo_root, "third_party"), os.path.join(work_dir, "third_party"))

        doc_a = os.path.join(corpus_dir, "report.txt")
        doc_b = os.path.join(corpus_dir, "notes.txt")
        with open(doc_a, "w", encoding="utf-8") as f:
            f.write("冷启动加密检索与 SM4 密文解密闭环验证文档。\n")
        with open(doc_b, "w", encoding="utf-8") as f:
            f.write("普通测试笔记文件。\n")

        # 进程 A：建库 + 加密归档后退出
        proc_a = subprocess.run(
            [binary_path, corpus_dir],
            cwd=work_dir,
            input="cold_start_secret\nexit\n",
            text=True,
            capture_output=True,
            timeout=30,
        )
        if proc_a.returncode != 0:
            print(f"[FAIL] Process A failed ({proc_a.returncode}):\n{proc_a.stdout}\n{proc_a.stderr}",
                  file=sys.stderr)
            return 1

        # 进程 B1：错误密码必须被 keyVerifier 拒绝
        proc_wrong = subprocess.run(
            [binary_path, "--search-only", work_dir],
            cwd=work_dir,
            input="wrong_password_123\n",
            text=True,
            capture_output=True,
            timeout=30,
        )
        if proc_wrong.returncode == 0:
            print(f"[FAIL] Process B with wrong password should fail!\n{proc_wrong.stdout}\n{proc_wrong.stderr}",
                  file=sys.stderr)
            return 1

        # 进程 B2：正确密码冷启动检索并解密 hit 文档
        restored_path = os.path.join(tmp_dir, "restored_report.txt")
        proc_right = subprocess.run(
            [binary_path, "--search-only", work_dir],
            cwd=work_dir,
            input=f"cold_start_secret\n冷启动 AND SM4\ndecrypt {doc_a} {restored_path}\nexit\n",
            text=True,
            capture_output=True,
            timeout=30,
        )
        out_b2 = proc_right.stdout + "\n" + proc_right.stderr
        if proc_right.returncode != 0:
            print(f"[FAIL] Process B2 failed ({proc_right.returncode}):\n{out_b2}", file=sys.stderr)
            return 1

        if doc_a not in out_b2:
            print(f"[FAIL] Cold-start search did not return {doc_a}:\n{out_b2}", file=sys.stderr)
            return 1

        if not os.path.exists(restored_path) or sha256_file(restored_path) != sha256_file(doc_a):
            print(f"[FAIL] Cold-start decrypted file missing or content mismatch!\n{out_b2}", file=sys.stderr)
            return 1

        print("Cross-process cold-start completeness test passed!")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
