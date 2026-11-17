#!/usr/bin/env python3
"""Integration test verifying EncryptedSearch CLI accepts a custom corpus path
and outputs real system/corpus monitoring metrics without hardcoded fake strings.
"""

import os
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: test_cli_monitoring.py <binary_path> <repo_root>", file=sys.stderr)
        return 2

    binary_path = os.path.abspath(sys.argv[1])
    repo_root = os.path.abspath(sys.argv[2])

    with tempfile.TemporaryDirectory(prefix="es_cli_test_") as tmp_dir:
        corpus_dir = os.path.join(tmp_dir, "my_corpus")
        work_dir = os.path.join(tmp_dir, "workdir")
        os.makedirs(corpus_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)

        # 供 ParallelHasher 定位 third_party/cppjieba/dict
        os.symlink(os.path.join(repo_root, "third_party"), os.path.join(work_dir, "third_party"))

        docs = {
            "a.txt": "国密算法 SM3 与 SM4 加密检索测试。\n",
            "b.txt": "C++17 多线程并发与布尔搜索演示。\n",
            "c.txt": "倒排索引与 TF-IDF 排序验证。\n",
        }
        total_bytes = 0
        for name, content in docs.items():
            raw = content.encode("utf-8")
            total_bytes += len(raw)
            with open(os.path.join(corpus_dir, name), "wb") as f:
                f.write(raw)

        proc = subprocess.run(
            [binary_path, corpus_dir],
            cwd=work_dir,
            input="testpass123\nexit\n",
            text=True,
            capture_output=True,
            timeout=30,
        )

        output = proc.stdout + "\n" + proc.stderr
        if proc.returncode != 0:
            print(f"[FAIL] CLI exited with code {proc.returncode}\n{output}", file=sys.stderr)
            return 1

        forbidden = ["185.6", "5,000 份", "总计 5GB", "Unknown GPU", "4294967295"]
        for bad in forbidden:
            if bad in output:
                print(f"[FAIL] Found hardcoded/invalid string in output: {bad!r}\n{output}", file=sys.stderr)
                return 1

        required_patterns = [
            r"文件数.*3",
            rf"{total_bytes}\s*B",
            r"Peak RSS|VmHWM",
            r"吞吐",
        ]
        for pat in required_patterns:
            if not re.search(pat, output):
                print(f"[FAIL] Missing expected pattern {pat!r} in output:\n{output}", file=sys.stderr)
                return 1

        print("CLI real monitoring integration test passed!")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
