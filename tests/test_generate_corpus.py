#!/usr/bin/env python3
"""Unit & property tests for generate_corpus.py (TDD)."""

import hashlib
import json
import os
import re
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


def run_generator(script_path: str, out_dir: str, manifest_path: str, extra_args: list[str]) -> None:
    cmd = [
        sys.executable,
        script_path,
        "--out-dir", out_dir,
        "--manifest", manifest_path,
        "--quiet",
        *extra_args,
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(f"Generator failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: test_generate_corpus.py <repo_root>", file=sys.stderr)
        return 2

    repo_root = os.path.abspath(sys.argv[1])
    script_path = os.path.join(repo_root, "generate_corpus.py")
    assert os.path.exists(script_path), f"Missing {script_path}"

    with tempfile.TemporaryDirectory(prefix="es_gen_test_") as tmp:
        dir_a = os.path.join(tmp, "corpus_a")
        man_a = os.path.join(tmp, "manifest_a.json")
        dir_b = os.path.join(tmp, "corpus_b")
        man_b = os.path.join(tmp, "manifest_b.json")

        args = ["--total-mb", "1.5", "--vocab-size", "500", "--seed", "12345"]
        run_generator(script_path, dir_a, man_a, args)
        run_generator(script_path, dir_b, man_b, args)

        # 1. manifest 不应落入 out_dir 内部，避免被搜索引擎索引自身真值文件
        assert not os.path.exists(os.path.join(dir_a, "manifest.json")), "manifest must stay outside out_dir"
        assert os.path.exists(man_a), "manifest file must be created"

        with open(man_a, "r", encoding="utf-8") as fa, open(man_b, "r", encoding="utf-8") as fb:
            data_a = json.load(fa)
            data_b = json.load(fb)

        # 2. 同 seed 可复现性
        assert data_a["summary"] == data_b["summary"], "Same seed must produce identical summary"
        assert data_a["queries"] == data_b["queries"], "Same seed must produce identical query oracle"
        assert data_a["files"] == data_b["files"], "Same seed must produce identical file hashes and sizes"

        # 3. 盘上实际文件数、总字节数、SHA-256 与 manifest 100% 吻合
        actual_files = {}
        for root, _, names in os.walk(dir_a):
            for n in names:
                full = os.path.join(root, n)
                rel = os.path.relpath(full, dir_a)
                actual_files[rel] = (os.path.getsize(full), sha256_file(full))

        assert len(actual_files) == data_a["summary"]["file_count"], "file_count mismatch"
        assert sum(sz for sz, _ in actual_files.values()) == data_a["summary"]["total_bytes"], "total_bytes mismatch"

        for entry in data_a["files"]:
            rel = entry["rel_path"]
            assert rel in actual_files, f"Missing file on disk: {rel}"
            sz, digest = actual_files[rel]
            assert sz == entry["bytes"], f"Byte size mismatch for {rel}"
            assert digest == entry["sha256"], f"SHA-256 mismatch for {rel}"

        # 4. 验证关键边界文件存在（0B 空文件、64KB 跨界文件、中文+空格嵌套路径）
        assert "edge_empty.txt" in actual_files and actual_files["edge_empty.txt"][0] == 0
        assert "edge_cross_64kb.txt" in actual_files and actual_files["edge_cross_64kb.txt"][0] > 65536
        cross_bytes = open(os.path.join(dir_a, "edge_cross_64kb.txt"), "rb").read()
        idx_en = cross_bytes.find(b"crossboundaryen")
        assert 0 < idx_en < 65536 < idx_en + len(b"crossboundaryen"), "English canary must straddle 65536"
        assert any(" " in rel and any(ord(ch) > 127 for ch in rel) for rel in actual_files), \
            "Must include nested path with spaces and CJK characters"

        # 5. 验证布尔查询真值集合一致性
        q = data_a["queries"]
        set_a = set(q["topicalpha"])
        set_b = set(q["topicbeta"])
        set_c = set(q["topicgamma"])
        assert set(q["topicalpha AND topicbeta"]) == (set_a & set_b)
        assert set(q["topicalpha OR topicgamma"]) == (set_a | set_c)
        assert set(q["topicalpha AND NOT topicbeta"]) == (set_a - set_b)

        # 6. 验证长尾词表丰富度（确保不是几个句子机械重复）
        vocab_hits = set()
        for rel in actual_files:
            if rel.endswith(".txt"):
                txt = open(os.path.join(dir_a, rel), "r", encoding="utf-8", errors="ignore").read()
                vocab_hits.update(re.findall(r"zword\d+", txt))
        assert len(vocab_hits) >= 200, f"Expected rich Zipf vocabulary (>=200 distinct zwords), got {len(vocab_hits)}"

    print("All generate_corpus.py tests passed!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
