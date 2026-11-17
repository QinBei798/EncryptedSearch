#!/usr/bin/env python3
"""Reproducible benchmark & correctness corpus generator for EncryptedSearch.

Generates a deterministic mixed-size, Zipf-distributed Chinese/English corpus
alongside edge-case files and a ground-truth manifest JSON for automated verification.
"""

import argparse
import bisect
import hashlib
import json
import math
import os
import random
import shutil
from typing import Dict, List, Optional, Set, Tuple


BASE_SENTENCES = [
    "加密算法在现代信息安全中起着至关重要的作用，特别是国密算法。",
    "国密标准包括 SM2、SM3 与 SM4 等，能够提供高强度数据安全保障。",
    "结巴分词支持 CutForSearch 模式，可处理复杂的中英混合文本检索。",
    "倒排索引是全文搜索引擎的核心结构，结合磁盘懒加载可降低内存开销。",
    "布尔搜索允许通过 AND、OR 与 NOT 逻辑运算符精确组合检索条件。",
    "采用 C++17 多线程并发与流式读写架构，能够稳定处理大规模文档库。",
    "密钥派生函数 PBKDF2 与 HMAC-SM3 盲索引可以有效抵御离线字典碰撞攻击。",
    "密文文件采用随机十六字节 IV 头部与 SM4-CBC 分组加密流式写入。",
]


def build_zipf_cdf(vocab_size: int, exponent: float = 1.05) -> List[float]:
    """Build cumulative distribution weights approximating a Zipf power law."""
    weights = [1.0 / math.pow(rank + 1, exponent) for rank in range(vocab_size)]
    total = sum(weights)
    cdf: List[float] = []
    acc = 0.0
    for w in weights:
        acc += w / total
        cdf.append(acc)
    cdf[-1] = 1.0
    return cdf


def sample_zipf_word(rng: random.Random, cdf: List[float]) -> str:
    """Sample a synthetic token index following the precomputed Zipf CDF."""
    r = rng.random()
    idx = bisect.bisect_left(cdf, r)
    if idx >= len(cdf):
        idx = len(cdf) - 1
    return f"zword{idx:05d}"


def build_paragraph_pool(rng: random.Random, cdf: List[float], pool_size: int = 128) -> List[bytes]:
    """Pre-generate varied ~2KB Chinese+English+Zipfian text paragraphs for fast streaming."""
    paragraphs: List[bytes] = []
    for _ in range(pool_size):
        lines: List[str] = []
        for _ in range(12):
            sentence = rng.choice(BASE_SENTENCES)
            zwords = " ".join(sample_zipf_word(rng, cdf) for _ in range(10))
            lines.append(f"{sentence} {zwords}\n")
        paragraphs.append("".join(lines).encode("utf-8"))
    return paragraphs


def write_tracked_file(
    out_dir: str,
    rel_path: str,
    payload_chunks: List[bytes],
    tags: List[str],
    records: List[Dict[str, object]],
    tag_index: Dict[str, Set[str]],
) -> int:
    """Write a file from byte chunks, compute exact byte count and SHA-256."""
    full_path = os.path.join(out_dir, rel_path)
    parent = os.path.dirname(full_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    hasher = hashlib.sha256()
    total_bytes = 0
    with open(full_path, "wb") as f:
        for chunk in payload_chunks:
            if chunk:
                f.write(chunk)
                hasher.update(chunk)
                total_bytes += len(chunk)

    records.append({
        "rel_path": rel_path,
        "bytes": total_bytes,
        "sha256": hasher.hexdigest(),
        "tags": sorted(tags),
    })
    for t in tags:
        tag_index.setdefault(t, set()).add(rel_path)
    return total_bytes


def build_cross_64kb_payload(paragraphs: List[bytes], rng: random.Random) -> bytes:
    """Construct a >70KB payload with English & Chinese words straddling byte 65536."""
    buf = bytearray(b"canaryheadtoken ")
    pad_unit = b"pad "
    while len(buf) + len(pad_unit) <= 65530:
        buf.extend(pad_unit)
    while len(buf) < 65530:
        buf.extend(b" ")

    # 'crossboundaryen' spans [65530, 65545), crossing 65536
    buf.extend(b"crossboundaryen ")
    buf.extend("搜索引擎测试内容。\n".encode("utf-8"))
    while len(buf) < 72 * 1024:
        buf.extend(rng.choice(paragraphs))
    buf.extend(b"\ncanarytailtoken\n")
    return bytes(buf)


def choose_topic_tags(rng: random.Random, doc_idx: int) -> List[str]:
    """Assign deterministic topic tags for exact boolean query ground truth."""
    tags: List[str] = []
    if doc_idx % 2 == 0 or rng.random() < 0.30:
        tags.append("topicalpha")
    if doc_idx % 3 == 0 or rng.random() < 0.25:
        tags.append("topicbeta")
    if doc_idx % 5 == 0 or rng.random() < 0.20:
        tags.append("topicgamma")
    return tags


def generate_corpus(
    out_dir: str,
    manifest_path: str,
    total_mb: float,
    vocab_size: int,
    seed: int,
    num_files: Optional[int] = None,
    large_file_mb: float = 0.0,
    include_edge_cases: bool = True,
    clean: bool = False,
    quiet: bool = False,
) -> Dict[str, object]:
    """Generate corpus files and return the manifest dictionary."""
    if clean and os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    rng = random.Random(seed)
    cdf = build_zipf_cdf(max(10, vocab_size))
    paragraphs = build_paragraph_pool(rng, cdf, pool_size=max(64, min(256, vocab_size // 4 + 32)))

    records: List[Dict[str, object]] = []
    tag_index: Dict[str, Set[str]] = {
        "topicalpha": set(),
        "topicbeta": set(),
        "topicgamma": set(),
        "crossboundaryen": set(),
        "搜索引擎": set(),
        "canaryheadtoken": set(),
        "canarytailtoken": set(),
    }

    written_bytes = 0
    target_bytes = int(total_mb * 1024 * 1024)

    # 1. Optional edge-case files (0B, whitespace, 64KB boundary, nested CJK+space path)
    if include_edge_cases:
        written_bytes += write_tracked_file(out_dir, "edge_empty.txt", [b""], [], records, tag_index)
        written_bytes += write_tracked_file(out_dir, "edge_whitespace.txt", [b"   \t\n  \r\n"], [], records, tag_index)
        cross_payload = build_cross_64kb_payload(paragraphs, rng)
        written_bytes += write_tracked_file(
            out_dir,
            "edge_cross_64kb.txt",
            [cross_payload],
            ["crossboundaryen", "搜索引擎", "canaryheadtoken", "canarytailtoken"],
            records,
            tag_index,
        )
        nested_payload = "中文路径与空格文件名端到端检索测试。\ntopicalpha topicgamma\n".encode("utf-8")
        written_bytes += write_tracked_file(
            out_dir,
            os.path.join("子目录", "中文 空格 文档.txt"),
            [nested_payload, rng.choice(paragraphs)],
            ["topicalpha", "topicgamma"],
            records,
            tag_index,
        )

    # 2. Optional single large streaming document
    if large_file_mb > 0.0:
        large_target = int(large_file_mb * 1024 * 1024)
        large_path = os.path.join(out_dir, "large_streaming.txt")
        hasher = hashlib.sha256()
        actual_large = 0
        with open(large_path, "wb") as f:
            head = b"canaryheadtoken topicalpha\n"
            f.write(head)
            hasher.update(head)
            actual_large += len(head)
            while actual_large < large_target:
                chunk = rng.choice(paragraphs)
                f.write(chunk)
                hasher.update(chunk)
                actual_large += len(chunk)
            tail = b"\ncanarytailtoken\n"
            f.write(tail)
            hasher.update(tail)
            actual_large += len(tail)
        records.append({
            "rel_path": "large_streaming.txt",
            "bytes": actual_large,
            "sha256": hasher.hexdigest(),
            "tags": ["canaryheadtoken", "canarytailtoken", "topicalpha"],
        })
        for t in ("canaryheadtoken", "canarytailtoken", "topicalpha"):
            tag_index[t].add("large_streaming.txt")
        written_bytes += actual_large

    # 3. Main mixed-size Zipfian documents
    remaining_bytes = max(0, target_bytes - written_bytes)
    doc_idx = 0
    if num_files is not None and num_files > 0:
        per_file_base = max(128, remaining_bytes // num_files)
        for i in range(num_files):
            tags = choose_topic_tags(rng, i)
            header = (" ".join(tags) + "\n").encode("utf-8") if tags else b""
            chunks = [header]
            cur = len(header)
            while cur < per_file_base:
                p = rng.choice(paragraphs)
                chunks.append(p)
                cur += len(p)
            rel = os.path.join(f"bucket_{i % 10:02d}", f"doc_{i:05d}.txt")
            written_bytes += write_tracked_file(out_dir, rel, chunks, tags, records, tag_index)
    else:
        # Mix small (4KB-16KB) and medium (64KB-384KB) files naturally
        while written_bytes < target_bytes:
            is_small = (doc_idx % 4 != 0)
            size_goal = rng.randint(4 * 1024, 16 * 1024) if is_small else rng.randint(64 * 1024, 384 * 1024)
            size_goal = min(size_goal, max(1024, target_bytes - written_bytes))
            tags = choose_topic_tags(rng, doc_idx)
            header = (" ".join(tags) + "\n").encode("utf-8") if tags else b""
            chunks = [header]
            cur = len(header)
            while cur < size_goal:
                p = rng.choice(paragraphs)
                chunks.append(p)
                cur += len(p)
            rel = os.path.join(f"bucket_{doc_idx % 10:02d}", f"doc_{doc_idx:05d}.txt")
            written_bytes += write_tracked_file(out_dir, rel, chunks, tags, records, tag_index)
            doc_idx += 1

    records.sort(key=lambda r: str(r["rel_path"]))

    alpha = tag_index["topicalpha"]
    beta = tag_index["topicbeta"]
    gamma = tag_index["topicgamma"]
    queries = {
        "topicalpha": sorted(alpha),
        "topicbeta": sorted(beta),
        "topicgamma": sorted(gamma),
        "topicalpha AND topicbeta": sorted(alpha & beta),
        "topicalpha OR topicgamma": sorted(alpha | gamma),
        "topicalpha AND NOT topicbeta": sorted(alpha - beta),
        "crossboundaryen": sorted(tag_index["crossboundaryen"]),
        "搜索引擎": sorted(tag_index["搜索引擎"]),
        "canaryheadtoken": sorted(tag_index["canaryheadtoken"]),
        "canarytailtoken": sorted(tag_index["canarytailtoken"]),
    }

    manifest: Dict[str, object] = {
        "schema_version": 1,
        "seed": seed,
        "out_dir": os.path.abspath(out_dir),
        "summary": {
            "file_count": len(records),
            "total_bytes": written_bytes,
            "vocab_size": vocab_size,
        },
        "queries": queries,
        "files": records,
    }

    manifest_parent = os.path.dirname(os.path.abspath(manifest_path))
    if manifest_parent:
        os.makedirs(manifest_parent, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, ensure_ascii=False, indent=2)

    if not quiet:
        mb = written_bytes / (1024.0 * 1024.0)
        print(
            f"Generated {len(records)} files ({written_bytes} bytes / {mb:.2f} MB) "
            f"into '{out_dir}' with seed={seed}."
        )
        print(f"Ground-truth manifest written to '{manifest_path}'.")

    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a reproducible Zipfian benchmark corpus and ground-truth manifest."
    )
    parser.add_argument("--out-dir", default="test_docs", help="Output corpus directory (default: test_docs)")
    parser.add_argument(
        "--manifest",
        default=None,
        help="Path for ground-truth manifest JSON (default: <out-dir>.manifest.json outside out-dir)",
    )
    parser.add_argument("--total-mb", type=float, default=100.0, help="Target total corpus size in MB (default: 100)")
    parser.add_argument("--num-files", type=int, default=None, help="Optional fixed number of main documents")
    parser.add_argument("--large-file-mb", type=float, default=0.0, help="Optional single large file size in MB")
    parser.add_argument("--vocab-size", type=int, default=20000, help="Zipfian vocabulary size (default: 20000)")
    parser.add_argument("--seed", type=int, default=20260422, help="Deterministic PRNG seed (default: 20260422)")
    parser.add_argument("--no-edge-cases", action="store_true", help="Disable built-in edge-case boundary files")
    parser.add_argument("--clean", action="store_true", help="Remove existing out-dir before generating")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir_clean = args.out_dir.rstrip("/\\") or "test_docs"
    manifest_path = args.manifest if args.manifest else f"{out_dir_clean}.manifest.json"
    generate_corpus(
        out_dir=args.out_dir,
        manifest_path=manifest_path,
        total_mb=args.total_mb,
        vocab_size=args.vocab_size,
        seed=args.seed,
        num_files=args.num_files,
        large_file_mb=args.large_file_mb,
        include_edge_cases=not args.no_edge_cases,
        clean=args.clean,
        quiet=args.quiet,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
