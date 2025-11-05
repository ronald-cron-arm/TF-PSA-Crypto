#!/usr/bin/env python3
"""
Clone a driver directory, fix includes, and prefix symbols with the driver name using ctags.
No backup files are created.

All *relative* paths are interpreted relative to the repository root (the current working directory).

Behavior:
  - Copy SRC_DIR → DST_DIR/DRIVER (destination root is "<dst_dir>/<driver>")
  - Rename DST_DIR/DRIVER/include/mbedtls → DST_DIR/DRIVER/include/<driver>
  - Rewrite #include lines "mbedtls/..." → "<driver>/..." only if the header exists under
    DST_DIR/DRIVER/include/<driver> (including private/)
  - Step 4: Prefix symbols only if:
      (a) they start with one of: 
          TF_PSA_CRYPTO_MBEDTLS_, TF_PSA_CRYPTO_PSA_CRYPTO_, 
          mbedtls_, MBEDTLS_, psa_, PSA_
      (b) they are reported by `ctags -x --language-force=C --c-kinds=defpst` 
          on all .c/.h under the target dir
    EXCEPTIONS (forced):
      - Any symbol in FORCE_RENAME_SYMBOLS present in the target tree is prefixed.
      - Any symbol whose name starts with any prefix in FORCE_RENAME_PREFIXES and 
        is present in the target tree is prefixed.
  - Verbose mode prints excluded files and excluded/eligible symbols (lists).
"""

import argparse
import fnmatch
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Set

# ---------- CONFIG ----------

# File-name-only exclusions for the copy step (match anywhere by filename)
DEFAULT_EXCLUDE_PATTERNS = [
    "asn1*",
    "base64*",
    "CMakeLists.txt",
    "crypto_builtin_key_derivation.h",
    "lmots*",
    "lms.c",
    "md.c",
    "memory_buffer_alloc.c",
    "nist_kw.c",
    "pem.c",
    "pk*",
    "platform*",
    "threading*",
]

# Repo-root–relative directories where ctags should scan headers for "do-not-touch" symbols.
DEFAULT_CTAGS_DIRS = [
    "core",
    "include/mbedtls",
    "include/psa",
    "include/tf-psa-crypto",
]

# Hard-coded list of header basenames to ignore for ctags scanning.
IGNORE_HEADERS_FOR_CTAGS = {
    "crypto_driver_contexts_primitives.h",
    "crypto_driver_contexts_composites.h",
    "crypto_driver_contexts_key_derivation.h",
}

# Hard-coded list of symbols that should be renamed even if found by ctags.
FORCE_RENAME_SYMBOLS = {
    "MBEDTLS_AESCE_C",
    "MBEDTLS_AESNI_C",
    "MBEDTLS_ECP_NIST_OPTIM",
    "MBEDTLS_ECP_RESTARTABLE",
    "MBEDTLS_PRIVATE",
}

# Hard-coded symbol *prefixes* to force-prefix if present in target tree.
FORCE_RENAME_PREFIXES = {
    "MBEDTLS_PSA_ACCEL_",
}

CTAGS_CMD_BASE = ["ctags", "-x", "--language-force=C", "--c-kinds=defpstv"]

INCLUDE_LINE_RE = re.compile(
    r'^\s*#\s*include\s*([<"])\s*mbedtls/([^>"]+)\s*([>"])', re.MULTILINE
)
IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")

# Priority order for prefix detection
PREFIXES = (
    "TF_PSA_CRYPTO_MBEDTLS_",
    "TF_PSA_CRYPTO_PSA_",
    "MBEDTLS_",
    "PSA_",
    "mbedtls_",
    "psa_",
)


# ---------- UTILITIES ----------

def build_exclude_matcher(src_root: Path, patterns: List[str]) -> Set[Path]:
    rel_excluded = set()
    for p in src_root.rglob("*"):
        if p.is_file() and any(fnmatch.fnmatch(p.name, pat) for pat in patterns):
            rel_excluded.add(p.relative_to(src_root))
    return rel_excluded


def copy_tree_with_exclusions(src: Path, dst: Path, rel_excluded: Set[Path], verbose: bool) -> None:
    if dst.exists():
        print(f"Removing pre-existing destination: {dst}")
        shutil.rmtree(dst)

    print(f"Copying tree: {src} → {dst}")
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        if any(part == ".git" for part in rel.parts):
            continue
        if p.is_dir():
            (dst / rel).mkdir(parents=True, exist_ok=True)
        elif rel not in rel_excluded:
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst / rel)

    if verbose and rel_excluded:
        print(f"Excluded {len(rel_excluded)} file(s):")
        for r in sorted(rel_excluded):
            print(f"  - {r}")


def rename_include_dir(dst_root: Path, driver: str) -> Path:
    old_dir = dst_root / "include" / "mbedtls"
    new_dir = dst_root / "include" / driver
    if old_dir.exists():
        print(f"Renaming include dir: {old_dir} → {new_dir}")
        if new_dir.exists():
            shutil.rmtree(new_dir)
        old_dir.rename(new_dir)
    else:
        print(f"Note: {old_dir} not found; skipping include dir rename.")
    return new_dir


def collect_header_relpaths(include_root: Path) -> Set[str]:
    headers = set()
    if include_root.is_dir():
        for h in include_root.rglob("*.h"):
            headers.add(h.relative_to(include_root).as_posix())
    return headers


def rewrite_includes_in_file(path: Path, header_set: Set[str], driver: str) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False

    changed = False

    def repl(m: re.Match) -> str:
        nonlocal changed
        hdr = m.group(2)
        if hdr in header_set:
            changed = True
            return f'#include {m.group(1)}{driver}/{hdr}{m.group(3)}'
        return m.group(0)

    new_text = INCLUDE_LINE_RE.sub(repl, text)
    if changed:
        path.write_text(new_text, encoding="utf-8")
    return changed


def run_ctags(files: List[Path]) -> Set[str]:
    if not files:
        return set()
    try:
        res = subprocess.run(CTAGS_CMD_BASE + [str(f) for f in files],
                             check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Warning: ctags failed; proceeding without symbol set filtering.", file=sys.stderr)
        return set()
    syms = set()
    for line in res.stdout.splitlines():
        parts = line.split()
        if parts:
            syms.add(parts[0])
    return syms


def collect_target_symbols(dst_root: Path) -> Set[str]:
    files = [p for p in dst_root.rglob("*") if p.suffix in (".c", ".h")]
    return run_ctags(files)


def symbols_present_in_dst(dst_root: Path, symbols: Set[str]) -> Set[str]:
    """Return subset of 'symbols' that appear (as whole identifiers) in any .c/.h under dst_root."""
    if not symbols:
        return set()
    wanted = {s: re.compile(rf"\b{s}\b") for s in symbols}
    present = set()
    for p in dst_root.rglob("*"):
        if p.suffix not in (".c", ".h"):
            continue
        try:
            txt = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for s, pat in list(wanted.items()):
            if pat.search(txt):
                present.add(s)
                del wanted[s]
        if not wanted:
            break
    return present


def symbols_with_prefixes_in_dst(dst_root: Path, prefixes: Set[str]) -> Set[str]:
    """Return all identifiers in the target tree that start with any of 'prefixes'."""
    found = set()
    if not prefixes:
        return found
    for p in dst_root.rglob("*"):
        if p.suffix not in (".c", ".h"):
            continue
        try:
            txt = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for ident in IDENT_RE.findall(txt):
            if any(ident.startswith(pref) for pref in prefixes):
                found.add(ident)
    return found


def build_exclusion_symbols(repo_root: Path, verbose: bool) -> Set[str]:
    excluded = set()
    for rel_path in DEFAULT_CTAGS_DIRS:
        header_dir = (repo_root / rel_path).resolve()
        if not header_dir.is_dir():
            if verbose:
                print(f"Note: skipping missing ctags dir {header_dir}")
            continue
        files = [p for p in header_dir.rglob("*.h") if p.name not in IGNORE_HEADERS_FOR_CTAGS]
        excluded |= run_ctags(files)
    excluded = {s for s in excluded if s.startswith(PREFIXES)}
    before = len(excluded)
    excluded -= FORCE_RENAME_SYMBOLS
    excluded = {s for s in excluded if not any(s.startswith(pref) for pref in FORCE_RENAME_PREFIXES)}
    if verbose:
        removed = before - len(excluded)
        if removed:
            print(f"Removed {removed} forced symbol(s)/prefix(es) from exclusion list.")
        print(f"Excluded symbols total: {len(excluded)}")
        if excluded:
            for s in sorted(excluded):
                print(f"  - {s}")
    return excluded


def compute_eligible_symbols(dst_root: Path, repo_root: Path, verbose: bool) -> Set[str]:
    dst_syms = collect_target_symbols(dst_root)
    dst_syms = {s for s in dst_syms if s.startswith(PREFIXES)}
    if verbose:
        print(f"Target symbols from ctags (matching prefixes): {len(dst_syms)}")

    exclusions = build_exclusion_symbols(repo_root, verbose)
    eligible = dst_syms - exclusions

    forced_present_exact = symbols_present_in_dst(dst_root, FORCE_RENAME_SYMBOLS)
    eligible |= forced_present_exact

    forced_present_by_prefix = symbols_with_prefixes_in_dst(dst_root, FORCE_RENAME_PREFIXES)
    eligible |= forced_present_by_prefix

    if verbose:
        if forced_present_exact:
            print(f"Forced exact symbols added: {len(forced_present_exact)}")
            for s in sorted(forced_present_exact):
                print(f"  + {s}")
        if forced_present_by_prefix:
            print(f"Forced prefix symbols added: {len(forced_present_by_prefix)} (matching {', '.join(sorted(FORCE_RENAME_PREFIXES))})")
            for s in sorted(forced_present_by_prefix):
                print(f"  + {s}")
        print(f"Eligible symbols to prefix: {len(eligible)}")
        for s in sorted(eligible):
            print(f"  * {s}")
    return eligible


def prefix_for_symbol(ident: str, driver: str) -> str:
    du = driver.upper()
    if ident.startswith("TF_PSA_CRYPTO_MBEDTLS_") or ident.startswith("TF_PSA_CRYPTO_PSA_CRYPTO_"):
        return f"{du}_{ident}"
    if ident.startswith("MBEDTLS_"):
        return f"{du}_{ident}"
    if ident.startswith("PSA_"):
        return f"{du}_{ident}"
    if ident.startswith("mbedtls_"):
        return f"{driver}_{ident}"
    if ident.startswith("psa_"):
        return f"{driver}_{ident}"
    return ident


def prefix_symbols_in_file(path: Path, eligible: Set[str], driver: str) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return
    changed = False

    def repl(m: re.Match) -> str:
        nonlocal changed
        ident = m.group(0)
        if ident in eligible:
            changed = True
            return prefix_for_symbol(ident, driver)
        return ident

    new_text = IDENT_RE.sub(repl, text)
    if changed:
        path.write_text(new_text, encoding="utf-8")


def iter_code_files(root: Path) -> Iterable[Path]:
    for ext in (".c", ".h"):
        yield from root.rglob(f"*{ext}")


# ---------- MAIN ----------

def main():
    ap = argparse.ArgumentParser(description="Clone driver tree, rewrite includes, and prefix symbols (no backups).")
    ap.add_argument("src_dir", help="Source directory (relative to repo root)")
    ap.add_argument("dst_dir", help="Destination directory (relative to repo root or absolute)")
    ap.add_argument("driver", help="New driver name (e.g. testdriver1)")
    ap.add_argument("--verbose", action="store_true", help="Verbose output (excluded files, symbols)")
    args = ap.parse_args()

    repo_root = Path.cwd()
    src = (repo_root / args.src_dir).resolve()

    dst_base = Path(args.dst_dir)
    if not dst_base.is_absolute():
        dst_base = (repo_root / dst_base).resolve()
    dst = (dst_base / args.driver).resolve()

    driver = args.driver
    verbose = args.verbose

    if not src.is_dir():
        sys.exit(f"Source is not a directory: {src}")

    # Step 1
    rel_excluded = build_exclude_matcher(src, DEFAULT_EXCLUDE_PATTERNS)
    copy_tree_with_exclusions(src, dst, rel_excluded, verbose)

    # Step 2
    new_include_dir = rename_include_dir(dst, driver)

    # Step 3
    header_set = collect_header_relpaths(new_include_dir)
    updated = sum(1 for f in iter_code_files(dst) if rewrite_includes_in_file(f, header_set, driver))
    print(f"Include rewrites: {updated} file(s) updated")

    # Step 4 — eligible set from ctags + forced (exact and prefixes)
    eligible = compute_eligible_symbols(dst, repo_root, verbose)
    for f in iter_code_files(dst):
        prefix_symbols_in_file(f, eligible, driver)

    print("Symbol prefixing complete.")
    print("✅ Done.")


if __name__ == "__main__":
    main()
