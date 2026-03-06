#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import sys
import subprocess
import os
import time
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional

import requests
from concurrent.futures import ProcessPoolExecutor, as_completed
import filecmp
import xml.etree.ElementTree as ET

# === CONFIG ===
COMBO_FILE = Path("ALLvalid_combinations.pruned.json")
BASE_URL = "http://fota-cloud-dn.ospserver.net/firmware"


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def fetch_text(url: str, timeout: int = 20) -> str:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def extract_pda_from_version_xml(text: str) -> Optional[str]:
    m = re.search(r"<pda>([A-Z0-9]{12,})</pda>", text)
    if m:
        return m.group(1)
    m = re.search(
        r"([A-Z0-9]{5}XX[USMQ][0-9A-Z][A-Z0-9]{3,})/[A-Z0-9]+/[A-Z0-9]+",
        text,
    )
    if m:
        return m.group(1)
    return None


def extract_known_pdas(version_xml: str) -> set[str]:
    """
    Parse version.xml and collect all PDA-like strings seen for this device/CSC.
    We treat any token that looks like a PDA/build (has '/' with three segments)
    as a known firmware string for this phone. [web:55][web:52]
    """
    known: set[str] = set()
    try:
        root = ET.fromstring(version_xml)
    except Exception:
        return known

    # Look for text content that resembles "PDA/CSC/PHONE"
    for elem in root.iter():
        if elem.text:
            t = elem.text.strip()
            if "/" in t:
                parts = t.split("/")
                if len(parts) == 3:
                    # store PDA part only (first segment)
                    known.add(parts[0].strip())
        # Also scan attributes; some firmwares embed builds in attributes
        for v in elem.attrib.values():
            v = v.strip()
            if "/" in v:
                parts = v.split("/")
                if len(parts) == 3:
                    known.add(parts[0].strip())

    return known


def iter_all_csc_models(csc_map: Dict[str, Any]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for csc, models in csc_map.items():
        if not isinstance(models, dict):
            continue
        for full_model, ok in models.items():
            if not ok:
                continue
            m = str(full_model).upper().replace("SM-", "")
            pairs.append((csc.upper(), m))
    return pairs


def write_if_changed_and_commit(csc: str, model_id: str, latest: str) -> bool:
    """
    Write current.test.<CSC>.<MODEL> via temp file, compare, move if changed,
    and commit. Returns True if a commit was made.
    Mirrors latest-2.py behavior (one line file). [web:37][web:40]
    """
    file_path = Path(f"current.test.{csc}.{model_id}")
    tmp_path = file_path.parent / f".tmp_current.test.{csc}_{model_id}"

    # Write new content (just latest, one line)
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(f"{latest}\n")

    # Compare existing vs new
    changed = True
    if file_path.exists() and filecmp.cmp(file_path, tmp_path, shallow=False):
        tmp_path.unlink(missing_ok=True)
        changed = False

    if not changed:
        return False

    # Move safely (same dir, so replace or fallback to move)
    try:
        tmp_path.replace(file_path)
    except OSError:
        from shutil import move
        move(str(tmp_path), str(file_path))

    # Commit message similar to latest-2.py: "CSC/SM-MODEL: VERSION"
    commit_msg = f"{csc}/SM-{model_id}: {latest}"
    subprocess.run(["git", "add", str(file_path)], check=False)
    subprocess.run(["git", "commit", "-m", commit_msg], check=False)

    return True


def process_one(args: Tuple[str, str, bool]) -> Tuple[str, str, int, bool, bool]:
    """
    Worker:
      - returns (CSC, MODEL, match_count, had_network_error, committed)
      - had_network_error=True if version.xml or version.test.xml failed
      - committed=True if file changed and a git commit was made
    """
    csc, model_id, verbose = args

    base_url = f"{BASE_URL}/{csc}/SM-{model_id}"

    # 1) version.xml -> PDA and known PDAs
    ver_xml_url = f"{base_url}/version.xml"
    if verbose:
        print(f"[{csc}/{model_id}] Downloading version.xml: {ver_xml_url}", file=sys.stderr)
    try:
        ver_xml_text = fetch_text(ver_xml_url, timeout=20)
    except Exception as e:
        print(f"[{csc}/{model_id}] Failed to fetch version.xml: {e}", file=sys.stderr)
        return csc, model_id, 0, True, False  # network / server error

    pda = extract_pda_from_version_xml(ver_xml_text)
    if not pda:
        print(f"[{csc}/{model_id}] Could not extract PDA from version.xml", file=sys.stderr)
        return csc, model_id, 0, True, False

    pda = pda.upper()
    if len(pda) < 10:
        print(f"[{csc}/{model_id}] PDA too short: {pda}", file=sys.stderr)
        return csc, model_id, 0, True, False

    known_pdas = extract_known_pdas(ver_xml_text)

    model_part = pda[0:5]
    mid = pda[5:8]
    boot = pda[8]
    tail = pda[9:]
    if len(tail) < 3:
        print(f"[{csc}/{model_id}] Tail too short: {tail}", file=sys.stderr)
        return csc, model_id, 0, True, False

    os_letter = tail[0]
    year_letter = tail[1]

    # 2) version.test.xml -> hashes
    ver_test_url = f"{base_url}/version.test.xml"
    if verbose:
        print(f"[{csc}/{model_id}] Downloading version.test.xml: {ver_test_url}", file=sys.stderr)
    try:
        ver_test_text = fetch_text(ver_test_url, timeout=30)
    except Exception as e:
        print(f"[{csc}/{model_id}] Failed to fetch version.test.xml: {e}", file=sys.stderr)
        return csc, model_id, 0, True, False

    hashes = [
        m.group(0).lower() for m in re.finditer(r"[0-9a-fA-F]{32}", ver_test_text)
    ]
    if not hashes:
        if verbose:
            print(f"[{csc}/{model_id}] No hashes in version.test.xml", file=sys.stderr)
        # No data, but not a network error. No file/commit.
        return csc, model_id, 0, False, False

    hash_set = set(hashes)

    # 3) logical sweep: collect all matches
    months = list("ABCDEFGHIJKL")
    incrementals = list("123456789") + list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    all_matches: list[str] = []

    for month in months:
        for inc in incrementals:
            suffix = f"{os_letter}{year_letter}{month}{inc}"
            p1 = f"{model_part}{mid}{boot}{suffix}"
            p2 = f"{model_part}OXM{boot}{suffix}"
            full = f"{p1}/{p2}/{p1}"

            h = md5_hex(full)
            if h in hash_set:
                all_matches.append(full)
                if verbose:
                    print(f"[{csc}/{model_id}] Match #{len(all_matches)}: {h} -> {full}", file=sys.stderr)

    match_count = len(all_matches)
    if match_count == 0:
        if verbose:
            print(f"[{csc}/{model_id}] No matches found in logical sweep", file=sys.stderr)
        return csc, model_id, 0, False, False

    # 4) filter to unique (beta-ish) PDAs: PDA not present in version.xml known set.
    unique_matches: list[str] = []
    for full in all_matches:
        pda_part = full.split("/")[0]
        if pda_part not in known_pdas:
            unique_matches.append(full)

    if not unique_matches:
        # Error catch: no unique beta version available
        if verbose:
            print(
                f"[{csc}/{model_id}] Matches found but none unique vs version.xml; skipping",
                file=sys.stderr,
            )
        return csc, model_id, match_count, False, False

    # 5) choose latest unique: last one found in brute-force order
    latest_unique = unique_matches[-1]

    if verbose:
        print(
            f"[{csc}/{model_id}] Total matches: {match_count}, unique: {len(unique_matches)}, "
            f"latest unique: {latest_unique}",
            file=sys.stderr,
        )

    # 6) write + commit if changed
    committed = write_if_changed_and_commit(csc, model_id, latest_unique)

    return csc, model_id, match_count, False, committed


def auto_workers(user_workers: Optional[int]) -> int:
    if user_workers is not None:
        return max(1, user_workers)
    n = os.cpu_count() or 1
    return n


def main():
    parser = argparse.ArgumentParser(
        description="Multicore FOTA brute-force (unique beta-only) with git commits, using pruned combos"
    )
    parser.add_argument(
        "--only-model",
        help="Optional: only this model (without SM-), e.g. S908B",
    )
    parser.add_argument(
        "--only-csc",
        help="Optional: only this CSC, e.g. EUX",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of worker processes (default: all logical cores)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose logging",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Run 'git push' right after each commit",
    )
    args = parser.parse_args()

    # Always primarily use the pruned file; no re-sorting.
    if not COMBO_FILE.is_file():
        print(f"[-] Pruned combinations file not found: {COMBO_FILE}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = json.loads(COMBO_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[-] Failed to parse {COMBO_FILE}: {e}", file=sys.stderr)
        sys.exit(1)

    csc_map = raw.get("CSC") or raw.get("csc")
    if not isinstance(csc_map, dict):
        print("[-] JSON does not contain 'CSC' map as expected", file=sys.stderr)
        sys.exit(1)

    all_pairs = iter_all_csc_models(csc_map)

    # apply optional filters
    filtered_pairs: List[Tuple[str, str]] = []
    for csc, model_id in all_pairs:
        if args.only_csc and csc.upper() != args.only_csc.upper():
            continue
        if args.only_model and model_id.upper() != args.only_model.upper():
            continue
        filtered_pairs.append((csc, model_id))

    if not filtered_pairs:
        print("[-] No CSC/model pairs to process after filters", file=sys.stderr)
        sys.exit(1)

    workers = auto_workers(args.workers)
    print(
        f"[+] Processing {len(filtered_pairs)} CSC/model pairs with {workers} workers",
        file=sys.stderr,
    )

    total_matches = 0
    total_pairs = 0
    commits_made = 0

    start = time.time()

    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(process_one, (csc, model_id, args.verbose))
            for csc, model_id in filtered_pairs
        ]
        for fut in as_completed(futures):
            try:
                csc, model_id, matches, had_error, committed = fut.result()
            except Exception as e:
                print(f"[!] Worker error: {e}", file=sys.stderr)
                continue

            total_pairs += 1
            total_matches += matches

            if had_error:
                print(f"[+] {csc}/{model_id}: network/error", file=sys.stderr)
            else:
                print(
                    f"[+] {csc}/{model_id}: {matches} matches, committed={committed}",
                    file=sys.stderr,
                )

            if committed:
                commits_made += 1
                if args.push:
                    print(f"[+] {csc}/{model_id}: pushing changes to GitHub...", file=sys.stderr)
                    subprocess.run(["git", "push"], check=False)

    elapsed = time.time() - start
    print(
        f"[+] Done. Processed {total_pairs} pairs, total matches: {total_matches}, "
        f"commits: {commits_made}, time: {elapsed:.1f}s",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
