import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict, Any, Tuple, List

import requests
from concurrent.futures import ProcessPoolExecutor, as_completed

COMBO_URL = "https://github.com/JeyKul/fwcheck2/raw/refs/heads/main/ALLvalid_combinations.json"
COMBO_FILE = Path("ALLvalid_combinations.pruned.json")


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def fetch_text(url: str) -> str:
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    return resp.text


def fetch_json(url: str):
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def extract_pda_from_version_xml(text: str) -> str | None:
    m = re.search(r"<pda>([A-Z0-9]{12,})</pda>", text)
    if m:
        return m.group(1)
    m = re.search(r"([A-Z0-9]{5}XX[USMQ][0-9A-Z][A-Z0-9]{3,})/[A-Z0-9]+/[A-Z0-9]+", text)
    if m:
        return m.group(1)
    return None


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


def process_one(args: Tuple[str, str, bool]) -> Tuple[str, str, int, bool]:
    """
    Worker:
      - returns (CSC, MODEL, match_count, had_network_error)
      - had_network_error=True if version.xml or version.test.xml failed
    """
    csc, model_id, verbose = args

    base_url = f"http://fota-cloud-dn.ospserver.net/firmware/{csc}/SM-{model_id}"

    # 1) version.xml -> PDA
    ver_xml_url = f"{base_url}/version.xml"
    if verbose:
        print(f"[{csc}/{model_id}] Downloading version.xml: {ver_xml_url}", file=sys.stderr)
    try:
        ver_xml_text = fetch_text(ver_xml_url)
    except Exception as e:
        print(f"[{csc}/{model_id}] Failed to fetch version.xml: {e}", file=sys.stderr)
        return csc, model_id, 0, True  # network / server error

    pda = extract_pda_from_version_xml(ver_xml_text)
    if not pda:
        print(f"[{csc}/{model_id}] Could not extract PDA from version.xml", file=sys.stderr)
        return csc, model_id, 0, True

    pda = pda.upper()
    if len(pda) < 10:
        print(f"[{csc}/{model_id}] PDA too short: {pda}", file=sys.stderr)
        return csc, model_id, 0, True

    model_part = pda[0:5]
    mid = pda[5:8]
    boot = pda[8]
    tail = pda[9:]
    if len(tail) < 3:
        print(f"[{csc}/{model_id}] Tail too short: {tail}", file=sys.stderr)
        return csc, model_id, 0, True

    os_letter = tail[0]
    year_letter = tail[1]

    # 2) version.test.xml -> hashes
    ver_test_url = f"{base_url}/version.test.xml"
    if verbose:
        print(f"[{csc}/{model_id}] Downloading version.test.xml: {ver_test_url}", file=sys.stderr)
    try:
        ver_test_text = fetch_text(ver_test_url)
    except Exception as e:
        print(f"[{csc}/{model_id}] Failed to fetch version.test.xml: {e}", file=sys.stderr)
        return csc, model_id, 0, True

    hashes = set(m.group(0).lower() for m in re.finditer(r"[0-9a-fA-F]{32}", ver_test_text))
    if not hashes:
        if verbose:
            print(f"[{csc}/{model_id}] No hashes in version.test.xml", file=sys.stderr)
        # This is not a network error, just no data
        return csc, model_id, 0, False

    # 3) logical sweep
    months = list("ABCDEFGHIJKL")
    incrementals = list("123456789") + list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    resolved_strings: list[str] = []
    seen_full = set()

    for month in months:
        for inc in incrementals:
            suffix = f"{os_letter}{year_letter}{month}{inc}"
            p1 = f"{model_part}{mid}{boot}{suffix}"
            p2 = f"{model_part}OXM{boot}{suffix}"
            full = f"{p1}/{p2}/{p1}"
            if full in seen_full:
                continue
            seen_full.add(full)

            h = md5_hex(full)
            if h in hashes:
                if verbose:
                    print(f"[{csc}/{model_id}] Match: {h} -> {full}", file=sys.stderr)
                resolved_strings.append(full)

    out_name = f"current.test.{csc}.{model_id}"
    out_path = Path(out_name)
    out_path.write_text(
        "\n".join(resolved_strings) + ("\n" if resolved_strings else ""),
        encoding="utf-8",
    )

    if verbose:
        print(f"[{csc}/{model_id}] Wrote {len(resolved_strings)} entries to {out_path}", file=sys.stderr)

    return csc, model_id, len(resolved_strings), False


def main():
    parser = argparse.ArgumentParser(
        description="Multicore FOTA brute-force and auto-prune dead CSC/model pairs"
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
        "--update-combos",
        action="store_true",
        help="(Re)download ALLvalid_combinations.json from GitHub",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of worker processes (default: 4)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose logging",
    )
    parser.add_argument(
        "--write-pruned",
        action="store_true",
        help="Write a pruned JSON without failing CSC/model pairs",
    )
    args = parser.parse_args()

    # Load or update JSON
    if args.update_combos or not COMBO_FILE.is_file():
        print(f"[+] Downloading {COMBO_URL}", file=sys.stderr)
        raw = fetch_json(COMBO_URL)
        COMBO_FILE.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    else:
        raw = json.loads(COMBO_FILE.read_text(encoding="utf-8"))

    csc_map = raw.get("CSC") or raw.get("csc")
    if not isinstance(csc_map, dict):
        print("[-] JSON does not contain 'CSC' map as expected", file=sys.stderr)
        sys.exit(1)

    all_pairs = iter_all_csc_models(csc_map)

    # apply optional filters
    filtered_pairs = []
    for csc, model_id in all_pairs:
        if args.only_csc and csc.upper() != args.only_csc.upper():
            continue
        if args.only_model and model_id.upper() != args.only_model.upper():
            continue
        filtered_pairs.append((csc, model_id))

    if not filtered_pairs:
        print("[-] No CSC/model pairs to process after filters", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Processing {len(filtered_pairs)} CSC/model pairs with {args.workers} workers", file=sys.stderr)

    total_matches = 0
    total_pairs = 0
    bad_pairs: set[Tuple[str, str]] = set()

    from concurrent.futures import ProcessPoolExecutor, as_completed

    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futures = [
            ex.submit(process_one, (csc, model_id, args.verbose))
            for csc, model_id in filtered_pairs
        ]
        for fut in as_completed(futures):
            try:
                csc, model_id, matches, had_error = fut.result()
            except Exception as e:
                print(f"[!] Worker error: {e}", file=sys.stderr)
                continue
            total_pairs += 1
            total_matches += matches
            if had_error:
                bad_pairs.add((csc, model_id))
                print(f"[+] {csc}/{model_id}: network/error -> mark as bad", file=sys.stderr)
            else:
                print(f"[+] {csc}/{model_id}: {matches} matches", file=sys.stderr)

    print(f"[+] Done. Processed {total_pairs} pairs, total matches: {total_matches}", file=sys.stderr)

    # build pruned JSON
    if args.write_pruned:
        pruned = raw.copy()
        pruned_csc_map = pruned.get("CSC") or pruned.get("csc")
        if isinstance(pruned_csc_map, dict):
            for csc, model_id in bad_pairs:
                models = pruned_csc_map.get(csc, {})
                key = f"SM-{model_id}"
                if key in models:
                    models.pop(key, None)
            # remove CSCs that became empty
            empty_csc = [c for c, m in pruned_csc_map.items() if isinstance(m, dict) and not m]
            for c in empty_csc:
                pruned_csc_map.pop(c, None)

        out_pruned = COMBO_FILE.with_name("ALLvalid_combinations.pruned.json")
        out_pruned.write_text(json.dumps(pruned, indent=2), encoding="utf-8")
        print(f"[+] Wrote pruned combinations to {out_pruned}", file=sys.stderr)


if __name__ == "__main__":
    main()
