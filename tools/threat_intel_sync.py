"""
Pulls malware-family threat intel (metadata only - hashes, imphash, tags,
file type, first-seen date) from MalwareBazaar's API and writes it into
data/known_imphashes.json, which src/static_scanner.py checks every scan
against each sample's own imphash.

This script NEVER downloads actual malware binaries. MalwareBazaar's API
also exposes a `get_file` query that returns the raw (zipped) sample - that
endpoint is deliberately not implemented anywhere in this file. Only
`get_recent`, `get_siginfo`, and `get_taginfo` are used, all of which
return JSON metadata about samples abuse.ch has already classified, not
sample content.

Setup:
    1. Get a free Auth-Key at https://auth.abuse.ch/ (personal account,
       API access under "MalwareBazaar").
    2. Provide it one of two ways - never hardcode it, never commit it:
       a) Environment variable:
              $env:MALWAREBAZAAR_AUTH_KEY = "your-key-here"
       b) A local key file (preferred - keeps the secret out of shell
          history/process listings entirely): create
          tools/.mb_auth_key containing just the key, no quotes, no
          trailing content. This filename is gitignored.

Usage:
    python threat_intel_sync.py --recent 100
    python threat_intel_sync.py --family Quasar --family AsyncRAT
    python threat_intel_sync.py --tag NSIS
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error
import urllib.parse

API_URL = "https://mb-api.abuse.ch/api/v1/"
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'known_imphashes.json')
KEY_FILE_PATH = os.path.join(os.path.dirname(__file__), '.mb_auth_key')


def _load_auth_key():
    """Env var takes priority; falls back to a local key file so the
    secret never has to appear in a shell command or env-var assignment
    (both of which land in shell history / process listings)."""
    env_key = os.environ.get('MALWAREBAZAAR_AUTH_KEY')
    if env_key:
        return env_key.strip()
    try:
        with open(KEY_FILE_PATH, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

# PE file types only - MalwareBazaar hosts far more than Windows PE
# malware (ELF, scripts, documents, etc.), and this project's static
# scanner only ever computes an imphash for PE files, so anything else
# would just be dead weight in the lookup table.
PE_FILE_TYPES = {'exe', 'dll', 'sys', 'scr', 'ocx', 'cpl'}


def _api_post(auth_key, query, extra_fields):
    fields = {"query": query, **extra_fields}
    body = urllib.parse.urlencode(fields).encode('ascii')
    req = urllib.request.Request(API_URL, data=body, method='POST')
    req.add_header('Auth-Key', auth_key)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP {e.code} from MalwareBazaar API: {e.read().decode('utf-8', errors='ignore')}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        print(f"[!] Network error contacting MalwareBazaar API: {e}", file=sys.stderr)
        return None


def _load_existing(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _merge_samples(known, samples, source_label):
    added = 0
    for s in samples:
        imphash = s.get('imphash')
        file_type = (s.get('file_type') or '').lower()
        if not imphash or file_type not in PE_FILE_TYPES:
            continue

        # `signature` is abuse.ch's actual confirmed family attribution.
        # `tags` is a free-form mix that includes real family names AND
        # generic type labels ("exe", "trojan", "rat") - falling back to
        # tags[0] produced misleading entries like family: "exe" for
        # samples abuse.ch hasn't attributed to a family yet. Be honest
        # about the uncertainty instead.
        family = s.get('signature') or 'unclassified'
        if imphash in known:
            known[imphash]['sample_count'] = known[imphash].get('sample_count', 1) + 1
        else:
            known[imphash] = {
                'family': family,
                'file_type': file_type,
                'first_seen': s.get('first_seen'),
                'source': 'malwarebazaar',
                'sample_count': 1,
                'query': source_label,
            }
            added += 1
    return added


def sync_recent(auth_key, known, selector):
    # get_recent's selector is NOT an arbitrary count - the API only
    # accepts the literal strings "time" (last 60 minutes) or "100" (most
    # recent 100 additions). Confirmed live: any other numeric value
    # returns query_status: unknown_selector.
    if selector not in ('time', '100'):
        print(f"[!] Invalid --recent value '{selector}' - must be 'time' or '100'.", file=sys.stderr)
        return 0
    print(f"[*] Fetching recent samples from MalwareBazaar (selector={selector})...")
    result = _api_post(auth_key, 'get_recent', {'selector': selector})
    if not result or result.get('query_status') != 'ok':
        print(f"[!] get_recent failed: {result.get('query_status') if result else 'no response'}", file=sys.stderr)
        return 0
    return _merge_samples(known, result.get('data', []), f'recent:{selector}')


def sync_signature(auth_key, known, family, limit=100):
    print(f"[*] Fetching samples for signature/family '{family}'...")
    result = _api_post(auth_key, 'get_siginfo', {'signature': family, 'limit': str(limit)})
    if not result or result.get('query_status') != 'ok':
        print(f"[!] get_siginfo for '{family}' failed: {result.get('query_status') if result else 'no response'}", file=sys.stderr)
        return 0
    return _merge_samples(known, result.get('data', []), f'signature:{family}')


def sync_tag(auth_key, known, tag, limit=100):
    print(f"[*] Fetching samples tagged '{tag}'...")
    result = _api_post(auth_key, 'get_taginfo', {'tag': tag, 'limit': str(limit)})
    if not result or result.get('query_status') != 'ok':
        print(f"[!] get_taginfo for '{tag}' failed: {result.get('query_status') if result else 'no response'}", file=sys.stderr)
        return 0
    return _merge_samples(known, result.get('data', []), f'tag:{tag}')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--recent', choices=['time', '100'], metavar='{time,100}',
                         help="Pull recent samples: 'time' (last 60 min) or '100' (most recent 100) - the only two values MalwareBazaar's API accepts")
    parser.add_argument('--family', action='append', default=[], help='Pull samples by signature/family name (repeatable)')
    parser.add_argument('--tag', action='append', default=[], help='Pull samples by tag (repeatable)')
    args = parser.parse_args()

    auth_key = _load_auth_key()
    if not auth_key:
        print(
            "[!] No MalwareBazaar Auth-Key found.\n"
            "    Get a free key at https://auth.abuse.ch/, then either:\n"
            '      $env:MALWAREBAZAAR_AUTH_KEY = "your-key-here"     (env var), or\n'
            f"      write it (just the key, nothing else) to: {KEY_FILE_PATH}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not (args.recent or args.family or args.tag):
        parser.print_help()
        sys.exit(1)

    known = _load_existing(OUTPUT_PATH)
    total_added = 0

    if args.recent:
        total_added += sync_recent(auth_key, known, args.recent)
    for family in args.family:
        total_added += sync_signature(auth_key, known, family)
    for tag in args.tag:
        total_added += sync_tag(auth_key, known, tag)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(known, f, indent=2, sort_keys=True)

    print(f"\n[+] Done. {total_added} new imphash(es) added, {len(known)} total known imphashes in {OUTPUT_PATH}")


if __name__ == '__main__':
    main()
