#!/usr/bin/env bash
# Fail if anything that looks like a real credential or a real device is about
# to be committed.
#
# This is a backstop for .gitignore, not a replacement. .gitignore only helps
# for paths nobody has staged yet; a `git add -f`, a renamed file, or a key
# pasted into a source comment slips straight past it. This scans the *tracked*
# tree, so it catches the mistake at CI time rather than after publication.
#
# Scanning is deliberately conservative: it flags anything credential-shaped and
# requires known-safe values to be listed explicitly below. A false positive
# costs a minute; a false negative publishes a key that opens someone's door.
set -Eeuo pipefail

cd "$(dirname "$0")/.."

fail=0
report() {
  echo "SECRET-SCAN: $1" >&2
  fail=1
}

# This scan asks "what would a commit expose", which only has an answer inside a
# git checkout. Without one, every `git ls-files` below yields nothing and the
# script cheerfully reports a clean scan of zero files — the worst possible
# failure for a security backstop. Refuse instead.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "check-secrets: not a git repository, so there are no tracked files to scan." >&2
  echo "This scan reports what a commit would expose; run it inside a checkout." >&2
  exit 1
fi

# Test vectors that are intentionally present. Anything credential-shaped that
# is NOT one of these is reported.
#
#   00112233445566778899aabbccddeeff  the obviously-synthetic AES test key
#   0a0b0c0d0e0f10111213141516171819  a second synthetic key, sciener tests
#   deadbeef                          placeholder in sample-lockData.json
#   987623e8a923a1bb3d9e7d0378124588  TTLock's *factory* key: hardcoded in the
#                                     vendor firmware, identical on every
#                                     unpaired lock, so public by construction
# Synthetic test vectors only. `000102...0f` is 16 counting bytes, used by the
# AesKey tests precisely so a length or ordering bug is obvious on sight; it
# could not be a real key.
ALLOWED_KEYS='00112233445566778899aabbccddeeff|0a0b0c0d0e0f10111213141516171819|987623e8a923a1bb3d9e7d0378124588|000102030405060708090a0b0c0d0e0f'

# Files whose content is protocol documentation rather than credentials.
EXCLUDE_PATHS=(':!Cargo.lock' ':!flake.lock' ':!*.png' ':!*.jpg' ':!*.sqlite*')

echo "Scanning $(git ls-files -- . "${EXCLUDE_PATHS[@]}" | wc -l | tr -d ' ') tracked files..."

# --- 1. AES-key-shaped strings (32 hex chars) --------------------------------
while IFS= read -r hit; do
  value=$(echo "${hit}" | grep -oiE '[0-9a-f]{32}' | head -1 | tr '[:upper:]' '[:lower:]')
  if ! echo "${value}" | grep -qiE "^(${ALLOWED_KEYS})$"; then
    report "possible AES key: ${hit}"
  fi
done < <(git grep -InE '(^|[^0-9a-fA-F])[0-9a-fA-F]{32}([^0-9a-fA-F]|$)' -- . "${EXCLUDE_PATHS[@]}" || true)

# --- 2. Real BLE addresses ---------------------------------------------------
# Documentation examples must use the reserved-looking AA:BB:CC:DD:EE:FF style
# or 00:00:.., not a device someone actually owns.
while IFS= read -r hit; do
  addr=$(echo "${hit}" | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1 | tr '[:lower:]' '[:upper:]')
  case "${addr}" in
    AA:BB:CC:DD:EE:FF | 00:00:00:00:00:00 | FF:FF:FF:FF:FF:FF | AA:BB:CC:DD:EE:F0) ;;
    *) report "possible real BLE address ${addr}: ${hit}" ;;
  esac
done < <(git grep -InE '(^|[^0-9a-fA-F:])([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}([^0-9a-fA-F:]|$)' -- . "${EXCLUDE_PATHS[@]}" || true)

# --- 3. Files that should never be tracked at all ----------------------------
while IFS= read -r tracked; do
  report "file should never be committed: ${tracked}"
done < <(git ls-files | grep -iE '(^|/)(lockData\.json|.*\.sqlite.*|.*\.pklg|.*\.pcapng?)$' || true)

# --- 4. Base64 credentials other than the public sample ----------------------
# TTLock credentials base64-decode to a comma-separated list of small integers.
while IFS= read -r hit; do
  token=$(echo "${hit}" | grep -oE '[A-Za-z0-9+/]{16,}={0,2}' | head -1)
  decoded=$(echo "${token}" | base64 -d 2>/dev/null | LC_ALL=C tr -d '\0' || true)
  if echo "${decoded}" | grep -qE '^[0-9]+(,[0-9]+)+$'; then
    if [[ ${token} != "NjgsNjYsNjUsNzcsNjUsNzAsNjUsNjgsNjQsNjYsMTA=" ]]; then
      report "possible TTLock credential: ${hit}"
    fi
  fi
done < <(git grep -InE '[A-Za-z0-9+/]{16,}={0,2}' -- '*.rs' '*.py' '*.json' '*.md' "${EXCLUDE_PATHS[@]}" || true)

if [[ ${fail} -ne 0 ]]; then
  echo >&2
  echo "Secret scan failed. If a finding is a deliberate test vector, add it to" >&2
  echo "the allowlist in $0 with a comment explaining why it is safe." >&2
  exit 1
fi

echo "Secret scan clean."
