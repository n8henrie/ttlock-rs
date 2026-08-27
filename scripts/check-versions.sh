#!/usr/bin/env bash
# Assert that every place carrying a version agrees with the Cargo workspace.
#
# The workspace version is the single source of truth. Most consumers derive it
# automatically (crates via `version.workspace`, the wheel via maturin, the Nix
# packages via `lib.importTOML`), but three cannot and must be bumped by hand:
# the `ttlock-core` dependency version, and the Home Assistant manifest's own
# version and `ttlock==` requirement. This catches the mismatch at CI time
# rather than at publish time.
set -Eeuo pipefail

cd "$(dirname "$0")/.."

fail=0
note() {
  printf '  %-46s %s\n' "$1" "$2"
}
check() {
  local what=$1 got=$2
  if [[ ${got} == "${expected}" ]]; then
    note "${what}" "${got}"
  else
    note "${what}" "${got}  <-- expected ${expected}"
    fail=1
  fi
}

expected=$(sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml |
  sed -n 's/^version = "\(.*\)"/\1/p' | head -1)

if [[ -z ${expected} ]]; then
  echo "could not read workspace.package.version from Cargo.toml" >&2
  exit 1
fi

echo "workspace version: ${expected}"

check "Cargo.toml ttlock-core dependency" \
  "$(sed -n 's/^ttlock-core = .*version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)"

check "custom_components/ttlock_ble/manifest.json version" \
  "$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' custom_components/ttlock_ble/manifest.json | head -1)"

check "custom_components/ttlock_ble/manifest.json ttlock requirement" \
  "$(sed -n 's/.*"ttlock==\([^"]*\)".*/\1/p' custom_components/ttlock_ble/manifest.json | head -1)"

if [[ ${fail} -ne 0 ]]; then
  echo
  echo "Version mismatch. Bump every value above to ${expected}." >&2
  exit 1
fi

echo "all versions agree"
