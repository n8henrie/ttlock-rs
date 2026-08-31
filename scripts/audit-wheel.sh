#!/usr/bin/env bash
# Prove a built wheel is as portable as its filename claims.
#
# maturin's `--auditwheel check` already refuses to *produce* a
# non-conforming Linux wheel, so this is a second opinion on the artifact
# rather than the primary gate. It exists because the failure mode being
# guarded against is a wheel that installs cleanly and then fails on a user's
# Raspberry Pi, which is discovered far too late.
#
# Checks, all against the extension actually inside the wheel:
#   1. no versioned glibc symbol newer than the policy floor
#   2. no unexpected DT_NEEDED shared library
#   3. no libpython dependency (an abi3 extension resolves those from the
#      interpreter that loads it)
#   4. no RPATH/RUNPATH or any other string pointing into /nix/store
#
# Usage: scripts/audit-wheel.sh dist/*.whl
set -Eeuo pipefail

cd "$(dirname "$0")/.."

# Must match scripts/build-wheel.sh.
MAX_GLIBC_MINOR=28

# Libraries a manylinux extension may rely on the host to provide.
ALLOWED_LIBS='^(libc|libm|libdl|libpthread|librt|libgcc_s|ld-linux.*)\.so'

wheels=("$@")
if [[ ${#wheels[@]} -eq 0 ]]; then
  echo "usage: $0 <wheel>..." >&2
  exit 2
fi

# Without `readelf` every ELF check below quietly finds nothing and the audit
# reports a clean wheel having inspected none of it — the same silent-pass
# shape as a linter handed an empty file list. Refuse instead.
for tool in unzip readelf; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "audit-wheel: ${tool} is not on PATH." >&2
    echo "Without it this check would pass without checking anything." >&2
    exit 1
  }
done

failures=0
note() {
  echo "AUDIT: $1" >&2
  failures=$((failures + 1))
}

workdir=$(mktemp -d)
trap 'rm -rf "${workdir}"' EXIT

for wheel in "${wheels[@]}"; do
  [[ -f ${wheel} ]] || {
    note "no such wheel: ${wheel}"
    continue
  }
  name=$(basename "${wheel}")
  echo "=== ${name} ==="

  # An abi3 wheel must say so in its filename, or it silently becomes
  # version-specific and the single-wheel-per-platform promise is broken.
  [[ ${name} == *-abi3-* ]] || note "${name}: not tagged abi3"

  case ${name} in
    *macosx*)
      # The manylinux glibc policy does not apply, but portability still does,
      # and this is not hypothetical: building the macOS wheel inside the Nix
      # dev shell produces an extension linked against
      # `/nix/store/...-libiconv/lib/libiconv.2.dylib` by absolute path. It
      # imports fine on the machine that built it and fails everywhere else.
      if ! command -v otool >/dev/null 2>&1; then
        echo "  macOS wheel, but no otool here — cannot audit; skipping" >&2
        continue
      fi
      unpacked="${workdir}/$(basename "${wheel}" .whl)"
      mkdir -p "${unpacked}"
      unzip -q -o "${wheel}" -d "${unpacked}"
      mapfile -t dylibs < <(find "${unpacked}" \( -name '*.so' -o -name '*.dylib' \) -type f)
      if [[ ${#dylibs[@]} -eq 0 ]]; then
        note "${name}: contains no loadable object"
        continue
      fi
      for object in "${dylibs[@]}"; do
        relative=${object#"${unpacked}/"}
        echo "  ${relative}"
        while read -r lib; do
          [[ -n ${lib} ]] || continue
          case ${lib} in
            /nix/store/*) note "${relative}: links ${lib}, which exists only on the build machine" ;;
            *libpython*) note "${relative}: links ${lib}; an abi3 extension must not" ;;
          esac
        done < <(otool -L "${object}" | tail -n +2 | awk '{print $1}')
      done
      continue
      ;;
    *manylinux*) ;;
    *)
      note "${name}: not a manylinux wheel"
      continue
      ;;
  esac

  unpacked="${workdir}/$(basename "${wheel}" .whl)"
  mkdir -p "${unpacked}"
  unzip -q -o "${wheel}" -d "${unpacked}"

  mapfile -t objects < <(find "${unpacked}" -name '*.so' -type f)
  if [[ ${#objects[@]} -eq 0 ]]; then
    note "${name}: contains no shared object"
    continue
  fi

  for object in "${objects[@]}"; do
    relative=${object#"${unpacked}/"}
    echo "  ${relative}"

    # 1. Versioned glibc symbols. `readelf -V` lists the versions the object
    #    *requires*, which is exactly the manylinux question.
    mapfile -t too_new < <(
      readelf -V "${object}" 2>/dev/null |
        grep -oE 'GLIBC_2\.[0-9]+' | sort -u |
        # `GLIBC_2.28` splits on "." into `GLIBC_2` and `28`, so the minor
        # version is $2. It was $3 here once, which made the whole check a
        # silent no-op that passed the very wheel this script exists to reject.
        awk -F. -v max="${MAX_GLIBC_MINOR}" '$2 + 0 > max + 0'
    )
    if [[ ${#too_new[@]} -gt 0 ]]; then
      note "${relative}: needs glibc newer than 2.${MAX_GLIBC_MINOR}: ${too_new[*]}"
    fi

    # 2/3. Shared library dependencies.
    while read -r lib; do
      [[ -n ${lib} ]] || continue
      if [[ ${lib} == libpython* ]]; then
        note "${relative}: links ${lib}; an abi3 extension must not"
      elif ! [[ ${lib} =~ ${ALLOWED_LIBS} ]]; then
        note "${relative}: unexpected shared library ${lib}"
      fi
    done < <(readelf -d "${object}" 2>/dev/null |
      sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')

    # 4. Nix store references. RPATH/RUNPATH would break the wheel off this
    #    machine; a store path anywhere else is merely wrong to ship.
    if readelf -d "${object}" 2>/dev/null |
      grep -E '\((RPATH|RUNPATH)\)' | grep -q '/nix/store'; then
      note "${relative}: RPATH/RUNPATH points into /nix/store"
    fi
    if grep -qa '/nix/store' "${object}"; then
      note "${relative}: contains a /nix/store path"
    fi
  done
done

echo
if [[ ${failures} -ne 0 ]]; then
  echo "${failures} problem(s); these wheels are not portable." >&2
  exit 1
fi
echo "wheel audit clean"
