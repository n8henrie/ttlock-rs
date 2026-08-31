#!/usr/bin/env bash
# Build the `ttlock` Python wheel, with a portable glibc ABI on Linux.
#
# Why this exists instead of `PyO3/maturin-action`: that action reaches for a
# manylinux Docker container, and this project pins everything else through
# Nix. Asking maturin for `--compatibility manylinux_2_28` on a modern runner
# without changing how the extension is *linked* does not work — the option is
# a label and an audit, not an ABI transformer. The build fails with references
# the policy forbids:
#
#   pthread_setspecific@GLIBC_2.34, stat64@GLIBC_2.33, gettid@GLIBC_2.30, ...
#
# Those come from ordinary Rust std (threads, TLS, file metadata), not from an
# exotic C dependency, so no amount of dependency pruning removes them. The fix
# is to link against an older glibc ABI, which `--zig` does: maturin drives
# `zig cc` as the linker with a pinned target glibc.
#
# Division of responsibility, which is the whole design:
#   Nix   pins the versions of rust, maturin and zig.
#   Zig   fixes the target libc ABI.
#   Maturin packages and audits the wheel.
#   Nothing from /nix/store may end up in the artifact.
#
# Usage:
#   scripts/build-wheel.sh [--out DIR]
#
# The target is the host: this builds natively per architecture rather than
# cross-compiling, so CI needs an x86-64 runner and an ARM64 one. Zig is here
# for the glibc version, not for architecture emulation.
set -Eeuo pipefail

cd "$(dirname "$0")/.."

out=dist
if [[ ${1:-} == --out ]]; then
  out=${2:?--out needs a directory}
elif [[ -n ${1:-} ]]; then
  echo "usage: $0 [--out DIR]" >&2
  exit 2
fi

# The glibc floor the wheel promises. 2.28 is RHEL/CentOS 8, Debian 10 and
# Ubuntu 18.10 — old enough for the Raspberry Pi images this tends to land on.
MANYLINUX=2_28

for tool in cargo maturin; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "missing ${tool}; run inside 'nix develop'" >&2
    exit 1
  }
done

host_target=$(rustc -vV | sed -n 's/^host: //p')
if [[ -z ${host_target} ]]; then
  echo "could not determine the host target from rustc" >&2
  exit 1
fi

args=(
  build
  --release
  --locked
  --manifest-path crates/ttlock-py/Cargo.toml
  --target "${host_target}"
  --out "${out}"
)

case ${host_target} in
  *-linux-gnu)
    # R2 in the assessment: the zig path is easy to bypass silently. A linker
    # override in the environment, or a maturin built without its `zig`
    # feature, both produce a normal host-linked build that fails the audit
    # later — or worse, passes a weaker one. Refuse up front.
    if ! maturin build --help 2>&1 | grep -q -- '--zig'; then
      echo "this maturin was built without zig support, so it cannot target an" >&2
      echo "older glibc. Package maturin with its 'zig' feature." >&2
      exit 1
    fi
    command -v zig >/dev/null 2>&1 || {
      echo "zig is not on PATH; maturin's --zig needs it" >&2
      exit 1
    }
    for var in RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_ENCODED_RUSTFLAGS; do
      if [[ -n ${!var:-} ]]; then
        echo "${var} is set (${!var}); it can override the zig linker." >&2
        echo "Unset it before building a release wheel." >&2
        exit 1
      fi
    done
    # A target-specific linker in cargo config would win over --zig too.
    linker_var="CARGO_TARGET_$(echo "${host_target}" | tr 'a-z-' 'A-Z_')_LINKER"
    if [[ -n ${!linker_var:-} ]]; then
      echo "${linker_var} is set; it would bypass --zig." >&2
      exit 1
    fi

    args+=(--zig --compatibility "manylinux_${MANYLINUX}" --auditwheel check)
    ;;
  *-apple-darwin)
    # manylinux is a Linux policy; the macOS wheel is an ordinary native build.
    ;;
  *)
    echo "unsupported host target: ${host_target}" >&2
    exit 1
    ;;
esac

# R9: a target directory shared with ordinary `cargo build` can hand back
# host-linked artifacts from before the zig linker was in play, which produces
# confusing pass/fail flapping. Keep release wheels in their own tree.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/wheel-${host_target}}"

echo "building wheel for ${host_target}"
echo "  target dir: ${CARGO_TARGET_DIR}"
echo "  maturin:    $(maturin --version)"
command -v zig >/dev/null 2>&1 && echo "  zig:        $(zig version)"
echo

maturin "${args[@]}"

echo
echo "built:"
ls -1 "${out}"/*.whl
