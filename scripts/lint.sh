#!/usr/bin/env bash
# Every static check in this repository, in one command.
#
# CI calls this, and it is meant to double as a pre-commit hook — see the
# "Contributing" section of README.md for the one-line install. Keeping both on
# the same script is the point: a hook that checks less than CI teaches you to
# distrust the hook, and one that checks more blocks commits CI would accept.
#
# `nix flake check` is deliberately NOT here. It builds every package and runs
# the NixOS VM test, which takes minutes — fine for CI as its own job, far too
# slow to sit in front of every commit.
#
# Usage:
#   scripts/lint.sh          check everything, report every failure
#   scripts/lint.sh --fix    apply what the formatters can fix, then check
set -Eeuo pipefail

cd "$(dirname "$0")/.."

# Every tool this script runs, and the reason the list is exhaustive rather
# than a spot check: a partially-populated PATH is worse than an empty one.
# Checking only for, say, `ruff` finds a globally installed one, skips the
# re-exec, and then runs whatever `cargo` happens to be first on PATH — which
# on a developer machine is usually a *different* Rust than the flake pins, so
# the script reports lints CI will never see and misses lints it will.
TOOLS=(cargo ruff ty statix deadnix nixfmt)

# The tools live in the Nix dev shell. A pre-commit hook runs in whatever
# environment git was invoked from, which normally has none of them, so
# re-enter the shell and re-exec once. The guard variable stops that recursing
# if the dev shell itself is missing something.
missing=()
for tool in "${TOOLS[@]}"; do
  command -v "${tool}" >/dev/null 2>&1 || missing+=("${tool}")
done

if [[ ${#missing[@]} -gt 0 ]]; then
  if [[ -n ${TTLOCK_LINT_RESHELLED:-} ]]; then
    echo "still missing inside the dev shell: ${missing[*]}" >&2
    echo "the flake's devShell needs to provide these." >&2
    exit 1
  fi
  if ! command -v nix >/dev/null 2>&1; then
    echo "missing: ${missing[*]}" >&2
    echo "and nix is not on PATH; run this inside 'nix develop'." >&2
    exit 1
  fi
  export TTLOCK_LINT_RESHELLED=1
  exec nix develop --command "$0" "$@"
fi

fix=0
case ${1:-} in
  --fix) fix=1 ;;
  "") ;;
  *)
    echo "usage: $0 [--fix]" >&2
    exit 2
    ;;
esac

failures=()

# Run one check, remember whether it failed, and keep going. Reporting every
# failure at once beats surfacing them one commit at a time.
run() {
  local name=$1
  shift
  printf '\n\033[1m==> %s\033[0m\n' "${name}"
  if "$@"; then
    return 0
  fi
  failures+=("${name}")
}

# The files to lint.
#
# Inside a checkout, git decides: it knows what is tracked and what is ignored.
# The existence filter on top is not paranoia — a file deleted without staging
# the deletion is still listed by `git ls-files`, and handing a missing path to
# nixfmt is a crash rather than a lint failure.
#
# Outside a checkout (a source tarball, an export with no .git) fall back to
# walking the tree. Linting is about files on disk, so it still has a sensible
# answer there — unlike `check-secrets.sh`, which asks what a commit would
# expose and refuses to guess.
if git rev-parse --git-dir >/dev/null 2>&1; then
  use_git=1
else
  use_git=0
  echo "note: not a git checkout, so linting every file on disk" >&2
fi

collect() {
  local pattern=$1 file
  if [[ ${use_git} -eq 1 ]]; then
    while IFS= read -r -d '' file; do
      [[ -f ${file} ]] && printf '%s\n' "${file}"
    done < <(git ls-files -z -- "${pattern}")
  else
    # Best-effort mirror of .gitignore. It will not match git exactly, which
    # is the price of not having git; `tmp/` is here because .gitignore
    # declares it this repository's scratch space and the throwaway scripts
    # that live there are not held to the same formatting.
    find . \
      \( -name .git -o -name target -o -name result -o -name .direnv \
      -o -name .venv -o -name venv -o -name __pycache__ -o -name tmp \) \
      -prune -o -type f -name "${pattern}" -print
  fi
}

mapfile -t nix_files < <(collect '*.nix')
mapfile -t python_files < <(collect '*.py')

# A formatter given no files exits 0. Without this, a broken file list turns
# every file-driven check below into a silent pass and the whole run goes green
# having checked nothing — which is exactly what happened when `.git` went
# missing during development.
if [[ ${#nix_files[@]} -eq 0 || ${#python_files[@]} -eq 0 ]]; then
  echo "found ${#nix_files[@]} .nix and ${#python_files[@]} .py files." >&2
  echo "Expected both to be non-empty; refusing to report a pass." >&2
  exit 1
fi

# --- Rust -------------------------------------------------------------------

if [[ ${fix} -eq 1 ]]; then
  run "cargo fmt" cargo fmt --all
else
  run "cargo fmt" cargo fmt --all --check
fi

# `--warn clippy::pedantic` before `-D warnings`, not after: rustc applies lint
# flags left to right, so the reverse order would demote every pedantic lint
# back to a warning and the run would pass with warnings printed.
#
# The workspace manifest already sets pedantic and nursery to warn; naming
# pedantic here too means this script keeps its bite if that ever changes.
run "cargo clippy (pedantic)" \
  cargo clippy --all-targets --all-features --workspace -- \
  --warn clippy::pedantic -D warnings

# --- Python -----------------------------------------------------------------

# `--config` is not redundant with the root pyproject, and both matter. With no
# configuration in the tree at all, ruff's discovery walks up past the
# repository and lands on the user's own `~/.config/ruff/ruff.toml`, so results
# depend on who is running it — a real bug here, not a hypothetical. Naming the
# file then pins *which* config wins regardless of the directory ruff is invoked
# from, and stops a future `[tool.ruff]` in `crates/ttlock-py/pyproject.toml`
# from quietly governing the files beneath it while the root governs the rest.
if [[ ${#python_files[@]} -gt 0 ]]; then
  run "ruff check" ruff check --config pyproject.toml -- "${python_files[@]}"
  if [[ ${fix} -eq 1 ]]; then
    run "ruff format" ruff format --config pyproject.toml -- "${python_files[@]}"
  else
    run "ruff format" ruff format --check --config pyproject.toml -- "${python_files[@]}"
  fi
fi

# The Home Assistant imports resolve only inside a Home Assistant install, so
# the component is type-checked with those unresolved rather than not at all.
#
# No explicit config path: ty's `--config-file` takes a bare `ty.toml`, whose
# schema has no `[tool.ty]` wrapper, so it rejects a pyproject outright. Its
# discovery does read `[tool.ty]` from the root pyproject, and that is what
# closes the hole this is about — discovery stops there instead of reaching the
# user's home directory.
run "ty" ty check --ignore unresolved-import custom_components/ttlock_ble

# --- Nix --------------------------------------------------------------------

run "statix" statix check .
run "deadnix" deadnix --fail .
if [[ ${#nix_files[@]} -gt 0 ]]; then
  if [[ ${fix} -eq 1 ]]; then
    run "nixfmt" nixfmt -- "${nix_files[@]}"
  else
    run "nixfmt" nixfmt --check -- "${nix_files[@]}"
  fi
fi

# --- Repository invariants --------------------------------------------------

run "versions agree" ./scripts/check-versions.sh
# The backstop for .gitignore: catches a credential pasted into source, or a
# secret-bearing file force-added past the ignore rules. Worth having in the
# pre-commit hook specifically, because that is the last moment it can help.
run "no secrets committed" ./scripts/check-secrets.sh

# --- Summary ----------------------------------------------------------------

echo
if [[ ${#failures[@]} -eq 0 ]]; then
  echo "all checks passed"
  exit 0
fi

echo "FAILED: ${#failures[@]} check(s)" >&2
for name in "${failures[@]}"; do
  echo "  - ${name}" >&2
done
if [[ ${fix} -eq 0 ]]; then
  echo >&2
  echo "Some of these are auto-fixable: scripts/lint.sh --fix" >&2
fi
exit 1
