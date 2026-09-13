#!/usr/bin/env bash
# Obtain only the official pipeline and its pinned estimator submodule.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
GUIDELINES_SHA=a43a59356b6e87490091751bc48c523f924d5f9e
ESTIMATOR_SHA=8f1ff7e20a4d3391e3badff1d76825314db225bc
GUIDELINES_URL=https://github.com/gong-cr/FHE-Security-Guidelines.git
ESTIMATOR_URL=https://github.com/malb/lattice-estimator.git
PIPELINE="$ROOT/external/FHE-Security-Guidelines"

die() { printf '%s\n' "$*" >&2; exit 1; }
clean_tracked() {
    git -C "$1" diff --quiet && git -C "$1" diff --cached --quiet ||
        die "Tracked dependency changes found in $1; refusing to overwrite them."
}

mkdir -p "$ROOT/external"
if [[ ! -e "$PIPELINE" ]]; then
    git clone --no-recurse-submodules "$GUIDELINES_URL" "$PIPELINE"
fi
[[ -d "$PIPELINE/.git" ]] || die "Expected a standalone Guidelines clone at $PIPELINE"
[[ "$(git -C "$PIPELINE" remote get-url origin)" == "$GUIDELINES_URL" ]] ||
    die "Unexpected Guidelines origin URL"
clean_tracked "$PIPELINE"
if ! git -C "$PIPELINE" cat-file -e "$GUIDELINES_SHA^{commit}" 2>/dev/null; then
    git -C "$PIPELINE" fetch origin "$GUIDELINES_SHA"
fi
git -C "$PIPELINE" checkout --detach "$GUIDELINES_SHA"
[[ "$(git -C "$PIPELINE" rev-parse HEAD)" == "$GUIDELINES_SHA" ]] || die "Wrong Guidelines commit"
[[ "$(git -C "$PIPELINE" ls-tree HEAD lattice-estimator)" == "160000 commit $ESTIMATOR_SHA"$'\t'"lattice-estimator" ]] ||
    die "The Guidelines gitlink does not pin the expected estimator"
[[ "$(git -C "$PIPELINE" config -f .gitmodules submodule.lattice-estimator.path)" == lattice-estimator ]] ||
    die "Unexpected estimator submodule path"
[[ "$(git -C "$PIPELINE" config -f .gitmodules submodule.lattice-estimator.url)" == "$ESTIMATOR_URL" ]] ||
    die "Unexpected estimator submodule URL"
if [[ -e "$PIPELINE/lattice-estimator/.git" ]]; then
    clean_tracked "$PIPELINE/lattice-estimator"
fi
# Do not recursively obtain the unrelated Concrete/SEAL example submodules.
git -C "$PIPELINE" submodule sync -- lattice-estimator
git -C "$PIPELINE" submodule update --init --checkout -- lattice-estimator
[[ "$(git -C "$PIPELINE/lattice-estimator" rev-parse HEAD)" == "$ESTIMATOR_SHA" ]] ||
    die "Wrong effective lattice-estimator commit"
clean_tracked "$PIPELINE"
clean_tracked "$PIPELINE/lattice-estimator"
printf 'FHE Guidelines: %s\nlattice-estimator: %s\n' "$GUIDELINES_SHA" "$ESTIMATOR_SHA"
