#!/usr/bin/env bash
# Obtain the original ring-aware artifact and verify its two pinned submodules.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_URL=https://github.com/TabOg/mlwe-hybrids.git
UPSTREAM_SHA=a92f335665eef69927d2d8f49832bd595a6dac32
UPSTREAM="$ROOT/external/mlwe-hybrids"
PATHS=(DualHybrid PrimalHybrid/lattice_estimator)
SHAS=(e2104ca50a293ed09b8fcec703cd2b143d21bee8 6019056011d10d7e9c30a0d5da2d2f729fbc2eec)
URLS=(https://github.com/TabOg/CodedDualAttack https://github.com/malb/lattice-estimator.git)

die() { printf '%s\n' "$*" >&2; exit 1; }
clean_source() {
    [[ -z "$(git -C "$1" status --porcelain --untracked-files=all)" ]] ||
        die "Dependency changes found in $1; refusing to overwrite them."
}
check_origin() {
    local actual
    actual="$(git -C "$1" remote get-url origin)"
    [[ "${actual%.git}" == "${2%.git}" ]] || die "Unexpected dependency origin URL"
}

mkdir -p "$ROOT/external"
if [[ ! -e "$UPSTREAM" ]]; then
    git clone --no-checkout --no-recurse-submodules "$UPSTREAM_URL" "$UPSTREAM"
    if ! git -C "$UPSTREAM" cat-file -e "$UPSTREAM_SHA^{commit}" 2>/dev/null; then
        git -C "$UPSTREAM" fetch origin "$UPSTREAM_SHA"
    fi
    # Only a newly created clone is checked out. Existing revisions are never moved.
    git -C "$UPSTREAM" -c core.autocrlf=false checkout --detach "$UPSTREAM_SHA"
fi
[[ -d "$UPSTREAM/.git" ]] || die "Expected a standalone mlwe-hybrids clone"
check_origin "$UPSTREAM" "$UPSTREAM_URL"
[[ "$(git -C "$UPSTREAM" rev-parse HEAD)" == "$UPSTREAM_SHA" ]] ||
    die "Unexpected mlwe-hybrids revision; refusing to change an existing checkout."
clean_source "$UPSTREAM"

# Preflight every existing submodule before initializing anything.
for i in "${!PATHS[@]}"; do
    path="${PATHS[$i]}" sha="${SHAS[$i]}" url="${URLS[$i]}"
    [[ "$(git -C "$UPSTREAM" ls-tree HEAD "$path")" == "160000 commit $sha"$'\t'"$path" ]] ||
        die "Unexpected submodule gitlink: $path"
    [[ "$(git -C "$UPSTREAM" config -f .gitmodules "submodule.$path.path")" == "$path" ]] ||
        die "Unexpected submodule path: $path"
    [[ "$(git -C "$UPSTREAM" config -f .gitmodules "submodule.$path.url")" == "$url" ]] ||
        die "Unexpected submodule URL: $path"
    if [[ -e "$UPSTREAM/$path/.git" ]]; then
        [[ "$(git -C "$UPSTREAM/$path" rev-parse HEAD)" == "$sha" ]] ||
            die "Unexpected submodule revision: $path; refusing to change it."
        check_origin "$UPSTREAM/$path" "$url"
        clean_source "$UPSTREAM/$path"
    fi
done

# These are the only recursive submodules at this pin. DualHybrid is verified
# for provenance only; the evaluation never executes or adapts its Kyber code.
git -C "$UPSTREAM" submodule sync -- "${PATHS[@]}"
git -C "$UPSTREAM" -c core.autocrlf=false submodule update --init -- "${PATHS[@]}"
for i in "${!PATHS[@]}"; do
    path="${PATHS[$i]}"
    [[ "$(git -C "$UPSTREAM/$path" rev-parse HEAD)" == "${SHAS[$i]}" ]] ||
        die "Wrong effective submodule commit: $path"
    check_origin "$UPSTREAM/$path" "${URLS[$i]}"
    clean_source "$UPSTREAM/$path"
done
[[ "$(git -C "$UPSTREAM" submodule status --recursive | wc -l)" -eq 2 ]] ||
    die "Unexpected recursive submodules"
clean_source "$UPSTREAM"
printf 'mlwe-hybrids: %s\n' "$UPSTREAM_SHA"
git -C "$UPSTREAM" submodule status --recursive
