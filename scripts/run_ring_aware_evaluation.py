#!/usr/bin/env python3
"""Supplementary sensitivity check using the pinned authors' ring-aware code under Sage."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

from generate_parameters import CONFIG, ROOT, generate, load_config, require

UPSTREAM = "a92f335665eef69927d2d8f49832bd595a6dac32"
UPSTREAM_URL = "https://github.com/TabOg/mlwe-hybrids"
SUBMODULES = {
    "DualHybrid": ("e2104ca50a293ed09b8fcec703cd2b143d21bee8", "https://github.com/TabOg/CodedDualAttack"),
    "PrimalHybrid/lattice_estimator": ("6019056011d10d7e9c30a0d5da2d2f729fbc2eec", "https://github.com/malb/lattice-estimator"),
}
VARIANTS = {
    "A": {"babai": True, "mitm": False},
    "B": {"babai": True, "mitm": True, "mitm_heuristic": "estimator"},
    "C": {"babai": True, "mitm": True, "mitm_heuristic": "square root"},
}
ORDINARY = {
    "bkw": "BKW", "usvp": "uSVP", "bdd": "BDD",
    "bdd_hybrid": "projected-CVP primal hybrid",
    "bdd_mitm_hybrid": "Babai MitM primal hybrid", "dual": "dual", "dual_hybrid": "dual hybrid",
}
# Regression checks only: all estimates and minima are recomputed from upstream.
AUDITED_TYPICAL = {
    1024: (128.322113887012, 172.283463324799),
    2048: (249.880310318088, 386.439683525210),
    4096: (507.919229585889, 832.207103030341),
}
REGRESSION_TOLERANCE_BITS = 1e-6


def sha_lf(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def git(path, *args):
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(path), *args], text=True).strip()


def verify_dependencies(path):
    require(git(path, "rev-parse", "HEAD") == UPSTREAM, "Wrong upstream commit; run bootstrap")
    for relative, (sha, url) in {"": (UPSTREAM, UPSTREAM_URL), **SUBMODULES}.items():
        repo = path / relative
        require(git(repo, "rev-parse", "HEAD") == sha, f"Wrong dependency commit: {relative}")
        require(git(repo, "remote", "get-url", "origin").removesuffix(".git") == url,
                f"Unexpected dependency origin: {relative}")
        require(not git(repo, "status", "--porcelain", "--untracked-files=all"),
                f"Dependency is not clean: {relative}; refusing to run")
        if relative:
            require(git(path, "ls-tree", "HEAD", relative) == f"160000 commit {sha}\t{relative}",
                    f"Wrong submodule gitlink: {relative}")
    recursive = git(path, "submodule", "status", "--recursive").splitlines()
    require(len(recursive) == len(SUBMODULES) and
            {tuple(line.strip().split()[:2]) for line in recursive} ==
            {(sha, relative) for relative, (sha, _) in SUBMODULES.items()},
            "Unexpected recursive submodule state")


def fingerprint(path):
    """Keep byte hashes in memory; publish only a compact, path-independent digest."""
    hashes = {}
    for relative in ("", *SUBMODULES):
        repo = path / relative
        for name in git(repo, "ls-files", "-z").split("\0"):
            source = repo / name
            if name and source.is_file():
                hashes[source.relative_to(path).as_posix()] = hashlib.sha256(source.read_bytes()).hexdigest()
    return hashes


def upstream(path):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(path / "PrimalHybrid"))
    from lattice_estimator.estimator import LWE, ND, RC, conf
    from lattice_estimator.estimator.simulator import GSA
    from lwe_rot_primal import rot_primal_hybrid
    require(conf.red_shape_model is GSA and conf.red_cost_model is RC.MATZOV,
            "Unexpected upstream cost/shape defaults")
    require(conf.max_beta == 1754, "Unexpected upstream search cutoff")
    return LWE, ND, RC, rot_primal_hybrid


def proxy_points(config):
    from sage.all import RealField, QQ, ZZ, floor, ceil
    rf = RealField(200)
    points = []
    for d in config["dimensions"]:
        mu = QQ(2*d)/3
        sd = (rf(2*d)/9).sqrt()
        weights = (int(floor(rf(mu)-2*sd)), int(mu.round()), int(ceil(rf(mu)+2*sd)))
        q = config["selected_q"][str(d)]
        require(ZZ(q).is_prime() and q % (2*d) == 1, "Expected an exact selected ring prime")
        for position, h in zip(("low", "typical", "high"), weights):
            points.append({"d": d, "q": q, "q_is_prime": True, "q_mod_2d": q % (2*d),
                           "position": position, "h": h, "p": h//2, "m": h-h//2,
                           "mu_H": str(mu), "sigma_H": str(sd)})
    return points


def encode_cost(cost):
    from sage.all import RealField
    bits = RealField(100)(cost["rop"]).log2()
    finite = math.isfinite(float(bits))
    return {"status": "finite" if finite else "nonfinite",
            "costs": {str(k): str(v) for k, v in cost.items()}, "costs_repr": repr(cost),
            "log2_rop": str(bits), "log2_rop_float": float(bits) if finite else None}


def worker(task):
    path, point, s_base, variant = task
    from sage.all import RealField, RR, oo
    LWE, ND, RC, rotated = upstream(Path(path))
    rf = RealField(200)
    sigma = rf(s_base)/(2*rf.pi()).sqrt()
    params = LWE.Parameters(n=point["d"], q=point["q"],
                            Xs=ND.SparseTernary(p=point["p"], m=point["m"], n=point["d"]),
                            Xe=ND.DiscreteGaussian(stddev=sigma), m=oo)
    require(params.Xs.hamming_weight == point["h"] and params.Xe.stddev == RR(sigma),
            "Unexpected estimator input conversion")
    if variant == "ordinary":
        costs = LWE.estimate(params, red_cost_model=RC.MATZOV, jobs=1, quiet=True,
                             deny_list=["arora-gb"], catch_exceptions=False)
        require(set(costs) == set(ORDINARY), "Unexpected ordinary attack family")
        return {name: encode_cost(costs[name]) for name in ORDINARY}
    cost = rotated(params, poly_degree=point["d"], red_cost_model=RC.MATZOV, **VARIANTS[variant])
    result = encode_cost(cost)
    result["uses_positive_rotation_dimension"] = bool(cost.get("zeta", 0) > 0)
    return result


def minimum(attacks, genuine_rotation=False):
    eligible = [(name, cost) for name, cost in attacks.items() if cost["status"] == "finite"
                and (not genuine_rotation or cost.get("uses_positive_rotation_dimension"))]
    require(bool(eligible), "No finite eligible attack")
    name, cost = min(eligible, key=lambda item: item[1]["log2_rop_float"])
    return {"attack": name, "log2_rop": cost["log2_rop"], "log2_rop_float": cost["log2_rop_float"]}


def summarize(row):
    ordinary = minimum(row["ordinary_attacks"])
    rotated = minimum(row["rotated_primal_attacks"], genuine_rotation=True)
    summary = {"minimum_ordinary_family": ordinary, "minimum_genuine_rotated_primal": rotated,
               "ordinary_family_is_cheaper": ordinary["log2_rop_float"] < rotated["log2_rop_float"],
               "nonfinite_ordinary_attacks": [name for name, cost in row["ordinary_attacks"].items()
                                             if cost["status"] == "nonfinite"]}
    point = row["input"]
    checks = {"all_three_rotated_finite_and_positive_zeta": all(
        cost["status"] == "finite" and cost["uses_positive_rotation_dimension"]
        for cost in row["rotated_primal_attacks"].values()),
        "ordinary_family_is_cheaper": summary["ordinary_family_is_cheaper"]}
    if point["position"] == "typical":
        expected = AUDITED_TYPICAL[point["d"]]
        summary["audited_typical_regression"] = {
            "expected_ordinary_minimum": expected[0], "expected_rotated_minimum": expected[1],
            "absolute_tolerance_bits": REGRESSION_TOLERANCE_BITS}
        checks["matches_audited_typical_minima"] = all(
            abs(actual["log2_rop_float"]-reference) <= REGRESSION_TOLERANCE_BITS
            for actual, reference in zip((ordinary, rotated), expected))
    if point["d"] == 1024:
        checks["both_minima_at_least_128"] = all(x["log2_rop_float"] >= 128 for x in (ordinary, rotated))
    if point["d"] == 4096:
        checks["both_minima_above_256"] = all(x["log2_rop_float"] > 256 for x in (ordinary, rotated))
    summary["regression_checks"] = checks
    row["derived_summary"] = summary
    require(all(checks.values()), f"Audited regression disagrees at d={point['d']}, h={point['h']}; stopping")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/ring_aware_2026_279.json")
    parser.add_argument("--jobs", type=int, default=3)
    args = parser.parse_args()
    require(args.jobs > 0, "--jobs must be positive")
    require(args.output.resolve() not in {(ROOT / name).resolve() for name in
            ("results/parameter_selection.json", "results/fhe_evaluation.json", "configs/paper_parameters.json")},
            "Supplementary output must not replace a main artifact")
    try:
        from sage.all import RealField
        from sage.env import SAGE_VERSION
    except ImportError:
        raise SystemExit("SageMath is required. Run: sage -python scripts/run_ring_aware_evaluation.py") from None
    sys.dont_write_bytecode = True
    config = load_config(CONFIG)
    generate(config)
    require(config["dimensions"] == list(AUDITED_TYPICAL) and config["s_base"] == 9,
            "The audited experiment requires the three selected dimensions and base width 9")
    path = ROOT / "external/mlwe-hybrids"
    verify_dependencies(path)
    before = fingerprint(path)
    _, ND, RC, _ = upstream(path)
    rf = RealField(200)
    sigma = rf(config["s_base"])/(2*rf.pi()).sqrt()
    points = proxy_points(config)
    rows = [{"input": p, "ordinary_attacks": {}, "rotated_primal_attacks": {}} for p in points]
    output = {
        "schema_version": 1, "record_type": "rerun_by_public_artifact",
        "experiment": "Supplementary sensitivity check for ePrint 2026/279",
        "execution": {"sage_version": SAGE_VERSION, "python_version": platform.python_version()},
        "dependencies": {"upstream_repository": UPSTREAM_URL, "upstream_commit": UPSTREAM,
                         "submodules": {p: {"commit": sha, "repository": url}
                                        for p, (sha, url) in SUBMODULES.items()}},
        "config_sha256_lf": sha_lf(CONFIG), "runner_sha256_lf": sha_lf(Path(__file__)),
        "methodology": {
            "scope": "Fixed-composition sensitivity proxy, not an exact iid-secret security model, exhaustive attack survey, or end-to-end OE-HRA bit security.",
            "actual_secret": "iid uniform ternary; H ~ Binomial(d, 2/3)",
            "proxy_secret": "ND.SparseTernary(p=floor(h/2), m=h-p, n=d); both sign counts are fixed",
            "weight_selection": {"mu_H": "2*d/3", "sigma_H": "sqrt(2*d/9)",
                                 "low": "floor(mu_H - 2*sigma_H)", "typical": "nearest integer to mu_H",
                                 "high": "ceil(mu_H + 2*sigma_H)"},
            "error_distribution": "ND.DiscreteGaussian(stddev=sigma)",
            "sigma_expression": "9/sqrt(2*pi)", "sigma_input": str(sigma), "sigma_input_precision_bits": 200,
            "sigma_stored": str(rf(ND.DiscreteGaussian(stddev=sigma).stddev)), "sigma_stored_precision_bits": 53,
            "cost_model": "RC.MATZOV", "setting": "classical", "nearest_neighbor_model": RC.MATZOV.nn,
            "shape_model": "GSA (unmodified upstream default)", "samples": "m=oo", "poly_degree": "d (RLWE rank 1)",
            "success_settings": "Unmodified attack-specific upstream defaults",
            "ordinary_family": {"routine": "LWE.estimate", "attacks": ORDINARY,
                                "options": {"deny_list": ["arora-gb"], "red_cost_model": "RC.MATZOV",
                                            "jobs": 1, "quiet": True, "catch_exceptions": False}},
            "rotated_primal": {"routine": "rot_primal_hybrid", "variants": VARIANTS,
                               "shared_options": {"poly_degree": "d", "red_cost_model": "RC.MATZOV"},
                               "eligibility": "Positive zeta required; zeta=0 is an ordinary fallback, never a genuine rotated minimum"},
            "cost_encoding": "Complete str(value) dictionaries and repr(costs); log2(rop) evaluated in RealField(100). Cost d is lattice dimension, not ring degree; absent fields were not returned.",
            "minima": "Minima over finite returns within each group. Nonfinite returns are retained with null numeric log2_rop and are not infinite-security guarantees.",
            "specialised_DualHybrid": "Verified for provenance only, never executed or adapted: the Kyber-specific artifact lacks the required ternary-secret plus independent Gaussian-error interface."},
        "high_dimensional_limitation": {
            "dimension": 4096, "inherited_max_beta": 1754, "local_search_can_return_beta": 1755,
            "svp_dimension_search": "For lattice dimensions >4096, inherited searches start at d_lattice-1754; projected-CVP results can meet eta=1755.",
            "interpretation": "Search cutoffs are unchanged. Many decimal places preserve returned computations, not physical bit-security precision. The conclusion is only that returned finite costs remain comfortably above 256 bits in this supplementary sensitivity check."},
        "proxy_evaluation": rows,
    }
    failure = None
    # A fresh process per call avoids sharing upstream optimisation caches between attacks.
    pool = ProcessPoolExecutor(max_workers=args.jobs, max_tasks_per_child=1)
    futures = {pool.submit(worker, (str(path), p, config["s_base"], variant)): (i, variant)
               for i, p in enumerate(points) for variant in ("ordinary", *VARIANTS)}
    try:
        for future in as_completed(futures):
            i, variant = futures[future]
            row = rows[i]
            answer = future.result()
            if variant == "ordinary":
                row["ordinary_attacks"] = answer
            else:
                row["rotated_primal_attacks"][variant] = answer
            print(f"d={points[i]['d']} h={points[i]['h']} {variant} completed", flush=True)
            if row["ordinary_attacks"] and len(row["rotated_primal_attacks"]) == 3:
                row["rotated_primal_attacks"] = {v: row["rotated_primal_attacks"][v] for v in VARIANTS}
                summarize(row)
    except Exception as exc:
        failure = type(exc).__name__
        print(f"Evaluation stopped: {exc}", file=sys.stderr, flush=True)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    try:
        verify_dependencies(path)
        unchanged = before == fingerprint(path)
        require(unchanged, "Upstream source bytes changed during evaluation")
    except Exception as exc:
        unchanged = False
        failure = failure or type(exc).__name__
        print(f"Source verification failed: {exc}", file=sys.stderr)
    output["source_verification"] = {"tracked_file_count": len(before), "all_tracked_bytes_unchanged": unchanged,
                                     "tracked_files_sha256": hashlib.sha256(
                                         json.dumps(before, sort_keys=True).encode()).hexdigest()}
    completed = sum("derived_summary" in row for row in rows)
    passed = failure is None and completed == 9
    output["derived_summary"] = {"completed_proxy_points": completed, "requested_proxy_points": 9,
                                 "all_requested_checks_passed": passed}
    if passed:
        output["derived_summary"]["any_d1024_minimum_below_128"] = any(
            row["derived_summary"][key]["log2_rop_float"] < 128 for row in rows if row["input"]["d"] == 1024
            for key in ("minimum_ordinary_family", "minimum_genuine_rotated_primal"))
    else:
        output["failure_type"] = failure
    destination = args.output if passed else args.output.with_suffix(".failed.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(output, indent=2, ensure_ascii=True, allow_nan=False)+"\n",
                           encoding="utf-8", newline="\n")
    require(passed, "Ring-aware reproduction failed; diagnostic .failed.json retained; successful result unchanged")
    print(f"All {completed} proxy points and audited regression checks passed.", flush=True)


if __name__ == "__main__":
    main()
