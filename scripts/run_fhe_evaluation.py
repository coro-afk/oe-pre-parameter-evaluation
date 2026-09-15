#!/usr/bin/env python3
"""Evaluate exact OE-PRE inputs with the pinned FHE Guidelines definitions under Sage."""

import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

from generate_parameters import CONFIG, ROOT, generate, load_config, require

GUIDELINES = "a43a59356b6e87490091751bc48c523f924d5f9e"
ESTIMATOR = "8f1ff7e20a4d3391e3badff1d76825314db225bc"
ROUTINES = ("LWE.primal_usvp", "LWE.dual_hybrid", "LWE.primal_hybrid", "LWE.primal_bdd")
SOURCE_FILES = ("conf.py", "lwe.py", "lwe_primal.py", "lwe_dual.py",
                "reduction.py", "simulator.py", "nd.py", "prob.py")


def sha_lf(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def git(path, *args):
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(path), *args], text=True).strip()


def verify_dependencies(path):
    require(git(path, "rev-parse", "HEAD") == GUIDELINES, "Wrong Guidelines commit; run bootstrap")
    estimator = path / "lattice-estimator"
    require(git(estimator, "rev-parse", "HEAD") == ESTIMATOR, "Wrong estimator commit; run bootstrap")
    require(git(path, "ls-tree", "HEAD", "lattice-estimator") ==
            f"160000 commit {ESTIMATOR}\tlattice-estimator", "Wrong estimator gitlink")
    for repo in (path, estimator):
        require(not git(repo, "status", "--porcelain", "--untracked-files=all"),
                "Dependency checkout is not clean; use an unmodified pinned checkout")
    return {"guidelines_commit": GUIDELINES, "estimator_commit": ESTIMATOR,
            "official_script_sha256_lf": sha_lf(path / "max_logQ_tables.py"),
            "estimator_source_sha256_lf": {name: sha_lf(estimator / "estimator" / name) for name in SOURCE_FILES}}


def official_definitions(path):
    """Execute official definitions only; exclude the full-table __main__ driver."""
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(path / "lattice-estimator"))
    source = (path / "max_logQ_tables.py").read_text(encoding="utf-8")
    marker = '\nif __name__ == "__main__":'
    require(source.count(marker) == 1, "Unexpected official pipeline structure")
    ns = {}
    exec(compile(source.split(marker)[0], str(path / "max_logQ_tables.py"), "exec"), ns)
    from estimator import conf
    require(conf.red_shape_model == "gsa", "Expected the pinned GSA default")
    require(ns["cost_model_classical"] == ns["RC"].MATZOV, "Expected classical MATZOV costs")
    return ns


def worker(task):
    path, case, index = task
    from sage.all import RealField, ZZ, oo
    ns = official_definitions(Path(path))
    rf = RealField(128)
    # Use 128-bit sigma for OE-PRE; the Python float 3.19 for Table 5.2.
    sigma = 3.19 if case["sigma_expression"] == "3.19" else rf(case["s_base"])/(2*rf.pi()).sqrt()
    params = ns["LWE"].Parameters(n=case["dimension"], q=ZZ(case["q"]),
                                 Xs=ns["MODE_TERNARY"], Xe=ns["ND"].DiscreteGaussian(sigma), m=oo)
    algorithms = ns["get_estimators_for_mode"](ns["MODE_TERNARY"], "classical", case["dimension"])
    expected = (ns["LWE"].primal_usvp, ns["LWE"].dual_hybrid,
                ns["LWE"].primal_hybrid, ns["LWE"].primal_bdd)
    require(len(algorithms) == len(expected), "Unexpected official attack count")
    for i, (algorithm, function) in enumerate(zip(algorithms, expected)):
        keywords = {"red_cost_model": ns["cost_model_classical"]}
        if i == 2:
            keywords.update(mitm=False, babai=False)
        require(algorithm.func == function and algorithm.keywords == keywords,
                "Unexpected official callable or attack options")
    output = {"routine": ROUTINES[index], "pipeline_index": index,
              "options": {"mitm": False, "babai": False} if index == 2 else {},
              "parameters_repr": repr(params), "log2_q": str(rf(params.q).log2()),
              "sigma_input": str(sigma), "sigma_stored": str(params.Xe.stddev)}
    try:
        costs = algorithms[index](params=params)
        # Preserve the pipeline's log(..., 2).n() convention, including symbolic costs.
        bits = ns["log"](costs["rop"], 2).n()
        finite = math.isfinite(float(bits))
        output.update(status="finite" if finite else "nonfinite",
                      costs={str(k): str(v) for k, v in costs.items()},
                      costs_repr=repr(costs), log2_rop=str(bits),
                      log2_rop_float=float(bits) if finite else None)
    except Exception as exc:
        # Keep errors local and avoid exporting tracebacks containing machine paths.
        print(f"{case['id']} {ROUTINES[index]} failed: {exc}", file=sys.stderr, flush=True)
        output.update(status="error", error_type=type(exc).__name__)
    return output


def evaluate(pool, path, cases):
    tasks = [(str(path), case, i) for case in cases for i in range(4)]
    results = list(pool.map(worker, tasks))
    rows = []
    for j, case in enumerate(cases):
        attacks = results[4*j:4*j+4]
        all_finite = all(a["status"] == "finite" for a in attacks)
        summary = {"all_four_finite": all_finite, "minimum_log2_rop": None, "classical_category": None}
        if all_finite:
            best = min(attacks, key=lambda a: a["log2_rop_float"])
            bits = best["log2_rop_float"]
            category = max((k for k in (128, 192, 256) if bits >= k), default=None)
            summary.update(minimum_log2_rop=bits, minimizing_routine=best["routine"],
                           classical_category=category,
                           margins={str(k): bits-k for k in (128, 192, 256)},
                           matches_paper_display=f"{bits:.6f}" == case["expected_minimum_log2_rop_display"],
                           matches_paper_category=category == case["expected_classical_category"])
        rows.append({"input": case, "secret_distribution": "ND.Uniform(-1, 1)",
                     "sample_convention": "m=oo", "attacks": attacks, "derived_summary": summary})
        print(f"{case['id']}: minimum={summary['minimum_log2_rop']} "
              f"category={summary['classical_category']} all_four_finite={all_finite}", flush=True)
    return rows


def matches(rows):
    return all(r["derived_summary"].get("all_four_finite")
               and r["derived_summary"].get("matches_paper_display")
               and r["derived_summary"].get("matches_paper_category") for r in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--guidelines-path", type=Path, default=ROOT / "external/FHE-Security-Guidelines")
    parser.add_argument("--output", type=Path, help="Default: results/fhe_evaluation.json")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--validation-only", action="store_true", help="Only Table 5.2; use a separate output file")
    args = parser.parse_args()
    require(args.jobs > 0, "--jobs must be positive")
    try:
        from sage.env import SAGE_VERSION
    except ImportError:
        raise SystemExit("SageMath is required. Run: sage -python scripts/run_fhe_evaluation.py") from None
    sys.dont_write_bytecode = True
    c = load_config(args.config)
    generate(c)  # Validate the exact paper parameters before launching any attacks.
    path = args.guidelines_path.resolve()
    pins = verify_dependencies(path)
    destination = args.output or ROOT / "results" / ("fhe_validation.json" if args.validation_only else "fhe_evaluation.json")
    if args.validation_only:
        require(destination.resolve() != (ROOT / "results/fhe_evaluation.json").resolve(),
                "Validation-only output must not replace the OE-PRE result")
    output = {"schema_version": 1, "record_type": "rerun_by_public_artifact",
              "execution": {"sage_version": SAGE_VERSION, "python_version": platform.python_version()},
              "dependencies": pins, "config_sha256_lf": sha_lf(args.config),
              "runner_sha256_lf": sha_lf(Path(__file__)),
              "methodology": {"cost_model": "RC.MATZOV", "setting": "classical",
                              "shape_model": "gsa (pinned defaults)", "samples": "m=oo",
                              "success_settings": "Unmodified attack-specific pinned defaults",
                              "raw_cost_encoding": "Unmodified str(value) and repr(costs); log2(rop) uses official log(..., 2).n().",
                              "derived_summary": "Minimum over all four finite attacks; largest of 128/192/256 with log2(rop)>=category; null if none."},
              "table_5_2_validation": {}, "oepre_evaluation": []}
    validation = [{"id": f"table52-q2pow{b}", "dimension": 1024, "q": 2**b,
                   "sigma_expression": "3.19", "expected_minimum_log2_rop_display": expected,
                   "expected_classical_category": category}
                  for b, expected, category in ((26, "131.332683", 128), (27, "126.193727", None))]
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        rows = evaluate(pool, path, validation)
        passed = matches(rows)
        output["table_5_2_validation"] = {"rows": rows, "published_integer_log2_q_boundary": 26,
                                          "reproduction_passed": passed}
        if passed and not args.validation_only:
            cases = [{"id": f"oePRE-d{d}", "dimension": d, "q": c["selected_q"][str(d)],
                      "s_base": c["s_base"], "sigma_expression": f"{c['s_base']}/sqrt(2*pi)",
                      "expected_minimum_log2_rop_display": c["expected_fhe_results"][str(d)]["minimum_log2_rop_display"],
                      "expected_classical_category": c["expected_fhe_results"][str(d)]["classical_category"]}
                     for d in c["dimensions"]]
            output["oepre_evaluation"] = evaluate(pool, path, cases)
            passed = matches(output["oepre_evaluation"])
    verify_dependencies(path)
    output["all_requested_checks_passed"] = passed
    if not passed:
        destination = destination.with_suffix(".failed.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(output, indent=2, ensure_ascii=True, allow_nan=False)+"\n", encoding="utf-8", newline="\n")
    require(passed, "FHE reproduction failed; retained diagnostic .failed.json and left the successful result unchanged")


if __name__ == "__main__":
    main()
