# oePRE Parameter Evaluation

This repository contains the reproducibility artifact for the concrete parameter
selection and underlying lattice-security evaluation reported in the oePRE manuscript.

It reproduces the numerical results in Section 3.4 and Appendix C, including:

- the NEL/statistical parameter checks;
- the single-hop correctness and modulus checks;
- the three concrete parameter sets and analytical resource sizes;
- the exact-input evaluation under the 2025 *Security Guidelines for Implementing
  Homomorphic Encryption*.

This artifact evaluates the underlying lattice parameters. It does not constitute
a machine-checked verification of the OE-HRA security proof.

## Reproduced paper results

All rows use a 1024-bit payload, `p=2`, gadget base 4, and lattice Gaussian widths
`(s_base,s_ct,s_pad)=(9,18,18)`. Each query cap is `2^18`.

| d | q | w | Ciphertext (KiB) | Rekey (KiB) | Expansion | Main products | Minimum log2(rop) | Classical category |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1024 | 114708481 | 14 | 6.75 | 94.5 | 54 | 30 | 128.127812 | 128 |
| 2048 | 350187521 | 15 | 14.5 | 217.5 | 116 | 32 | 249.907166 | 192 |
| 4096 | 999923713 | 15 | 30 | 450 | 240 | 32 | 507.943400 | 256 |

Sizes are raw coefficient encodings, with `1 KiB = 8192 bits`. Ciphertext and rekey
lengths are `2*d*ceil(log2(q))` and `2*w*d*ceil(log2(q))` bits. Expansion divides
ciphertext bits by payload bits. The `2*w+2` main ReEnc ring products exclude
decomposition, additions, PRF evaluation and sampling; they are not measured timings.

## Requirements

- Linux or WSL, Bash and Git for dependency setup.
- Python 3.11 or later, standard library only, for parameter generation.
- Tested FHE environment: SageMath **10.3** with Python **3.11.11** under WSL Ubuntu.
  Activate that Sage environment before running the commands below.

The bundled results were recomputed with this Sage/Python combination and include
all 20 attack outputs (eight validation and twelve oePRE), including the raw cost
dictionaries. Parameter generation was also
checked with Python 3.12.3.

## Pinned external dependencies

- [FHE Security Guidelines](https://github.com/gong-cr/FHE-Security-Guidelines/tree/a43a59356b6e87490091751bc48c523f924d5f9e):
  `a43a59356b6e87490091751bc48c523f924d5f9e`.
- [lattice-estimator](https://github.com/malb/lattice-estimator/tree/8f1ff7e20a4d3391e3badff1d76825314db225bc):
  `8f1ff7e20a4d3391e3badff1d76825314db225bc`.

The Guidelines revision already pins that estimator as its `lattice-estimator`
Git submodule. Bootstrap keeps this official layout at
`external/FHE-Security-Guidelines/lattice-estimator`, verifies the parent gitlink
and both checked-out commits, and initializes only this submodule. It does not
download the unrelated example submodules, install Sage, or edit upstream sources.
It is safe to rerun and refuses to overwrite tracked dependency changes.
Use the same Linux/WSL environment for bootstrap and evaluation to avoid Git
checkout/line-ending differences. All of `external/` is ignored by Git.

## Quick start

From the repository root:

```sh
bash scripts/bootstrap_dependencies.sh
python3 scripts/generate_parameters.py
sage -python scripts/run_fhe_evaluation.py
```

The FHE runner uses four worker processes by default (`--jobs 1` runs serially).
It first reproduces the two Table 5.2 boundary points, then evaluates the three
oePRE inputs only if validation passes. To run just the validation:

```sh
sage -python scripts/run_fhe_evaluation.py --validation-only --output external/table52_validation.json
```

## Output

- `results/parameter_selection.json`: deterministic 100-digit Decimal results,
  exact rational statistical bounds, NEL widths/slacks, padding precision witness,
  complete correctness bounds, prime/gadget checks and raw resource quantities.
  Noninteger Decimal quantities are strings; powers of two in the configuration
  use exact integer exponents. The nonzero collision term is stored as an exact
  expression and a logarithm, and certified below the `2^-194` cap by
  integer arithmetic. The exact statistical sum with that cap is below `2^-130`.
- `results/fhe_evaluation.json`: separate `table_5_2_validation` and
  `oepre_evaluation` sections, exact inputs, versions/source hashes, all four attack
  cost dictionaries and their original textual representations, plus clearly
  identified derived minima, margins and categories. No timing or machine paths
  are included. Successful runs replace this file; failed numerical comparisons
  write a separate `.failed.json` and return a nonzero exit code.

## Methodology

The runner loads the definitions in the pinned `max_logQ_tables.py`, excluding
its full-table driver, and calls its four classical ternary routines unchanged:
`LWE.primal_usvp`, `LWE.dual_hybrid`,
`LWE.primal_hybrid(mitm=False,babai=False)`, and `LWE.primal_bdd`.
It retains classical MATZOV reduction costs, the pinned GSA shape defaults,
attack-specific success settings, and unlimited samples (`m=oo`).

Actual oePRE rows use `n=d`, the exact prime `q`, `ND.Uniform(-1,1)` secrets and
`ND.DiscreteGaussian(9/sqrt(2*pi))` errors. The input sigma is evaluated with
Sage's 128-bit real field; the estimator's stored sigma is recorded separately.
The largest supported category among 128, 192 and 256 is derived using the
pipeline's `log2(rop) >= category` test. The 1024 row has only a 0.127812 modeled
margin above Category 128.

**Table 5.2 validation uses different error inputs:** ternary `n=1024`,
`sigma=3.19`, and `q=2^26` / `2^27`. Its minima are 131.332683 / 126.193727,
confirming the published largest integer `log2(q)=26` at Category 128.
Those rows are not oePRE parameter sets.

## Scope

The categories assess underlying lattice parameters under the Guidelines'
heuristic attack and RLWE-to-LWE modeling conventions. They are not end-to-end
OE-HRA advantage bounds. The formal security theorem, reductions, distinct sample
interfaces and computational losses remain in the paper.

Correctness targets one fresh honest single-hop execution with failure at most
`2^-40`. Padding has a hard support bound; its statistical distance is charged in
the security budget. This artifact checks the analytical inverse-CDF precision
budget, but does not implement a sampler, certify concrete CDT thresholds, or
benchmark the cryptosystem.

## Provenance

This artifact accompanies the oePRE manuscript and directly implements the fixed
parameterization and conservative numerical formulas in Section 3.4 and Appendix C.
The FHE evaluation uses the pinned official pipeline definitions. The MIT license
applies to this artifact; external dependencies retain their upstream licenses.
