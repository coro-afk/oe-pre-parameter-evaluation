# OE-PRE Parameter Evaluation

This repository contains the reproducibility artifact for the concrete parameter
selection and underlying lattice-security evaluation reported in the OE-PRE manuscript.

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
all 20 attack outputs (eight validation and twelve OE-PRE), including the raw cost
dictionaries. Parameter generation was also
checked with Python 3.12.3.

## Pinned external dependencies

- [FHE Security Guidelines](https://github.com/gong-cr/FHE-Security-Guidelines/tree/a43a59356b6e87490091751bc48c523f924d5f9e):
  `a43a59356b6e87490091751bc48c523f924d5f9e`.
- [lattice-estimator](https://github.com/malb/lattice-estimator/tree/8f1ff7e20a4d3391e3badff1d76825314db225bc):
  `8f1ff7e20a4d3391e3badff1d76825314db225bc`.
- Supplementary [TabOg/mlwe-hybrids](https://github.com/TabOg/mlwe-hybrids/tree/a92f335665eef69927d2d8f49832bd595a6dac32):
  `a92f335665eef69927d2d8f49832bd595a6dac32`, with
  [PrimalHybrid/lattice_estimator](https://github.com/malb/lattice-estimator/tree/6019056011d10d7e9c30a0d5da2d2f729fbc2eec)
  at `6019056011d10d7e9c30a0d5da2d2f729fbc2eec` and
  [DualHybrid](https://github.com/TabOg/CodedDualAttack/tree/e2104ca50a293ed09b8fcec703cd2b143d21bee8)
  at `e2104ca50a293ed09b8fcec703cd2b143d21bee8` (verified only).

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
OE-PRE inputs only if validation passes. To run just the validation:

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
  The direct NEL-LWE reduction uses `delta_nel = 2*epsilon_nel/(1-epsilon_nel)^2`.
  With `epsilon_nel = 2^-152`, the honest-user contribution is exactly
  `2^-133/(1-2^-152)^2`, and the sampler contribution is at most `2^-132`.
  Thus `Delta_stat <= 2^-133/(1-2^-152)^2 + 2^-132 + 2^-194 < 2^-130`.
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

Actual OE-PRE rows use `n=d`, the exact prime `q`, `ND.Uniform(-1,1)` secrets and
`ND.DiscreteGaussian(9/sqrt(2*pi))` errors. The input sigma is evaluated with
Sage's 128-bit real field; the estimator's stored sigma is recorded separately.
The largest supported category among 128, 192 and 256 is derived using the
pipeline's `log2(rop) >= category` test. The 1024 row has only a 0.127812 modeled
margin above Category 128.

**Table 5.2 validation uses different error inputs:** ternary `n=1024`,
`sigma=3.19`, and `q=2^26` / `2^27`. Its minima are 131.332683 / 126.193727,
confirming the published largest integer `log2(q)=26` at Category 128.
Those rows are not OE-PRE parameter sets.

## Supplementary ring-aware sensitivity check

[ePrint 2026/279](https://eprint.iacr.org/2026/279) motivates checking primal
hybrids that exploit negacyclic rotations. The actual OE-PRE secret is iid uniform
ternary; the authors' sparse workflow uses fixed-composition `SparseTernary`.
This supplementary sensitivity check therefore uses balanced fixed-weight proxies
at `floor(mu_H-2*sigma_H)`, the nearest integer to `mu_H`, and
`ceil(mu_H+2*sigma_H)`, where `mu_H=2*d/3` and `sigma_H=sqrt(2*d/9)`.
Each proxy fixes `p=floor(h/2)` positive and `m=h-p` negative entries. These are
**fixed-composition proxy estimates, not exact iid-secret security levels**, a
tail-security bound, an exhaustive attack survey, or end-to-end OE-HRA bit security.

The runner reads the selected exact primes from `configs/paper_parameters.json`
and uses `sigma=9/sqrt(2*pi)`, classical MATZOV costs and upstream GSA defaults.
It calls the three documented rotated Babai variants: no MitM, estimator MitM,
and square-root MitM, always with `poly_degree=d`. The ordinary family uses the
same upstream estimator and proxy inputs with `deny_list=["arora-gb"]`.
Only positive-`zeta` calls count as genuine rotated-primal attacks. In particular,
the audited projected-CVP/no-MitM call selected `zeta=0` and follows the ordinary
fallback; its costs are not reported as rotated-primal estimates.

| d | h_typ | Ordinary min log2(rop) | Genuine rotated-primal min log2(rop) |
|---:|---:|---:|---:|
| 1024 | 683 | 128.322 | 172.283 |
| 2048 | 1365 | 249.880 | 386.440 |
| 4096 | 2731 | 507.919 | 832.207 |

Within all nine proxies, genuine rotated-primal attacks do not become the limiting
attack: the same-repository ordinary family is cheaper. Neither minimum falls below
128 bits at any tested `d=1024` weight (`652`, `683`, `713`). The selected parameters
and existing FHE-Guidelines results are unchanged. At `d=4096`, inherited
high-dimensional search cutoffs limit the estimate; the returned finite costs
remain comfortably above 256 bits, but their many decimal places do not express
physical bit-security precision. BKW and uSVP return non-finite costs at those
three weights; these are retained and excluded from minima.

Optional reproduction, independent of the main workflow (same Sage 10.3 / Python
3.11.11 environment):

```sh
bash scripts/bootstrap_ring_aware.sh
sage -python scripts/run_ring_aware_evaluation.py
```

The bootstrap clones only the original authors' repository into ignored
`external/mlwe-hybrids`, verifies its two recursive submodule pins, and refuses
dirty sources or unexpected existing revisions. The runner imports upstream code
unchanged, uses three workers by default (`--jobs 1` runs serially), and writes
`results/ring_aware_2026_279.json`: all nine inputs, versions/pins, complete returned
cost dictionaries (including attack dimensions, probabilities and repetitions),
and derived minima. Audited minima are regression checks, never substitutes for
recomputation; the absolute comparison tolerance is `1e-6` bits. A failed
comparison writes `.failed.json`, returns a nonzero exit
code and leaves any successful result unchanged.

The specialised `DualHybrid` artifact is Kyber-specific and lacks the needed
ternary-secret plus independent Gaussian-error interface. It is neither adapted
nor evaluated on OE-PRE; ordinary lattice-estimator dual and dual-hybrid costs
provide the comparison here.

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

This artifact accompanies the OE-PRE manuscript and directly implements the fixed
parameterization and conservative numerical formulas in Section 3.4 and Appendix C.
The statistical loss is synchronized with manuscript commit
[`76223a0e7b091e2d40119727a834d3c747d2535b`](https://github.com/coro-afk/oe-pre/commit/76223a0e7b091e2d40119727a834d3c747d2535b),
using the direct NEL-LWE reduction in Section 2.2 and the budget in Appendix C.1.
This update preserves the Gaussian widths, moduli, correctness bounds and resource
sizes. The exact lattice-estimator inputs are also unchanged, so the bundled FHE
attack results remain applicable.
The FHE evaluation uses the pinned official pipeline definitions. The MIT license
applies to this artifact; external dependencies retain their upstream licenses.

## AI-assisted development

Generative AI tools (OpenAI ChatGPT) were used to assist with the
implementation, documentation, and review of this reproducibility artifact.
All parameter formulas, cryptographic assumptions, external dependencies,
numerical outputs, and code used to support the reported results were reviewed
and validated by the authors. The authors take full responsibility for the
artifact and its results.
