#!/usr/bin/env python3
"""Reproduce Section 3.4 / Appendix C numerical conditions (standard library only)."""

import argparse
from decimal import Decimal as D, ROUND_CEILING, ROUND_FLOOR, localcontext
from fractions import Fraction as F
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/paper_parameters.json"
# Pi constant for the 100-digit Decimal evaluation of the Appendix C formulas.
PI = D("3.141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647")


def require(condition, message):
    """Keep manuscript checks active even under python -O."""
    if not condition:
        raise ValueError(message)


def ceil(value):
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def prime(n):
    """Deterministic trial division; adequate for the three paper primes."""
    if n < 2 or n % 2 == 0:
        return n == 2
    return all(n % factor for factor in range(3, math.isqrt(n) + 1, 2))


def digits(q, base):
    w, capacity = 0, 1
    while capacity < q:
        w, capacity = w + 1, capacity * base
    return w


def fraction_record(value):
    with localcontext() as ctx:
        ctx.rounding = ROUND_CEILING
        upper = D(value.numerator) / D(value.denominator)
    return {"numerator": str(value.numerator), "denominator": str(value.denominator),
            "decimal_upper": str(upper)}


def load_config(path=CONFIG):
    c = json.loads(path.read_text(encoding="utf-8"))
    require(c["schema_version"] == 1, "Unsupported configuration schema")
    require(c["dimensions"] == [1024, 2048, 4096], "Expected the three paper dimensions")
    require(c["gadget_base"] == 4 and c["plaintext_modulus"] == 2,
            "The Appendix C specialization requires B_g=4 and p=2")
    require(c["message_coefficient_bound"] == c["secret_coefficient_bound"] == 1,
            "The complete-noise specialization requires B_m=B_s=1")
    require(c["secret_distribution"] == "uniform ternary", "Expected ternary secrets")
    require(c["payload_bits"] == 1024, "Expected the 1024-bit payload")
    require(all(type(v) is int and v == 2**18 for v in c["query_caps"].values())
            and set(c["query_caps"]) == {"Q_Hon", "Q_Enc", "Q_ReEnc"},
            "Expected all three query caps to be 2^18")
    require(c["m_nel"] == c["query_caps"]["Q_Enc"] + 1, "Incorrect m_nel")
    for name, expected in {"epsilon_nel_log2": -152, "delta_trunc_log2": -151,
                           "delta_disc_log2": -151, "delta_samp_upper_log2": -150,
                           "collision_cap_log2": -194, "delta_stat_target_log2": -130,
                           "delta_corr_op_log2": -40, "s_base": 9, "s_ct": 18,
                           "s_pad": 18}.items():
        require(type(c[name]) is int and c[name] == expected, f"Unexpected paper input: {name}")
    require(set(c["selected_q"]) == {str(d) for d in c["dimensions"]}, "Incomplete q mapping")
    return c


def parameter_row(c, dimension):
    d, q = D(dimension), c["selected_q"][str(dimension)]
    require(type(q) is int and q > 1, "q must be an exact positive integer")
    base, w = c["gadget_base"], digits(q, c["gadget_base"])
    sb, sc, sp = (D(c[k]) for k in ("s_base", "s_ct", "s_pad"))
    eps, trunc, corr = (D(2)**c[k] for k in
                       ("epsilon_nel_log2", "delta_trunc_log2", "delta_corr_op_log2"))
    eta = ((2*d*c["m_nel"]*(1+1/eps)).ln()/PI).sqrt()
    base_min = D(2).sqrt()*eta
    abar = sb**2+2*eta**2
    require(sb >= base_min and sc**2 > abar, f"NEL base/ciphertext condition failed: d={dimension}")
    padding_rhs = sc**2*abar/(sc**2-abar)
    require(sp**2 >= padding_rhs, f"NEL padding condition failed: d={dimension}")
    bpad = sp*((2*d/trunc).ln()/PI).sqrt()
    # Bound the reused public-key error via its combined multiplier before squaring.
    tau_ct = sc**2
    tau_pk = sb**2*d*(1+2*w*d)**2
    tau_aux = sb**2*(4*w*d+4*w*d**3+1+d)
    tau = (tau_ct+tau_pk+tau_aux).sqrt()
    bagg = tau*((2*d/corr).ln()/PI).sqrt()
    qcorr = 2*(c["message_coefficient_bound"]+c["plaintext_modulus"]*(bpad+bagg))
    require(prime(q) and q % (2*dimension) == 1, f"Prime/NTT condition failed: d={dimension}")
    require(q > qcorr and base**(w-1) < q <= base**w, f"No-wrap/gadget condition failed: d={dimension}")
    first = int(qcorr.to_integral_value(rounding=ROUND_FLOOR))+1
    first += (1-first) % (2*dimension)
    while not prime(first):
        first += 2*dimension
    require(first == q, f"q is not the first admissible prime at its own w: d={dimension}")

    eps_exact = F(2)**c["epsilon_nel_log2"]
    delta_nel = 4*eps_exact/(1-eps_exact)
    nel = c["query_caps"]["Q_Hon"]*delta_nel
    delta_samp = F(2)**c["delta_trunc_log2"]+F(2)**c["delta_disc_log2"]
    require(delta_samp <= F(2)**c["delta_samp_upper_log2"], "Sampler budget failed")
    sampler = c["query_caps"]["Q_ReEnc"]*delta_samp
    pairs = math.comb(c["m_nel"], 2)
    cap = F(2)**c["collision_cap_log2"]
    # Exact integer certificate, not an underflowed floating-point collision term.
    require(pairs*cap.denominator < cap.numerator*q**dimension, "Collision cap failed")
    total_upper = nel+sampler+cap
    target = F(2)**c["delta_stat_target_log2"]
    require(total_upper < target, "Delta_stat is not strictly below its target")

    support = int(bpad.to_integral_value(rounding=ROUND_FLOOR))
    grid_factor = dimension*2*support
    tape_bits = -c["delta_disc_log2"]+(grid_factor-1).bit_length()
    grid_bound = F(grid_factor, 2**tape_bits)
    require(grid_bound <= F(2)**c["delta_disc_log2"], "Inverse-CDF grid budget failed")
    tail_log2 = ((2*d).ln()-PI*D(support+1)**2/sp**2)/D(2).ln()
    require(tail_log2 < c["delta_trunc_log2"], "Bounded support tail budget failed")
    ell = (q-1).bit_length()
    ct_bits, rk_bits = 2*dimension*ell, 2*w*dimension*ell
    return {
        "dimension": dimension, "q": q, "log2_q": D(q).ln()/D(2).ln(), "w": w,
        "modulus_bits": ell, "m_nel": c["m_nel"], "smoothing_rank": dimension*c["m_nel"],
        "eta_bar": eta, "sqrt_2_eta_bar": base_min, "A_bar": abar,
        "s_base": int(sb), "s_ct": int(sc), "s_pad": int(sp),
        "ordinary_sigma_base": sb/(2*PI).sqrt(), "ordinary_sigma_pad": sp/(2*PI).sqrt(),
        "smoothing_slack": sb-base_min, "balanced_width_min": (2*abar).sqrt(),
        "nel_ct_squared_slack": sc**2-abar, "nel_padding_rhs": padding_rhs,
        "nel_padding_slack": sp**2-padding_rhs,
        "B_pad": bpad, "tau_ct_squared": tau_ct, "tau_pk_squared": tau_pk,
        "tau_aux_squared": tau_aux, "tau_star": tau, "B_agg": bagg,
        "q_corr": qcorr, "q_slack": D(q)-qcorr,
        "q_is_prime": True, "q_mod_2d": q % (2*dimension),
        "gadget_lower_exclusive": base**(w-1), "gadget_upper_inclusive": base**w,
        "first_admissible_prime_at_w": first,
        "statistics": {
            "delta_nel": fraction_record(delta_nel), "nel_contribution": fraction_record(nel),
            "delta_samp_upper": fraction_record(delta_samp), "sampler_contribution": fraction_record(sampler),
            "collision": {"formula": "pairs / q^dimension", "pairs": pairs, "q": q,
                          "dimension": dimension, "negative_log2": (dimension*D(q).ln()-D(pairs).ln())/D(2).ln(),
                          "strict_cap_log2": c["collision_cap_log2"], "exact_integer_check_passed": True},
            "total_upper_using_collision_cap": fraction_record(total_upper),
            "target_slack_lower": fraction_record(target-total_upper), "below_target": True},
        "padding_precision": {"support_lower": -support, "support_upper": support,
                              "tape_bits_per_coefficient": tape_bits, "L_pad": dimension*tape_bits,
                              "product_grid_TV_upper": fraction_record(grid_bound),
                              "product_truncation_log2_upper": tail_log2,
                              "scope": "Analytical inverse-CDF precision witness; no sampler implementation or CDT certificate generated."},
        "resources": {"ciphertext_raw_bits": ct_bits, "ciphertext_raw_kib": D(ct_bits)/8192,
                      "rekey_raw_bits": rk_bits, "rekey_raw_kib": D(rk_bits)/8192,
                      "ciphertext_expansion": D(ct_bits)/c["payload_bits"], "main_reenc_ring_products": 2*w+2},
        "all_conditions_passed": True}


def generate(c):
    with localcontext() as ctx:
        ctx.prec = 100
        rows = [parameter_row(c, d) for d in c["dimensions"]]
        require(ceil(max(r["sqrt_2_eta_bar"] for r in rows)) == c["s_base"],
                "Base width is not the smallest common integer")
        require(ceil(max(r["balanced_width_min"] for r in rows)) == c["s_ct"] == c["s_pad"],
                "Symmetric widths are not the smallest common integer")
        return {"schema_version": 1, "decimal_precision": 100,
                "numerical_encoding": "Decimal quantities are strings; rational statistics retain exact numerator/denominator.",
                "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--output", type=Path, default=ROOT / "results/parameter_selection.json")
    args = parser.parse_args()
    output = generate(load_config(args.config))
    output["config_sha256_lf"] = hashlib.sha256(args.config.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, default=str, allow_nan=False)+"\n", encoding="utf-8", newline="\n")
    for row in output["rows"]:
        r = row["resources"]
        print(f"d={row['dimension']} q={row['q']} w={row['w']} q_slack={row['q_slack']:.3f} "
              f"ct/rk={r['ciphertext_raw_kib']}/{r['rekey_raw_kib']} KiB "
              f"expansion={r['ciphertext_expansion']} products={r['main_reenc_ring_products']}")
    print("All statistical/NEL, padding, single-hop correctness, modulus and resource checks passed.")


if __name__ == "__main__":
    main()
