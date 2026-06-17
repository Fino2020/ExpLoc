"""Recompute MSP/MSR/MIoU at CVE level via union across functions.

Reads a _full.json file with per_cve data (including per-function pred_lines/gt_lines).
Outputs CVE-level union metrics vs original function-level macro metrics.
"""
import json, sys
from collections import defaultdict


def union_lines(funcs):
    """Union all pred_lines and gt_lines across functions in a CVE."""
    se = set()
    sp = set()
    for f in funcs:
        for l in f.get("pred_lines", []):
            se.add(l)
        for l in f.get("gt_lines", []):
            sp.add(l)
    return se, sp


def compute_metrics(se, sp):
    if not se and not sp:
        return 1.0, 1.0, 1.0
    if not se:
        return 0.0, 0.0, 0.0
    if not sp:
        return 0.0, 0.0, 0.0
    inter = se & sp
    union = se | sp
    msp = len(inter) / len(se)
    msr = len(inter) / len(sp)
    miou = len(inter) / len(union)
    return msp, msr, miou


def main():
    if len(sys.argv) < 2:
        print("Usage: python recompute_cve_union.py <explanation_eval_*.json>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path) as f:
        data = json.load(f)

    per_cve = data.get("per_cve", [])
    if not per_cve:
        print("No per_cve data found in this file. Re-run explain_localization.py first.")
        sys.exit(1)

    cve_metrics = []
    for entry in per_cve:
        funcs = entry["functions"]
        if not funcs:
            continue
        se, sp = union_lines(funcs)
        msp, msr, miou = compute_metrics(se, sp)
        cve_metrics.append({
            "cve_id": entry["cve_id"],
            "n_funcs": len(funcs),
            "|S_e|": len(se),
            "|S_p|": len(sp),
            "|S_e ∩ S_p|": len(se & sp),
            "MSP": msp,
            "MSR": msr,
            "MIoU": miou,
        })

    n_cves = len(cve_metrics)
    if n_cves == 0:
        print("No CVEs with data.")
        return

    cve_msp = sum(c["MSP"] for c in cve_metrics) / n_cves
    cve_msr = sum(c["MSR"] for c in cve_metrics) / n_cves
    cve_miou = sum(c["MIoU"] for c in cve_metrics) / n_cves

    print(f"\n{'='*60}")
    print(f"  CVE-LEVEL UNION EVALUATION")
    print(f"  File: {path}")
    print(f"  N (CVEs): {n_cves}")
    print(f"  N (functions, original): {data.get('n_functions', '?')}")
    print()
    print(f"  {'':20s} {'Function-level':>15s} {'CVE-level':>15s}")
    print(f"  {'MSP':20s} {data['MSP']*100:>14.2f}% {cve_msp*100:>14.2f}%")
    print(f"  {'MSR':20s} {data['MSR']*100:>14.2f}% {cve_msr*100:>14.2f}%")
    print(f"  {'MIoU':20s} {data['MIoU']*100:>14.2f}% {cve_miou*100:>14.2f}%")

    # Per-CVE distribution
    multi_func = [c for c in cve_metrics if c["n_funcs"] >= 2]
    single_func = [c for c in cve_metrics if c["n_funcs"] == 1]
    print(f"\n  CVEs with ≥2 functions: {len(multi_func)}")
    if multi_func:
        mm = sum(c["MIoU"] for c in multi_func) / len(multi_func)
        print(f"    Multi-func MIoU: {mm*100:.2f}%")
    if single_func:
        sm = sum(c["MIoU"] for c in single_func) / len(single_func)
        print(f"    Single-func MIoU: {sm*100:.2f}%")

    # Save
    out_path = path.replace(".json", "_cve_union.json")
    result = {
        "source": path,
        "n_cves": n_cves,
        "n_functions_original": data.get("n_functions"),
        "function_level": {"MSP": data["MSP"], "MSR": data["MSR"], "MIoU": data["MIoU"]},
        "cve_level": {"MSP": round(cve_msp, 4), "MSR": round(cve_msr, 4), "MIoU": round(cve_miou, 4)},
        "per_cve": cve_metrics,
    }
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\n  Saved to {out_path}")


if __name__ == "__main__":
    main()
