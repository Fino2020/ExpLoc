#!/bin/bash
cd /mnt/d/Desktop/Explainable_Baseline/unified_training
EPOCHS=30

echo "=== TASK 1/3: IVDetect + GNNExplainer (IVDetect_exp) ==="
python explain_localization.py --model ivdetect --explainer gnnexplainer --epochs $EPOCHS --device cuda --limit 0 --output checkpoints/exp_ivdetect_gnnexplainer.json

echo ""
echo "=== TASK 2/3: GNN + CFExplainer ==="
python explain_localization.py --model gnn --explainer cfexplainer --epochs $EPOCHS --device cuda --limit 0 --output checkpoints/exp_gnn_cfexplainer.json

echo ""
echo "=== TASK 3/3: Coca + GNNExplainer (Coca_exp) ==="
python explain_localization.py --model coca --explainer gnnexplainer --epochs $EPOCHS --device cuda --limit 0 --output checkpoints/exp_coca_gnnexplainer.json

echo ""
echo "=== FINAL RESULTS ==="
for f in exp_ivdetect_gnnexplainer exp_gnn_cfexplainer exp_coca_gnnexplainer; do
  python3 -c "
import json
with open('checkpoints/${f}.json') as fh:
    d = json.load(fh)
print(f\"{d['run']}: n_funcs={d['n_functions']} MSP={d['MSP']*100:.2f}% MSR={d['MSR']*100:.2f}% MIoU={d['MIoU']*100:.2f}%\")
"
done
