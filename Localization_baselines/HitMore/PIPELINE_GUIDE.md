# HitMore Pipeline — 全量训练 & 测试操作指南

> GPU: PyTorch MLP | CUDA 11.8 | RTX 3070 Ti  
> 训练集: HitMore 原始 6 个 Java 项目  
> 测试集: VulnLocalization `full_manifest.json` (886 CVEs)  
> 更新时间: 2026-06-03

---

## 1. Pipeline 概览

```
┌─────────────────────────────────────────────────────────────┐
│                    训练阶段 (HitMore 数据)                    │
│                                                             │
│  /mnt/d/Desktop/HitMore-main/dataset/                       │
│  ├── merge_data_without_GT/{ds}.merge.txt  (244K 行)        │
│  │   └── 格式: bugId,rank_a,score_a,file_a,                 │
│  │             bugId,rank_bl,file_bl,score_bl,               │
│  │             bugId,rank_bz,file_bz                        │
│  ├── bugLocator/{ds}/{ds}.xml  (bug 标题+描述)               │
│  └── bugLocator/{ds}/{ds}_bugPredict.res  (GT 标注)         │
│                                                             │
│  解析 → 67K (bugId, file_path) pairs                        │
│  ↓ GT 模糊匹配 → label=1/0                                  │
│  ↓ 去重 (vs VulnLocalization GT,  80 条移除)                 │
│  ↓ extract_all_features() → 35 维特征                       │
│  ↓ PyTorch MLP [256→128→64] GPU 训练                        │
│  ↓ 保存 hitmore_mlp_gpu.pt + scaler.pkl                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    测试阶段 (VulnLocalization)                │
│                                                             │
│  full_manifest.json (886 CVEs)                              │
│  ↓ 每个 CVE: list_repo_files() → 候选文件列表                 │
│  ↓ GT 文件 → positive, 非 GT → negative (max 3x neg)         │
│  ↓ extract_all_features() → 相同 35 维特征                   │
│  ↓ 特征对齐 (缺失列补 0, 多余列删除)                           │
│  ↓ 模型推理 → 每个 CVE 文件按概率排序                          │
│  ↓ 3-level 文件模糊匹配 + 5-level 函数模糊匹配                 │
│  ↓ 计算: Success Rate, MRR, Top-1/3/5, P/R/F1, NDCG@15, MAP@15│
│  ↓ 输出 evaluation_summary.json + evaluation_details.json    │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 数据统计

| 数据集       | Merge 行数    | XML bugs  | GT bugs   | Pos 样本     | Neg 样本      |
|-----------|-------------|-----------|-----------|------------|-------------|
| aspectj   | 26,749      | 367       | 563       | 1,449      | ~4,288      |
| hibernate | 63,540      | 430       | 1,285     | 2,923      | ~8,638      |
| lucene    | 67,814      | 592       | 1,454     | 6,918      | ~20,451     |
| openjpa   | 23,480      | 452       | 533       | 1,420      | ~4,260      |
| tomcat    | 42,892      | 712       | 992       | 2,397      | ~7,186      |
| zookeeper | 19,926      | 293       | 470       | 1,798      | ~5,394      |
| **合计**    | **244,401** | **2,846** | **5,297** | **16,905** | **~50,217** |

全量训练集: **98,502 条** (去重后, max_neg_ratio=5)
测试集: **886 CVEs** (multi-language: C, Python, JS, Java, PHP, Go, Ruby...)

---

## 3. 特征列表 (35 维)

### Bug Report 特征 (18)
| 特征                        | 说明             |
|---------------------------|----------------|
| br_text_len               | 文本长度           |
| br_word_count             | 单词数            |
| br_sentence_count         | 句子数            |
| br_has_stack_trace        | 是否含堆栈跟踪        |
| br_has_code               | 是否含代码片段        |
| br_has_patch              | 是否含 patch/diff |
| br_has_screenshot         | 是否含截图关键词       |
| br_security_keyword_count | 安全关键词密度        |
| br_avg_word_len           | 平均单词长度         |
| br_readability            | Flesch 可读性得分   |
| br_token_count            | 归一化 token 数    |
| br_unique_token_count     | 唯一 token 数     |
| br_unique_ratio           | 唯一 token 比率    |
| br_url_count              | URL 数量         |
| br_mention_count          | @mention 数量    |
| br_has_java_example       | 含 Java 代码示例    |
| br_has_c_example          | 含 C 代码示例       |
| br_has_python_example     | 含 Python 代码示例  |

### File 特征 (9)
| 特征                       | 说明         |
|--------------------------|------------|
| file_depth               | 文件路径深度     |
| file_name_len            | 文件名长度      |
| file_has_src_ext         | 是否源码文件扩展名  |
| file_in_important_dir    | 路径是否含重要目录名 |
| file_path_security_score | 路径安全关键词得分  |
| file_is_test             | 是否测试文件     |
| file_matches_language    | 扩展名匹配声明语言  |

### Relation 特征 (6)
| 特征                          | 说明                        |
|-----------------------------|---------------------------|
| rel_jaccard                 | Issue 文本与文件路径 Jaccard 相似度 |
| rel_token_overlap           | Token 重叠数                 |
| rel_filename_in_issue       | 文件名出现在 Issue 中            |
| rel_filename_noext_in_issue | 无扩展名文件名出现在 Issue 中        |
| rel_dir_overlap             | 目录路径与 Issue 文本重叠          |
| rel_content_jaccard         | 文件内容与 Issue Jaccard (如可用) |

### Meta 特征 (2)
| 特征              | 说明      |
|-----------------|---------|
| meta_cvss_score | CVSS 分数 |
| meta_language   | 编程语言    |

备注: `file_name`, `file_extension`, `meta_cwe_id` 在 `prepare_features()` 中被 drop/encode，最终训练特征矩阵 **34 维**。

---

## 4. 模型架构

```
VulnMLP(34)
  ├── Linear(34 → 256) + BatchNorm1d + ReLU + Dropout(0.3)
  ├── Linear(256 → 128) + BatchNorm1d + ReLU + Dropout(0.3)
  ├── Linear(128 → 64)  + BatchNorm1d + ReLU + Dropout(0.3)
  └── Linear(64 → 1) → sigmoid → probability

Loss: BCEWithLogitsLoss(pos_weight = neg_count / pos_count)
Optimizer: AdamW(lr=0.001, weight_decay=1e-4)
Early stopping: patience=10 on validation loss (10% holdout)
```

---

## 5. 全量训练 & 测试命令

### 5.1 正确评估 (full_repo 模式 — **推荐**)

此模式对 CVE 仓库中的**所有文件**进行排名，与 `evaluate.py` 使用相同的评估条件：

```bash
cd /mnt/d/Desktop/VulnLocalization

# 快速测试 (3 个 CVE)
python3 -m HitMore.main --mode full_repo --limit 3

# 全量 (98K 训练, 886 CVE 测试, 对所有仓库文件排名)
python3 -m HitMore.main --mode full_repo --limit 0 --train-samples 0

# 然后运行评估：
cd Explainable_Localization
python3 evaluate.py --manifest ../Dataset/full_manifest.json \
    --results ../HitMore/output/full_repo \
    --output ../HitMore/output/full_repo
```

### 5.2 旧版评估 (cross_project — **指标虚高，请勿用于基线**)

```bash
# 内部评估候选池极小 (平均 6.4 个文件/CVE)
# 成功率虚高 — 不可与 evaluate.py 结果比较
python3 -m HitMore.main --mode cross_project --limit 0 --train-samples 0
```

### 5.3 区别

| 属性 | full_repo (正确) | cross_project (旧版) |
|------|-----------------|---------------------|
| 候选池 | 所有仓库文件 (50-5000+) | GT + 3× 负样本 (平均 6.4) |
| 输出格式 | result.json → evaluate.py | 内部评估 |
| 可比较性 | 与 VulnLocalization 可比较 | 不可比较 |
| 评估 | 使用 evaluate.py | 内部计算 |

```bash
cd /mnt/d/Desktop/VulnLocalization

# Step 1: 仅训练 + 保存模型
python3 -c "
from HitMore.hitmore_data_loader import load_hitmore_training_data
from HitMore.dataset import prepare_features
from HitMore.model import train_pytorch_model
import torch, joblib, os

print('Loading training data...')
df = load_hitmore_training_data(max_neg_ratio=5, verbose=True, dedup_test_files=True)
for c in ['_dataset', '_source']:
    if c in df.columns: df = df.drop(columns=[c])

X, y, feature_names, scaler = prepare_features(df)
print(f'Training: {X.shape}')

model = train_pytorch_model(X, y, epochs=80, batch_size=128, verbose=True)

os.makedirs('HitMore/output/model', exist_ok=True)
torch.save({
    'model_state_dict': model.state_dict(),
    'input_dim': X.shape[1],
    'feature_names': list(feature_names),
}, 'HitMore/output/model/hitmore_mlp_gpu.pt')
joblib.dump(scaler, 'HitMore/output/model/scaler.pkl')
print('Model saved.')
"

# Step 2: 加载模型 + 测试
python3 -c "
from HitMore.dataset import build_dataset, prepare_features
from HitMore.model import VulnMLP, predict_proba, compute_cve_metrics, compute_aggregate, save_results, print_results
import torch, joblib, json, os, pandas as pd

DEVICE = torch.device('cuda')

# 加载模型
ckpt = torch.load('HitMore/output/model/hitmore_mlp_gpu.pt')
model = VulnMLP(ckpt['input_dim']).to(DEVICE)
model.load_state_dict(ckpt['model_state_dict'])
model.eval()

# 加载测试数据
print('Building test set...')
test_df = build_dataset(limit=None, verbose=True)
X_test, y_test, test_fn, _ = prepare_features(test_df)

# 对齐特征
test_feat_df = pd.DataFrame(X_test, columns=test_fn)
train_fn = ckpt['feature_names']
for col in set(train_fn) - set(test_fn):
    test_feat_df[col] = 0.0
test_feat_df = test_feat_df[train_fn]
X_test = test_feat_df.values

# 推理 + 评估
y_proba = predict_proba(model, X_test)
test_df = test_df.copy()
test_df['y_proba'] = y_proba

all_metrics = []
for cve_id, group in test_df.groupby('cve_id'):
    ranked = group.sort_values('y_proba', ascending=False)
    pred_files = ranked['file_path'].tolist()
    gt_files = set(group[group['label'] == 1]['file_path'].tolist())
    gt_funcs = set()
    if '_gt_funcs' in group.columns:
        try:
            raw = group['_gt_funcs'].iloc[0]
            if isinstance(raw, str): gt_funcs = set(json.loads(raw))
        except: pass
    pred_funcs = [os.path.splitext(os.path.basename(fp))[0] for fp in pred_files]
    all_metrics.append(compute_cve_metrics(cve_id, pred_files, gt_files, pred_funcs[:15], gt_funcs))

agg = compute_aggregate(all_metrics)
save_results(agg, all_metrics, [], {}, 'HitMore/output')
print_results(agg)
"
```

### 5.4 参数说明

| 参数 | 默认 | 说明 |
|------|------|------|
| `--mode cross_project` | cross_project | 跨项目迁移 (train=HitMore, test=VulnLocalization) |
| `--mode kfold` | - | K-fold CV on VulnLocalization only (不使用 HitMore) |
| `--limit 0` | 0 | 测试 CVE 数量 (0=全部 886) |
| `--train-samples 0` | 100 | 每数据集训练样本数 (0=全部 ~98K) |
| `--output HitMore/output` | HitMore/output | 输出目录 |

### 5.5 常用运行规模

```bash
# 验证跑通 (600 训练, 30 测试) —  30s
python3 -m HitMore.main --mode cross_project --limit 30 --train-samples 100

# 中等规模 (1,200 训练, 100 测试) —  2min
python3 -m HitMore.main --mode cross_project --limit 100 --train-samples 200

# 全量 (98K 训练, 886 测试) —  1-3h (repo 扫描占大头)
python3 -m HitMore.main --mode cross_project --limit 0 --train-samples 0
```

---

## 6. 输出文件

```
HitMore/output/
├── evaluation_summary.json    ← 聚合指标 (与 evaluate.py 格式一致)
├── evaluation_details.json    ← 每个 CVE 的详细指标
└── model/
    ├── hitmore_mlp_gpu.pt     ← PyTorch 模型权重 + 元数据
    ├── scaler.pkl             ← StandardScaler
    └── feature_names.json     ← 特征名列表
```

### evaluation_summary.json 结构

```json
{
  "total_cves": 886,
  "evaluated": 886,
  "file_level": {
    "success_rate": 0.9964,
    "precision": 0.2610,
    "recall": 0.9832,
    "f1": 0.4069,
    "mrr": 0.8387,
    "ndcg": 0.8584,
    "map": 0.7919,
    "top1_accuracy": 0.7420,
    "top3_accuracy": 0.9181,
    "top5_accuracy": 0.9786,
    "avg_first_rank": 1.5
  },
  "function_level": { ... },
  "counts": {
    "with_file_gt": 562,
    "with_func_gt": 557,
    "skipped_no_gt": 0
  },
  "fold_results": [ ... ],
  "top_features": [ ... ]
}
```

---

## 7. 核心模块

| 文件                               | 职责                                      |
|----------------------------------|-----------------------------------------|
| `HitMore/config.py`              | 路径、超参数、MLP 配置                           |
| `HitMore/hitmore_data_loader.py` | 解析 HitMore 原始数据 (merge + XML + GT)、去重   |
| `HitMore/features_extract.py`    | 35 维特征提取 (Bug Report + File + Relation) |
| `HitMore/dataset.py`             | VulnLocalization 测试集构建、特征预处理            |
| `HitMore/model.py`               | PyTorch MLP 训练、推理、评估指标、结果保存             |
| `HitMore/main.py`                | CLI 入口                                  |

---

## 8. 评估指标说明

所有指标与 `Explainable_Localization/evaluate.py` 一致：

**文件级匹配** (3-level fuzzy):
1. 精确路径匹配 (case-insensitive)
2. 路径后缀匹配
3. 文件名 + 目录重叠匹配

**函数级匹配** (5-level fuzzy):
1. 精确归一化匹配
2. 短名匹配 (最后一段 after `::` / `.`)
3. 最后组件匹配 (Class::method vs method)
4. 子串 + 前缀对齐
5. Levenshtein 编辑距离 ≤ 2 或 ratio ≤ 0.3

**指标**:
- Success Rate: 至少命中 1 个 GT 文件的 CVE 比例
- MRR: Mean Reciprocal Rank (第一个正确文件的排名倒数)
- Top-1/3/5: 前 K 个预测中命中的 CVE 比例
- Precision / Recall / F1 (ref)
- NDCG@15: Normalized Discounted Cumulative Gain
- MAP@15: Mean Average Precision
