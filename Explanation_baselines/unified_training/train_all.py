"""Train all three detectors on unified dataset."""
import os, sys, json, time, argparse
import torch
import torch.nn as nn
from torch_geometric.loader import DataLoader
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.insert(0, os.path.dirname(__file__))
from data_loader import merge_datasets, UnifiedGraphDataset
from models import GNNDetector, IVDetectDetector, CocaDetector, MoCoTrainer, graph_augmentation
from config import *


def train_epoch(model, loader, optimizer, criterion, device):
    model.train()
    total_loss = correct = total = 0
    for data in loader:
        data = data.to(device)
        optimizer.zero_grad()
        out = model(data)
        loss = criterion(out, data.y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * data.num_graphs
        pred = out.argmax(dim=1)
        correct += (pred == data.y).sum().item()
        total += data.num_graphs
    return total_loss / max(total, 1), correct / max(total, 1)


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    all_preds, all_labels = [], []
    for data in loader:
        data = data.to(device)
        out = model(data)
        pred = out.argmax(dim=1)
        all_preds.append(pred.cpu())
        all_labels.append(data.y.cpu())
    all_preds = torch.cat(all_preds).numpy()
    all_labels = torch.cat(all_labels).numpy()
    return {
        "accuracy": accuracy_score(all_labels, all_preds),
        "precision": precision_score(all_labels, all_preds, zero_division=0),
        "recall": recall_score(all_labels, all_preds, zero_division=0),
        "f1": f1_score(all_labels, all_preds, zero_division=0),
    }


def train_detector(model, train_loader, val_loader, test_loader, name, device, epochs=NUM_EPOCHS):
    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    criterion = nn.CrossEntropyLoss()
    best_val_f1 = 0
    best_state = None
    patience_counter = 0

    print(f"\n{'='*50}\nTraining {name}\n{'='*50}")
    t0 = time.time()
    for epoch in range(epochs):
        train_loss, train_acc = train_epoch(model, train_loader, optimizer, criterion, device)
        val_metrics = evaluate(model, val_loader, device)
        print(f"  Epoch {epoch+1:3d}: loss={train_loss:.4f} acc={train_acc:.3f} "
              f"val_f1={val_metrics['f1']:.3f} val_prec={val_metrics['precision']:.3f} val_rec={val_metrics['recall']:.3f}")

        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= EARLY_STOP_PATIENCE:
                print(f"  Early stop at epoch {epoch+1}")
                break

    model.load_state_dict(best_state)
    test_metrics = evaluate(model, test_loader, device)
    elapsed = time.time() - t0
    print(f"  Test: acc={test_metrics['accuracy']:.3f} prec={test_metrics['precision']:.3f} "
          f"rec={test_metrics['recall']:.3f} f1={test_metrics['f1']:.3f} ({elapsed:.0f}s)")

    # Save
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    torch.save(best_state, os.path.join(OUTPUT_DIR, f"{name}_best.pt"))
    return test_metrics


def train_coca_ssl(encoder, train_loader, device, epochs=30):
    """Pre-train Coca encoder with MoCo contrastive learning."""
    print(f"\n{'='*50}\nPre-training Coca (MoCo)\n{'='*50}")
    encoder = encoder.to(device)
    trainer = MoCoTrainer(encoder)
    trainer.encoder = trainer.encoder.to(device)
    trainer.encoder_k = trainer.encoder_k.to(device)
    trainer.queue = trainer.queue.to(device)
    trainer.queue_ptr = trainer.queue_ptr.to(device)
    optimizer = torch.optim.Adam(encoder.parameters(), lr=0.001)

    for epoch in range(epochs):
        total_loss = count = 0
        for data in train_loader:
            data = data.to(device)
            data_aug = graph_augmentation(data).to(device)
            loss = trainer.forward(data, data_aug)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            count += 1
        print(f"  Epoch {epoch+1:3d}: moco_loss={total_loss/max(count,1):.4f}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    torch.save(encoder.state_dict(), os.path.join(OUTPUT_DIR, "coca_encoder_pretrain.pt"))
    return encoder


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", type=str, default="all",
                        choices=["gnn", "ivdetect", "coca", "all"])
    parser.add_argument("--device", type=str, default="cuda" if torch.cuda.is_available() else "cpu")
    parser.add_argument("--epochs", type=int, default=NUM_EPOCHS)
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--sample", type=int, default=0, help="Sample N for quick test")
    args = parser.parse_args()

    device = torch.device(args.device)
    print(f"Device: {device}")

    # Load data
    print("Loading data...")
    df = merge_datasets(dedup=True)
    if args.sample > 0:
        df = df.sample(args.sample, random_state=42)
        # Re-split on the sample
        from sklearn.model_selection import train_test_split
        ids = df["id"].unique()
        train_ids, test_ids = train_test_split(ids, test_size=0.2, random_state=42)
        val_ids, test_ids = train_test_split(test_ids, test_size=0.5, random_state=42)
        split_map = {}
        for i in train_ids: split_map[i] = 0
        for i in val_ids: split_map[i] = 1
        for i in test_ids: split_map[i] = 2
        df["split"] = df["id"].map(split_map).fillna(0).astype(int)
    print(f"Dataset: {len(df)} samples ({df.vul.sum()} vul)")

    # Build graphs and create dataloaders
    for split_name, split_val in [("train", 0), ("val", 1), ("test", 2)]:
        subset = df[df["split"] == split_val]
        print(f"  {split_name}: {len(subset)} samples ({subset.vul.sum()} vul)")

    # Note: graph building is expensive, use caching in UnifiedGraphDataset
    train_ds = UnifiedGraphDataset(df, "train")
    val_ds = UnifiedGraphDataset(df, "val")
    test_ds = UnifiedGraphDataset(df, "test")
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size)

    results = {}

    if args.detector in ("gnn", "all"):
        gnn = GNNDetector(input_dim=128, hidden_dim=HIDDEN_DIM, num_layers=NUM_GNN_LAYERS,
                          num_classes=NUM_CLASSES, dropout=DROPOUT, gnn_type="GCNConv", pooling=POOLING)
        results["gnn"] = train_detector(gnn, train_loader, val_loader, test_loader, "gnn", device, args.epochs)

    if args.detector in ("ivdetect", "all"):
        ivdetect = IVDetectDetector(input_dim=128, hidden_dim=HIDDEN_DIM, num_layers=NUM_GNN_LAYERS,
                                     num_classes=NUM_CLASSES, dropout=DROPOUT)
        results["ivdetect"] = train_detector(ivdetect, train_loader, val_loader, test_loader, "ivdetect", device, args.epochs)

    if args.detector in ("coca", "all"):
        from models.encoder_coca import CocaEncoder
        encoder = CocaEncoder(input_dim=128, hidden_dim=HIDDEN_DIM, num_layers=NUM_GNN_LAYERS, dropout=DROPOUT)
        encoder = train_coca_ssl(encoder, train_loader, device, epochs=min(30, args.epochs))
        coca = CocaDetector(input_dim=128, hidden_dim=HIDDEN_DIM, num_layers=NUM_GNN_LAYERS,
                            num_classes=NUM_CLASSES, dropout=DROPOUT)
        # Load pre-trained encoder weights
        coca.encoder.load_state_dict(encoder.state_dict())
        results["coca"] = train_detector(coca, train_loader, val_loader, test_loader, "coca", device, args.epochs)

    # Summary
    print(f"\n{'='*50}\nSummary\n{'='*50}")
    for name, metrics in results.items():
        print(f"  {name}: acc={metrics['accuracy']:.3f} prec={metrics['precision']:.3f} "
              f"rec={metrics['recall']:.3f} f1={metrics['f1']:.3f}")

    with open(os.path.join(OUTPUT_DIR, "results.json"), "w") as f:
        json.dump({k: {kk: round(vv, 4) for kk, vv in v.items()} for k, v in results.items()}, f, indent=2)
    print(f"\nCheckpoints saved to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
