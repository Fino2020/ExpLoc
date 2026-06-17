"""IVDetect-style detector — TreeLSTM + GCN."""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_max_pool

class IVDetectDetector(nn.Module):
    """Simplified IVDetect: GCN + GRU sequence encoder (no TreeLSTM for tree-sitter graphs)."""
    def __init__(self, input_dim=128, hidden_dim=128, num_layers=3, num_classes=2, dropout=0.3):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        # GRU for sequential code representation
        self.gru = nn.GRU(input_dim, hidden_dim, num_layers=2, batch_first=True,
                          bidirectional=True, dropout=dropout)

        # GCN for graph structure
        self.linear_in = nn.Linear(input_dim, hidden_dim)
        self.gcn_layers = nn.ModuleList()
        for _ in range(num_layers):
            self.gcn_layers.append(GCNConv(hidden_dim, hidden_dim))
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)

        # Combine GRU + GCN outputs
        self.fusion = nn.Linear(hidden_dim * 2 + hidden_dim, hidden_dim)
        self.classifier = nn.Linear(hidden_dim, num_classes)

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch

        # GCN path
        x_gcn = self.linear_in(x)
        for layer in self.gcn_layers:
            x_gcn = layer(x_gcn, edge_index)
            x_gcn = self.relu(x_gcn)
            x_gcn = self.dropout(x_gcn)
        x_gcn_pooled = global_max_pool(x_gcn, batch)

        # GRU path: treat node features as sequence
        # Group by batch and pad
        batch_size = int(batch.max()) + 1
        gru_outputs = []
        for i in range(batch_size):
            mask = batch == i
            seq = x[mask].unsqueeze(0)  # (1, nodes_i, feat)
            if seq.size(1) > 0:
                out, _ = self.gru(seq)
                gru_outputs.append(out[:, -1, :])  # last hidden
            else:
                gru_outputs.append(torch.zeros(1, self.hidden_dim * 2, device=x.device))
        x_gru = torch.cat(gru_outputs, dim=0)  # (batch_size, hidden*2)

        # Fusion
        x_combined = torch.cat([x_gcn_pooled, x_gru], dim=-1)
        x_out = self.fusion(x_combined)
        x_out = self.relu(x_out)
        x_out = self.dropout(x_out)
        return self.classifier(x_out)
