"""GNN Detector — cfexplainer/GNNExplainer baseline."""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GINConv, GraphConv, global_mean_pool, global_max_pool, global_add_pool

class GNNDetector(nn.Module):
    """Standard GNN vulnerability detector used by GNNExplainer/CFExplainer."""
    def __init__(self, input_dim=128, hidden_dim=128, num_layers=3, num_classes=2,
                 dropout=0.3, gnn_type="GCNConv", pooling="mean"):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        self.linear_in = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
        )

        self.gnn_layers = nn.ModuleList()
        for _ in range(num_layers):
            if gnn_type == "GCNConv":
                layer = GCNConv(hidden_dim, hidden_dim)
            elif gnn_type == "GINConv":
                mlp = nn.Sequential(nn.Linear(hidden_dim, hidden_dim), nn.ReLU(), nn.Linear(hidden_dim, hidden_dim))
                layer = GINConv(mlp)
            elif gnn_type == "GraphConv":
                layer = GraphConv(hidden_dim, hidden_dim)
            else:
                layer = GCNConv(hidden_dim, hidden_dim)
            self.gnn_layers.append(layer)

        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)

        if pooling == "mean":
            self.pool = global_mean_pool
        elif pooling == "max":
            self.pool = global_max_pool
        else:
            self.pool = global_add_pool

        self.classifier = nn.Linear(hidden_dim, num_classes)

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch

        x = self.linear_in(x)
        for layer in self.gnn_layers:
            x = layer(x, edge_index)
            x = self.relu(x)
            x = self.dropout(x)

        x = self.pool(x, batch)
        x = self.classifier(x)
        return x

    def get_embeddings(self, data):
        """Get node embeddings before pooling (for explainers)."""
        x, edge_index = data.x, data.edge_index
        x = self.linear_in(x)
        for layer in self.gnn_layers:
            x = layer(x, edge_index)
            x = self.relu(x)
        return x
