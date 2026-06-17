"""Coca-style encoder — contrastive learning with MoCo."""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool
import copy

class CocaEncoder(nn.Module):
    """GNN encoder for Coca contrastive pre-training."""
    def __init__(self, input_dim=128, hidden_dim=128, num_layers=3, dropout=0.3):
        super().__init__()
        self.linear_in = nn.Linear(input_dim, hidden_dim)
        self.gnn_layers = nn.ModuleList()
        for _ in range(num_layers):
            self.gnn_layers.append(GCNConv(hidden_dim, hidden_dim))
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)
        self.projector = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
        )

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        x = self.linear_in(x)
        for layer in self.gnn_layers:
            x = layer(x, edge_index)
            x = self.relu(x)
            x = self.dropout(x)
        x = global_mean_pool(x, batch)
        x = self.projector(x)
        return x


class CocaDetector(nn.Module):
    """Coca detector = encoder + classifier head."""
    def __init__(self, input_dim=128, hidden_dim=128, num_layers=3,
                 num_classes=2, dropout=0.3):
        super().__init__()
        self.encoder = CocaEncoder(input_dim, hidden_dim, num_layers, dropout)
        self.classifier = nn.Linear(hidden_dim, num_classes)

    def forward(self, data):
        emb = self.encoder(data)
        return self.classifier(emb)


class MoCoTrainer:
    """Momentum Contrast trainer for Coca encoder."""
    def __init__(self, encoder, queue_size=4096, momentum=0.999, temperature=0.07):
        self.encoder = encoder
        self.momentum = momentum
        self.temperature = temperature

        # Momentum encoder
        self.encoder_k = copy.deepcopy(encoder)
        for param in self.encoder_k.parameters():
            param.requires_grad = False

        # Queue
        self.queue_size = queue_size
        self.register_buffer("queue", torch.randn(queue_size, encoder.projector[-1].out_features))
        self.register_buffer("queue_ptr", torch.zeros(1, dtype=torch.long))
        self.queue = F.normalize(self.queue, dim=1)

    def register_buffer(self, name, tensor):
        setattr(self, name, tensor)

    @torch.no_grad()
    def _momentum_update(self):
        for p, pk in zip(self.encoder.parameters(), self.encoder_k.parameters()):
            pk.data = pk.data * self.momentum + p.data * (1. - self.momentum)

    @torch.no_grad()
    def _dequeue_and_enqueue(self, keys):
        batch_size = keys.shape[0]
        ptr = int(self.queue_ptr)
        if ptr + batch_size > self.queue_size:
            self.queue[ptr:] = keys[:self.queue_size - ptr]
            self.queue[:batch_size - (self.queue_size - ptr)] = keys[self.queue_size - ptr:]
            ptr = batch_size - (self.queue_size - ptr)
        else:
            self.queue[ptr:ptr + batch_size] = keys
            ptr = (ptr + batch_size) % self.queue_size
        self.queue_ptr[0] = ptr

    def forward(self, im_q, im_k):
        """Compute MoCo loss. im_q and im_k are two augmented views of the same graph."""
        q = self.encoder(im_q)
        q = F.normalize(q, dim=1)

        with torch.no_grad():
            self._momentum_update()
            k = self.encoder_k(im_k)
            k = F.normalize(k, dim=1)

        # Positive logits: q @ k
        l_pos = torch.einsum('nc,nc->n', [q, k]).unsqueeze(-1)
        # Negative logits: q @ queue
        l_neg = torch.einsum('nc,kc->nk', [q, self.queue.clone().detach()])
        logits = torch.cat([l_pos, l_neg], dim=1)
        labels = torch.zeros(logits.shape[0], dtype=torch.long, device=logits.device)
        loss = F.cross_entropy(logits / self.temperature, labels)

        self._dequeue_and_enqueue(k)
        return loss


def graph_augmentation(data):
    """Simple graph augmentation: random edge drop + node feature noise."""
    data_aug = data.clone()

    # Edge drop (keep 80% edges randomly)
    if data.edge_index.size(1) > 5:
        num_edges = data.edge_index.size(1)
        keep = torch.randperm(num_edges)[:int(num_edges * 0.8)]
        data_aug.edge_index = data.edge_index[:, keep]

    # Feature noise
    noise = torch.randn_like(data.x) * 0.05
    data_aug.x = data.x + noise

    return data_aug
