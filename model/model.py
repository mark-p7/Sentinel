import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from .build_graph import build_graph

# Function to fit normalizer
def fit_normalizer(x_raw):
    mean = x_raw.mean(dim=0, keepdim=True)
    std = x_raw.std(dim=0, unbiased=False, keepdim=True) + 1e-6
    return (mean, std)

# Function to apply normalizer
def normalize(x_raw, mean, std):
    return (x_raw - mean) / std

# GNN using GCNConv from PyTorch Geometric with skip connections.
# The skip (residual) path preserves per-node feature signal through the GNN layers so the model can detect malicious packages even when they are surrounded by many benign neighbors in the graph.
class GCN(torch.nn.Module):
    def __init__(self, in_feat, hidden, out):
        super().__init__()
        # Layer 1: input features -> hidden representation
        self.conv1 = GCNConv(in_feat, hidden)
        self.bn1 = torch.nn.BatchNorm1d(hidden)
        # Layer 2: hidden -> hidden (captures 2-hop neighborhood patterns)
        self.conv2 = GCNConv(hidden, hidden)
        self.bn2 = torch.nn.BatchNorm1d(hidden)
        # Classification head: combines GNN output with original features
        self.classifier = torch.nn.Linear(hidden + in_feat, out)

    # Function to define ingestion of data into the model (Forward pass)
    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        x_input = x

        x = self.conv1(x, edge_index)
        x = self.bn1(x) if x.size(0) > 1 else x
        x = F.relu(x)
        x = F.dropout(x, p=0.3, training=self.training)

        x = self.conv2(x, edge_index)
        x = self.bn2(x) if x.size(0) > 1 else x
        x = F.relu(x)
        x = F.dropout(x, p=0.3, training=self.training)

        # Concatenate GNN output with original features (skip connection) so the classifier sees both graph-context and per-node signals
        x = torch.cat([x, x_input], dim=1)
        x = self.classifier(x)

        return F.log_softmax(x, dim=1)

# Function to train model
def train_model(data, mean, std):
    # Normalize the node tensors
    data.x = normalize(data.x_raw, mean, std)

    # Create the model with 64 hidden units for better capacity
    model = GCN(data.num_node_features, 64, 2)

    # Adam optimizer with weight decay for regularization
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)

    # Class-weighted loss to handle potential class imbalance
    # Gives higher weight to the minority class so the model doesn't
    # just predict everything as benign
    num_benign = (data.y == 0).sum().float()
    num_malicious = (data.y == 1).sum().float()
    total = num_benign + num_malicious
    if num_malicious > 0 and num_benign > 0:
        weight = torch.tensor([total / (2 * num_benign), total / (2 * num_malicious)])
    else:
        weight = None

    # Training loop (One epoch counts as a complete pass through the entire dataset during training)
    # 200 epochs with early-stopping patience for convergence on larger datasets
    best_loss = float("inf")
    patience_counter = 0
    patience = 30

    for epoch in range(200):
        # Transition to training mode
        model.train()
        # Clear gradients
        optimizer.zero_grad()
        # Ingest data (Forward pass)
        out = model(data)
        # Loss compute with class weights
        loss = F.cross_entropy(out, data.y, weight=weight)
        # Backpropagation
        loss.backward()
        # Update weights
        optimizer.step()

        loss_val = loss.item()
        if epoch % 20 == 0:
            print(f"Epoch = {epoch}, Loss = {loss_val:.4f}")

        # Early stopping: stop if loss hasn't improved for `patience` epochs
        # This is to help stop overfitting
        if loss_val < best_loss - 1e-4:
            best_loss = loss_val
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"Early stopping at epoch {epoch}, Loss = {loss_val:.4f}")
                break

    return model

# Function to save the model
def save_model(model, mean, std, filename, in_feat):
    # Infer hidden dimension from the model's first conv layer output
    hidden = model.conv1.lin.weight.shape[0]
    out = model.classifier.weight.shape[0]
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "mean": mean,
        "std": std,
        "in_feat": in_feat,
        "hidden": hidden,
        "out": out,
    }
    torch.save(checkpoint, filename)

# Function to load the model
def load_model(filename):
    checkpoint = torch.load(filename, map_location="cpu")

    in_feat = checkpoint.get("in_feat")
    if in_feat is None:
        in_feat = checkpoint["model_state_dict"]["conv1.lin.weight"].shape[1]

    hidden = checkpoint.get("hidden", 16)
    out = checkpoint.get("out", 2)

    model = GCN(in_feat, hidden, out)
    model.load_state_dict(checkpoint["model_state_dict"])
    return model, checkpoint["mean"], checkpoint["std"]

# Function to test model
def evaluate(model, data, mean, std):
    data.x = normalize(data.x_raw, mean, std)
    model.eval()

    out = model(data)
    pred = out.argmax(dim=1)
    acc = (pred == data.y).sum().item() / len(data.y)

    node_names = getattr(data, "node_names", [str(i) for i in range(len(data.y))])
    pkg_results = []
    for name, true_lb, pred_lb in zip(node_names, data.y.tolist(), pred.tolist()):
        if true_lb == 1 and pred_lb == 1: outcome = "TP"
        elif true_lb == 0 and pred_lb == 0: outcome = "TN"
        elif true_lb == 0 and pred_lb == 1: outcome = "FP"
        else: outcome = "FN"
        pkg_results.append({
            "name": name,
            "true_label": true_lb,
            "pred_label": pred_lb,
            "outcome": outcome,
        })

    tp = sum(1 for r in pkg_results if r["outcome"] == "TP")
    tn = sum(1 for r in pkg_results if r["outcome"] == "TN")
    fp = sum(1 for r in pkg_results if r["outcome"] == "FP")
    fn = sum(1 for r in pkg_results if r["outcome"] == "FN")
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0)

    return {
        "accuracy": acc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "packages": pkg_results,
    }

def run_model(is_train, model_name, benign_json_data, malicious_json_data):
    # Train
    if is_train:
        print("Training model")
        data = build_graph(benign_json_data, malicious_json_data)
        mean, std = fit_normalizer(data.x_raw)
        model = train_model(data, mean, std)
        save_model(model, mean, std, model_name, in_feat=data.x_raw.shape[1])
        print(f"Model trained and saved to '{model_name}'.")
    else:
        # Eval
        print("Evaluating model")
        test_data = build_graph(benign_json_data, malicious_json_data)
        model, mean, std = load_model(model_name)
        result = evaluate(model, test_data, mean, std)
        print(f"Calculated accuracy: {result['accuracy']:.4f}")
        return result