import torch
import torch.nn.functional as F
from torch_geometric.data import Data
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

# Conventional GNN class using the GCNConv GNN design from Pytorch
class GCN(torch.nn.Module):
    def __init__(self, in_feat, hidden, out):
        super().__init__()
        # Init GCN Layers
        # First layer to take in features and transform them into size, hidden
        self.conv1 = GCNConv(in_feat, hidden)
        # Second layer takes hidden features from first layer and maps to final dimension, number of output classes
        self.conv2 = GCNConv(hidden, out)

    # Function to define ingestion of data into the model (Forward pass)
    def forward(self, data):
        x, edge_index = data.x, data.edge_index

        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, training=self.training)
        x = self.conv2(x, edge_index)

        return F.log_softmax(x, dim=1)

# Function to train model
def train_model(data, mean, std):
    # Normalize the node tensors
    data.x = normalize(data.x_raw, mean, std)

    # Create the model
    model = GCN(data.num_node_features, 16, 2)
    
    # Pytorch Adam optimizer to apply gradients and update weights, with learning rate of 0.01
    optimizer = torch.optim.Adam(
        model.parameters(), lr=0.01
    )  

    # Pytorch training loop
    # 1. Transition model to training mode
    # 2. Feed data to the model
    # 3. Compute loss (determine the diff between model prediction and actual value)
    # 4. Clear old gradients (Cleanup)
    # 5. Backpropagate Errors (Calculates the gradient)
    # 6. Update Weights (Adjusts weights based on decrease of loss -- Where the real training happens)
    # Training loop (One epoch counts as a complete pass through the entire dataset during training)
    for epoch in range(100):
        # Transition to training mode
        model.train()
        # Clear gradients
        optimizer.zero_grad()
        # Ingest data (Forward pass)
        out = model(data)
        # Loss compute
        loss = F.cross_entropy(out, data.y)
        # Backpropagation
        loss.backward()
        # Update weights
        optimizer.step()
        # Print computed loss per pass
        if epoch % 10 == 0:
            print(f"Epoch = {epoch}, Loss = {loss.item()}")
    return model

# Function to save the model
def save_model(model, mean, std, filename, in_feat: int):
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "mean": mean,
        "std": std,
        "in_feat": in_feat,
        "hidden": 16,
        "out": 2
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
def evaluate(model, data,mean,std):
    data.x = normalize(data.x_raw, mean, std) # Normalize nodes
    model.eval() # Put model into eval mode
    
    out = model(data)
    
    # Predict selection based on raw scores provided above
    pred = out.argmax(dim=1)
    
    # Get accuracy rating
    acc = (pred == data.y).sum().item() / len(data.y)
    return acc

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
        acc = evaluate(model, test_data, mean, std)
        print("Calculated accuracy:", acc)
        return acc