import sys
import json
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv

# Function to build graph (pytorch data object) from packages json data
def build_graph(pkgs_json, m_pkgs_json):
    # Create ids mapping and pkgs arr to represent nodes
    nodes = []
    ids = {}

    for pkg in pkgs_json:
        nodes.append(pkg)

    for pkg in m_pkgs_json:
        nodes.append(pkg)

    i = 0
    for pkg in nodes:
        ids[pkg] = i
        i += 1

    # Create edges mapping
    edges = []
    for pkg in pkgs_json:
        for dep in pkgs_json[pkg]["dependencies"]:
            if dep in ids:
                edges.append((ids[pkg], ids[dep]))
                edges.append((ids[dep], ids[pkg]))

    for pkg in m_pkgs_json:
        for dep in m_pkgs_json[pkg]["dependencies"]:
            if dep in ids:
                edges.append((ids[pkg], ids[dep]))
                edges.append((ids[dep], ids[pkg]))

    # Convert edges to tensor if any
    if edges:
        edge_ind = torch.tensor(edges, dtype=torch.long).T
    else:
        edge_ind = torch.empty(2, 0, dtype=torch.long).T

    # Create features (identification factors) -- TODO: Expand on this later on
    feats = []
    for node in nodes:
        pkg = pkgs_json.get(node) or m_pkgs_json.get(node)
        weekly_downloads = float(pkg["weekly_downloads"])
        dep_count = float(pkg["dependency_count"])
        feats.append([weekly_downloads, dep_count])

    # Convert features to tensor
    x_raw = torch.tensor(feats, dtype=torch.float)

    # Label nodes
    y = torch.zeros(len(nodes), dtype=torch.long)
    for m_pkg in m_pkgs_json:
        y[ids[m_pkg]] = 1  # 1 indicates malicious
    for pkg in pkgs_json:
        y[ids[pkg]] = 0  # 0 indicates non-malicious behaviour

    # Return graph object
    data = Data(edge_index=edge_ind, y=y)

    # Keep x raw for now as we want to normalize it later on
    data.x_raw = x_raw

    return data

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
def save_model(model, mean, std, filename):
    checkpoint = {"model_state_dict": model.state_dict(), "mean": mean, "std": std} # Save the model and std to use later
    torch.save(checkpoint, filename)

# Function to load the model
def load_model(filename):
    checkpoint = torch.load(filename)
    model = GCN(2, 16, 2)
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

def main():
    # Determine whether to train or evaluate model
    train = True
    if len(sys.argv) == 2:
        if sys.argv[1] == "-t" or sys.argv[1] == "--train":
            train = True
        elif sys.argv[1] == "-e" or sys.argv[1] == "--eval":
            train = False
        else:
            print("Incorrect arguments passed.\nPlease enter one of the following 2 arguments\n-t or --train to train the model\n-e or --eval to evaluate the model")
            exit(1)
    elif len(sys.argv) > 2:
        print("Too many arguments passed.\nPlease enter one of the following 2 arguments\n-t or --train to train the model\n-e or --eval to evaluate the model")
    else:
        print("Please specify whether to train or evaluate.\nPlease enter one of the following 2 arguments\n-t or --train to train the model\n-e or --eval to evaluate the model")
        exit(1)
    
    # Init data variables and constants
    train_pkgs = None
    train_m_pkgs = None
    test_pkgs = None
    test_m_pkgs = None
    model_file_name = "gnn_model.pt"
    
    # Load sample data
    if train:
        with open("./samples/train_benign.json") as f:
            train_pkgs = json.load(f)
        with open("./samples/train_malicious.json") as f:
            train_m_pkgs = json.load(f)
    else:
        with open("./samples/test_benign.json") as f:
            test_pkgs = json.load(f)
        with open("./samples/test_malicious.json") as f:
            test_m_pkgs = json.load(f)
        
    # Train
    if train:
        print("Training model")
        data = build_graph(train_pkgs, train_m_pkgs)
        mean, std = fit_normalizer(data.x_raw)
        model = train_model(data, mean, std)
        save_model(model, mean, std, model_file_name)
        print(f"Model trained and saved to '{model_file_name}'.")
    else:
        # Eval
        print("Evaluating model")
        test_data = build_graph(test_pkgs, test_m_pkgs)
        model, mean, std = load_model(model_file_name)
        acc = evaluate(model, test_data, mean, std)
        print("Calculated accuracy:", acc)

main()
