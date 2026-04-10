import importlib
import json
from pathlib import Path
from model.build_graph import script_features, build_graph
from model.model import train_model, GCN
import torch
import random
from helpers import create_dataset

# Import model and init constants
app = importlib.import_module("model.model")

MODEL = Path("gnn_model.pt")
MODEL_NAME = "gnn_model.pt"

# Verify dependency edges are inserted bidirectionally into the graph
def test_edges_are_bidirectional():
    benign = {
        "A": {"dependencies": ["B"], "weekly_downloads": 10},
        "B": {"dependencies": [], "weekly_downloads": 10}
    }
    data = build_graph(benign, {})
    edges = data.edge_index.T.tolist()
    assert [0,1] in edges
    assert [1,0] in edges

# Ensure isolated nodes still produce valid feature vectors
def test_isolated_node_features():
    benign = {"solo": {"dependencies": [], "weekly_downloads": 5}}
    data = build_graph(benign, {})
    assert data.x_raw.shape[0] == 1

# Confirm install script detection flags are generated correctly
def test_script_detection():
    pkg = {"scripts": {"install": "node setup.js"}}
    feats = script_features(pkg)
    assert feats[0] == 1.0 # has_any
    assert feats[1] == 1.0 # has_install

# Ensure missing script fields do not crash feature extraction
def test_script_missing_safe():
    pkg = {}
    feats = script_features(pkg)
    assert isinstance(feats, list)

# Validate model input layer matches graph feature dimension (How many features there are)
def test_model_input_dimension():
    benign = {"A": {"dependencies": [], "weekly_downloads": 10}}
    data = build_graph(benign, {})
    model = GCN(data.x_raw.shape[1], 16, 2)
    assert model.conv1.lin.weight.shape[1] == data.x_raw.shape[1]

# Verify empty datasets do not crash graph construction
def test_empty_dataset():
    data = build_graph({}, {})
    assert data.x_raw.shape[0] == 0

# Confirm training loop executes successfully without runtime errors
def test_training_runs_without_crash():
    torch.manual_seed(42)
    benign = {"A": {"dependencies": [], "weekly_downloads": 10}}
    data = build_graph(benign, {})
    mean = data.x_raw.mean(dim=0, keepdim=True)
    std = data.x_raw.std(dim=0, keepdim=True) + 1e-6
    model = train_model(data, mean, std)
    assert model is not None

# Ensure different scripts produce different feature vectors
def test_script_changes_feature_vector():
    benign = {"scripts": {"install": "node setup.js"}}
    suspicious = {"scripts": {"install": "node -e 'abcdefg'"}}
    f1 = script_features(benign)
    f2 = script_features(suspicious)
    assert f1 != f2

# Verify benign nodes get label 0 and malicious nodes get label 1
def test_labels_assigned_correctly():
    benign = {"safe-pkg": {"dependencies": [], "weekly_downloads": 100}}
    malicious = {"evil-pkg": {"dependencies": [], "weekly_downloads": 1}}
    data = build_graph(benign, malicious)
    labels = data.y.tolist()
    assert 0 in labels, "Expected at least one benign label (0)"
    assert 1 in labels, "Expected at least one malicious label (1)"

# Verify that a graph with only benign packages contains no malicious labels
def test_all_benign_labels():
    benign = {
        "b-a": {"dependencies": [], "weekly_downloads": 100},
        "b-b": {"dependencies": [], "weekly_downloads": 101},
    }
    data = build_graph(benign, {})
    assert all(lbl == 0 for lbl in data.y.tolist()), "All labels should be benign (0)"


# Verify that a graph with only malicious packages contains no benign labels
def test_all_malicious_labels():
    malicious = {
        "m-a": {"dependencies": [], "weekly_downloads": 1},
        "m-b": {"dependencies": [], "weekly_downloads": 2},
    }
    data = build_graph({}, malicious)
    assert all(lbl == 1 for lbl in data.y.tolist()), "All labels should be malicious (1)"

# Final test verifying training and evaluation accuracy threshold
def test_final_accuracy():
    # Remove the model if exists
    if MODEL.exists():
        MODEL.unlink()

    torch.manual_seed(42)
    random.seed(42)

    # Load DB benign data for a realistic training/evaluation scenario
    with open("./samples/benign/db_benign.json") as f:
        all_benign = json.load(f)

    # Use a subset for faster testing while still being representative
    keys = list(all_benign.keys())
    random.shuffle(keys)
    train_keys = keys[:200]
    test_keys = keys[200:300]

    train_benign = {k: all_benign[k] for k in train_keys}
    test_benign = {k: all_benign[k] for k in test_keys}

    # Generate malicious data for training
    random.seed(42)
    train_malicious = create_dataset(train_benign, len(train_benign))

    # Test model training
    app.run_model(
        True,
        MODEL_NAME,
        train_benign,
        train_malicious,
    )
    assert MODEL.exists(), "Training did not create a model"

    # Test model evaluation with fresh attack simulations on held-out benign data
    random.seed(99)
    eval_malicious = create_dataset(test_benign, len(test_benign))
    result = app.run_model(
        False,
        MODEL_NAME,
        test_benign,
        eval_malicious,
    )

    acc = result["accuracy"] if isinstance(result, dict) else result
    assert isinstance(acc, (float, int)), "The accuracy score must be a number"
    assert float(acc) >= 0.65, f"Expected accuracy >= 0.65, got {acc}"
