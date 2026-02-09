import importlib
import json
from pathlib import Path
from model.build_graph import script_features, build_graph
from model.model import train_model, GCN
import torch

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

# Final test verifying training and evaluation accuracy threshold
def test_final_accuracy():
    # Remove the model if exists
    if MODEL.exists():
        MODEL.unlink()
        
    # Load test data
    with open("./samples/train_benign.json") as f:
        benign_train_json_data = json.load(f)
    with open("./samples/train_malicious.json") as f:
        malicious_train_json_data = json.load(f)
    with open("./samples/test_benign.json") as f:
        benign_test_json_data = json.load(f)
    with open("./samples/test_malicious.json") as f:
        malicious_test_json_data = json.load(f)

    # Test model training
    app.run_model(
        True,
        MODEL_NAME,
        benign_train_json_data,
        malicious_train_json_data
    )
    assert MODEL.exists(), "Training did not create a model"

    # Test model evaluation results
    acc = app.run_model(
        False,
        MODEL_NAME,
        benign_test_json_data,
        malicious_test_json_data
    )
    
    assert isinstance(acc, (float, int)), "The accuracy score must be a number"
    assert float(acc) >= 0.65, f"Expected accuracy >= 0.65, got {acc}"
