import importlib
import json
from pathlib import Path

# Import model and init constants
app = importlib.import_module("model.model")

MODEL = Path("gnn_model.pt")
MODEL_NAME = "gnn_model.pt"

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
