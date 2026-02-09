import sys
import json
from db import DataStorage
from helpers import create_dataset
from model.model import run_model

def main():
    # Init model name
    model_name = "gnn_model.pt"
    
    # Determine whether to train or evaluate model (train on default)
    is_train = True
    use_real_data = False
    log_gen_pkgs = False
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--train" or arg == "-t":
            is_train = True
        elif arg == "--eval" or arg == "-e":
            is_train = False
        elif arg == "--use-real-data":
            use_real_data = True
        elif arg == "--log-generated-packages":
            log_gen_pkgs = True
        else:
            print(f"Incorrect arguments passed: {arg}\nUsage: python app.py --samples <file.txt>")
            sys.exit(1)
        i += 1
        
    # Load sample data
    benign_json_data = None
    malicious_json_data = None
    
    if is_train:
        with open("./samples/train_benign.json") as f:
            benign_json_data = json.load(f)
        with open("./samples/train_malicious.json") as f:
            malicious_json_data = json.load(f)
    else:
        with open("./samples/test_benign.json") as f:
            benign_json_data = json.load(f)
        with open("./samples/test_malicious.json") as f:
            malicious_json_data = json.load(f)
    
    if use_real_data:
        # Load data from Database
        print("Connecting to database...")
        ds = DataStorage()
        
        if not ds.verify_connection():
            print("Could not connect to the database")
            exit(1)

        # Get real world benign data
        print("Fetching data from the db")
        all_packages = ds.get_all_packages()
        print(f"Retrieved {len(all_packages)} packages")
        benign_json_data = all_packages
        
        # Get synthetic data based on real world benign data
        malicious_json_data = create_dataset(benign_json_data, len(benign_json_data))
        
        if log_gen_pkgs:
            with open("./samples/b_data.json", "w") as f:
                json.dump(benign_json_data, f, indent=4)
            with open("./samples/m_data.json", "w") as f:
                json.dump(malicious_json_data, f, indent=4)
                
    # Run model
    run_model(is_train, model_name, benign_json_data, malicious_json_data)

if __name__ == "__main__":
    main()