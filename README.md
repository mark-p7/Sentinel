# Sentinel
A GNN Based NPM Supply Chain Attack Detection Tool

Mark De Guzman<br>
British Columbia Institute of Technology (BCIT)<br>
October 10th, 2025<br>

## Steps To Run:
NOTE: First make sure you are within the current directory

1. Create python environment:<br>
`python3 -m venv .venv`

1. Start python environment:<br>
`source .venv/bin/activate`

1. Install packages<br>
`pip install -r requirements.txt`

1. Run Program<br>
- Option 1 (Train the model):<br>
`python app.py -t`

- Option 2 (Evaluate the model):<br>
`python app.py -e`

## What the prototype does

The prototype uses the datasets within the current directory to help either train a new model or evaluate an existing model.
The model is named "gnn_model.pt" and is created/loaded within the current directory.

These are the artifical data samples that will be used within this prototype (all are within the current directory):
- [NPM packages sample data for training (train_benign.json)](./samples/train_benign.json)
- [Malicious NPM package sample data for training (train_malicious.json)](./samples/train_malicious.json)
- [NPM package sample data for evaluation (test_benign.json)](./samples/test_benign.json)
- [Malicious NPM package sample data for evaluation (test_malicious.json)](./samples/test_malicious.json)

## Output

### Training
<pre>
Training model
Epoch = 0, Loss = 0.7774453163146973
Epoch = 10, Loss = 0.544178307056427
Epoch = 20, Loss = 0.45122388005256653
Epoch = 30, Loss = 0.4503107964992523
Epoch = 40, Loss = 0.41077545285224915
Epoch = 50, Loss = 0.4083067774772644
Epoch = 60, Loss = 0.4220380485057831
Epoch = 70, Loss = 0.40408775210380554
Epoch = 80, Loss = 0.4153529405593872
Epoch = 90, Loss = 0.40803200006484985
Model trained and saved to 'gnn_model.pt'.
</pre>

This output represents the loss compute during each training pass. Decreasing loss compute means that the model is actually learning.<br>
Model is then saved in the "gnn_model.pt" file within the current directory <br>

### Evaluating

<pre>
Evaluating model
Calculated accuracy: 0.972972972972973
</pre>

The calculated accuracy is the representation of how many classifications the model was able to get right for each node when determining whether it was benign or malicious.

## How the GNN prototype works
There are 5 main sections in how the current prototype works.
1. Building the graph
2. Create/Apply normalizer
3. Train model
4. Evaluate model
5. Save/Load model

Building the graph means that we take in the sample json data and convert it into a graph with nodes and edges for the GNN to consume.
I'm using pytorch since it's a well known AI/ML library to help with this. It let's us create a dictionary-like object that holds node-level,
link-level, and graph-level attributes. It's useful for storing our newly created tensors (multi-dimensional array of values for efficient computing).

With the new data, I want to be able to normalize it. Normalizing data adds uniformity and normalization to the data. This helps make sure that when new data comes, they follow a consistent rule/format/data structure. "fit_normalizer" helps to determine how the data should be normalized and "normalize" helps to apply the normalizer to the data.

Training the model is self explanatory. Based on the labels previously provided when building the initial graph of the 2 data samples, this function is where the model will learn to adjust and differentiate the difference between benign and malicious data. Important to note that we can watch the loss compute through each training pass to keep track of whether it’s actually learning or not. Loss compute is just the difference between the model prediction and the actual value. If the difference goes down overtime, it's a good indicator of proper training.

Evaluating the model is also self explanatory. Here, the model is given new data samples and the model is tasked to identify malicious and benign packages. The data samples have also been normalized to the same extent as the training data as well within the evaluate function. It returns an accuracy score at the end that determines how accurate it was at classifying the different nodes as either benign or malicious.

Save/Load model is just saving the model after training and loading it back when either training or evaluating. This is good for continued training on existing models so that we don't sped time having to retrain everything from scratch. It's also good for letting others evaluate data sets with your saved model.

## Diagram

![Prototype Diagram](PrototypeDiagram.png)
