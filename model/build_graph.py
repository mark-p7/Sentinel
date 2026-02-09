import math
import re
import torch
from torch_geometric.data import Data
from torch_geometric.utils import degree

# Sus patterns that can be regex matched against npm install scripts
SUSPICIOUS_PATTERNS = [
    r"\brm\s+-rf\b",                  # destructive delete commands
    r"\bcurl\b.*\|\s*(bash|sh)\b",    # remote download piped into shell
    r"\bwget\b.*\.(exe|sh|bin)\b",    # downloading executables
    r"\beval\s*\(",                   # runtime code execution
    r"Buffer\.from\(",                # potential encoded payload execution
    r"\bprintenv\b",                  # environment exfiltration
    r"http[s]?://",                   # external network activity
]

# Create features for npm install scripts
def script_features(pkg: dict):
    # Get scripts
    scripts = pkg.get("scripts") or {}

    # Ensure scripts is a dict
    if not isinstance(scripts, dict):
        scripts = {}

    # Collect script names and contents
    keys = set(scripts.keys())
    vals = [str(v) for v in scripts.values()]
    joined = "\n".join(vals)
    joined_lower = joined.lower()

    # Create feat flags
    has_any = 1.0 if len(vals) else 0.0
    has_install = 1.0 if "install" in keys else 0.0
    has_preinstall = 1.0 if "preinstall" in keys else 0.0
    has_postinstall = 1.0 if "postinstall" in keys else 0.0
    total_len = float(len(joined))
    log_len = math.log10(total_len + 1.0)

    # Count sus pattern matches
    hit_count = 0.0
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, joined, flags=re.IGNORECASE):
            hit_count += 1.0

    # Additional heuristics
    has_pipe_shell = 1.0 if re.search(r"\|\s*(bash|sh)\b", joined_lower) else 0.0
    has_url = 1.0 if "http://" in joined_lower or "https://" in joined_lower else 0.0

    # Return feature vector
    return [
        has_any,
        has_install,
        has_preinstall,
        has_postinstall,
        log_len,
        hit_count,
        has_pipe_shell,
        has_url,
    ]

# Create features for typosquatting/sus naming
def name_shape_features(name: str):
    name = name or ""
    has_scope = 1.0 if name.startswith("@") else 0.0
    name_length = float(len(name))
    digit_count = float(sum(c.isdigit() for c in name))
    hyphen_count = float(name.count("-"))
    underscore_count = float(name.count("_"))
    return [
        has_scope,
        name_length,
        digit_count,
        hyphen_count,
        underscore_count,
    ]

# Function to build graph (pytorch data object) from packages json data
def build_graph(pkgs_json, m_pkgs_json):
    # Build nodes
    nodes = list(pkgs_json.keys()) + list(m_pkgs_json.keys())
    ids = {pkg_name: i for i, pkg_name in enumerate(nodes)}

    # Build edges
    edges = []

    def add_edges(src_map):
        for pkg_name, pkg in src_map.items():
            # For each dependency, create graph edge
            for dep in pkg.get("dependencies", []):
                if dep in ids:
                    edges.append((ids[pkg_name], ids[dep]))
                    edges.append((ids[dep], ids[pkg_name]))

    # Add edges for both benign and malicious sets
    add_edges(pkgs_json)
    add_edges(m_pkgs_json)

    # Convert edge list into PyTorch tensor
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t()
    else:
        # If no edges exist, create empty edge tensor
        edge_index = torch.empty((2, 0), dtype=torch.long)

    # Create node labels
    # 0 = benign
    # 1 = malicious
    y = torch.zeros(len(nodes), dtype=torch.long)
    for m_pkg in m_pkgs_json.keys():
        y[ids[m_pkg]] = 1

    # Build features
    feats = []
    for name in nodes:
        # Get package metadata
        pkg = pkgs_json.get(name) or m_pkgs_json.get(name)

        # Basic numerical features
        weekly = float(pkg.get("weekly_downloads", 0.0))
        dep_count = float(pkg.get("dependency_count",
                                  len(pkg.get("dependencies", []))))

        # Log scaling reduces magnitude differences
        log_weekly = math.log10(weekly + 1.0)

        # Maintainer feature (Will build upon this more later, but for now, if only 1 maintainer then that counts as a point toward m over b)
        maintainers = pkg.get("maintainers", [])
        maint_count = float(len(maintainers)) if isinstance(maintainers, list) else 0.0
        maint_single = 1.0 if maint_count == 1.0 else 0.0

        # Description length heuristic (avoid stuff like empty/short descriptions)
        desc = pkg.get("description") or ""
        desc_len = math.log10(len(desc) + 1.0)

        # Create features list
        f = []
        f += [log_weekly, dep_count, maint_count, maint_single, desc_len]
        f += script_features(pkg)
        f += name_shape_features(name)
        feats.append(f)

    # Convert feature list into tensor
    x_raw = torch.tensor(feats, dtype=torch.float)

    # Add graph-structure features
    # Degree (number of edges connected to the node)
    deg = degree(edge_index[0], num_nodes=len(nodes)).view(-1, 1)

    # Compute neighbor stats
    neighbors = [[] for _ in range(len(nodes))]
    for s, t in edges:
        neighbors[s].append(t)

    neigh_mean = []
    neigh_min = []
    for i in range(len(nodes)):
        # If node has no neighbors
        if not neighbors[i]:
            neigh_mean.append([0.0])
            neigh_min.append([0.0])
            continue
        # only account for log_weekly feature for now
        vals = x_raw[neighbors[i], 0]
        neigh_mean.append([float(vals.mean().item())])
        neigh_min.append([float(vals.min().item())])

    neigh_mean = torch.tensor(neigh_mean, dtype=torch.float)
    neigh_min = torch.tensor(neigh_min, dtype=torch.float)
    x_raw = torch.cat([x_raw, deg, neigh_mean, neigh_min], dim=1)

    # Create PyG Data object
    data = Data(edge_index=edge_index, y=y)

    # Store raw features (normalize later)
    data.x_raw = x_raw

    return data
