import json
import math
import re
import torch
from collections import defaultdict
from torch_geometric.data import Data
from torch_geometric.utils import degree

# Suspicious patterns matched against npm install scripts
SUSPICIOUS_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\bcurl\b.*\|\s*(bash|sh)\b",
    r"\bwget\b.*\.(exe|sh|bin)\b",
    r"\beval\s*\(",
    r"Buffer\.from\s*\(",
    r"\bprintenv\b",
    r"http[s]?://",
    r"eval\s*\(\s*atob\s*\(",
    r"require\s*\(\s*['\"]child_process",
]

# Calculate randomness/unpredictability of a string for obfuscation
def obfuscate(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)

# Converting string to dict with some error handling
def convert_str_to_dict(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            result = json.loads(value)
            return result if isinstance(result, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}

# Feature extractors
def script_features(pkg: dict) -> list:
    # Function mainly used to determine how malicious a script can be from the package data
    scripts = pkg.get("scripts") or {}
    if not isinstance(scripts, dict):
        scripts = {}

    keys = set(scripts.keys())
    vals = [str(v) for v in scripts.values()]
    joined = "\n".join(vals)
    joined_lower = joined.lower()

    # Simply already having an install script is pretty sus since most packages dont have or need em
    has_any = 1.0 if vals else 0.0
    has_install = 1.0 if "install" in keys else 0.0
    has_preinstall = 1.0 if "preinstall" in keys else 0.0
    has_postinstall = 1.0 if "postinstall" in keys else 0.0
    total_len = float(len(joined))
    log_len = math.log10(total_len + 1.0)

    # Regex match for sus patterns
    hit_count = 0.0
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, joined, flags=re.IGNORECASE):
            hit_count += 1.0

    # Additional checks for URL/obfuscation
    has_pipe_shell = 1.0 if re.search(r"\|\s*(bash|sh)\b", joined_lower) else 0.0
    has_url = 1.0 if "http://" in joined_lower or "https://" in joined_lower else 0.0
    has_base64_eval = 1.0 if re.search(
        r"eval\s*\(\s*Buffer\.from|eval\s*\(\s*atob\s*\(", joined, flags=re.IGNORECASE
    ) else 0.0
    install_hook_count = float(sum(
        1 for h in ("preinstall", "install", "postinstall") if h in keys
    ))

    return [
        has_any, has_install, has_preinstall, has_postinstall,
        log_len, hit_count, has_pipe_shell, has_url,
        has_base64_eval, install_hook_count,
    ]

def name_shape_features(name: str) -> list:
    # Function to check for how sus the package name is for typosquat attacks
    name = name or ""
    return [
        1.0 if name.startswith("@") else 0.0,
        float(len(name)),
        float(sum(c.isdigit() for c in name)),
        float(name.count("-")),
        float(name.count("_")),
    ]

def extended_features(pkg: dict) -> list:
    # Other sus factors that should be checked 
    # some factors dont automatically give malicious vibes but still count towards being sus
    is_deprecated       = 1.0 if pkg.get("is_deprecated", False) else 0.0
    dist = convert_str_to_dict(pkg.get("dist"))
    dist_file_count_log = math.log10(float(dist.get("fileCount", 0) or 0) + 1.0)
    dist_size_log       = math.log10(float(dist.get("unpackedSize", 0) or 0) + 1.0)
    has_repository = 1.0 if convert_str_to_dict(pkg.get("repository")) else 0.0
    has_homepage   = 1.0 if (pkg.get("homepage") or "") else 0.0

    version_str = str(pkg.get("version") or "0.0.0")
    try:
        parts = version_str.split(".")
        major = int(parts[0])
        patch = int(parts[2]) if len(parts) >= 3 else 0
    except (ValueError, IndexError):
        major, patch = 0, 0

    is_early_version = 1.0 if major == 0 else 0.0
    is_patch_bump    = 1.0 if (patch > 0 and major == 0) else 0.0
    has_author       = 1.0 if pkg.get("author") else 0.0
    has_npm_user     = 1.0 if pkg.get("_npmUser") else 0.0

    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else convert_str_to_dict(pkg.get("scripts"))
    if not scripts:
        scripts = {}
    hook_entropies = [
        obfuscate(str(scripts[h]))
        for h in ("preinstall", "install", "postinstall")
        if h in scripts and scripts[h]
    ]
    avg_script_entropy = sum(hook_entropies) / len(hook_entropies) if hook_entropies else 0.0

    return [
        is_deprecated, dist_file_count_log, dist_size_log,
        has_repository, has_homepage,
        is_early_version, is_patch_bump,
        has_author, has_npm_user, avg_script_entropy,
    ]

# Graph construction
def build_graph(pkgs_json, m_pkgs_json):
    # Builds a PyTorch Geometric Data object from benign and malicious package dicts.

    # Node features (34 per node):
    # 5 basic:          log_weekly, dep_count, maint_count, maint_single, desc_len
    # 10 script:        script_features()
    # 5 name_shape:     name_shape_features()
    # 10 extended:      extended_features()
    # 4 graph-struct:   degree, neigh_mean_weekly, neigh_min_weekly, neigh_max_weekly
    # Edges: DEPENDS_ON - package dependency edges (bidirectional)

    nodes = list(pkgs_json.keys()) + list(m_pkgs_json.keys())
    ids   = {node_key: i for i, node_key in enumerate(nodes)}

    # Reverse index: bare package name, all node keys that represent it.
    # Handles both name-only keys ("lodash") and versioned keys ("lodash@4.17.21")
    # so dependency resolution should work correctly when multiple versions coexist.
    name_to_keys: dict = defaultdict(list)
    for node_key in nodes:
        pkg = pkgs_json.get(node_key) or m_pkgs_json.get(node_key)
        bare = (pkg.get("name") if pkg else None) or node_key.split("@")[0]
        name_to_keys[bare].append(node_key)

    # Step 1: Dependency edges
    edges = []
    def add_edges(src_map):
        for node_key, pkg in src_map.items():
            for dep_name in pkg.get("dependencies", []):
                for dep_key in name_to_keys.get(dep_name, []):
                    if dep_key != node_key:
                        edges.append((ids[node_key], ids[dep_key]))
                        edges.append((ids[dep_key], ids[node_key]))
    add_edges(pkgs_json)
    add_edges(m_pkgs_json)

    # Step 2: Labels
    y = torch.zeros(len(nodes), dtype=torch.long)
    for m_pkg in m_pkgs_json.keys():
        y[ids[m_pkg]] = 1

    # Step 3: Per-node feature vectors
    neighbors: list[list] = [[] for _ in range(len(nodes))]
    for s, t in edges:
        neighbors[s].append(t)

    feats = []
    for node_key in nodes:
        pkg = pkgs_json.get(node_key) or m_pkgs_json.get(node_key)
        # Currently using "React" for single packages. If there's 2 versions, we use Reactv2.0.1 as a fallback
        bare_name = (pkg.get("name") if pkg else None) or node_key.split("@")[0]
        weekly    = float(pkg.get("weekly_downloads", 0.0))
        dep_count = float(pkg.get("dependency_count", len(pkg.get("dependencies", []))))
        log_weekly = math.log10(weekly + 1.0)
        maintainers  = pkg.get("maintainers", [])
        maint_count  = float(len(maintainers)) if isinstance(maintainers, list) else 0.0
        maint_single = 1.0 if maint_count == 1.0 else 0.0
        desc     = pkg.get("description") or ""
        desc_len = math.log10(len(desc) + 1.0)

        f = [log_weekly, dep_count, maint_count, maint_single, desc_len]
        f += script_features(pkg)
        f += name_shape_features(bare_name)
        f += extended_features(pkg)
        feats.append(f)

    # Convert to tensor
    x_raw = torch.tensor(feats, dtype=torch.float)

    # Step 4: Graph-structure features
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t()
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)

    # Create degree #of edges connected to node
    deg = degree(edge_index[0], num_nodes=len(nodes)).view(-1, 1)

    # aggregating neihboring features together
    neigh_mean_list, neigh_min_list, neigh_max_list = [], [], []

    # look through each direct neihbor and calc the mean, min, max of number of direct nodes
    for i in range(len(nodes)):
        nbrs = neighbors[i]
        if not nbrs:
            neigh_mean_list.append([0.0])
            neigh_min_list.append([0.0])
            neigh_max_list.append([0.0])
        else:
            vals = x_raw[nbrs, 0]
            neigh_mean_list.append([float(vals.mean())])
            neigh_min_list.append([float(vals.min())])
            neigh_max_list.append([float(vals.max())])

    # Convert it to tensor
    neigh_mean = torch.tensor(neigh_mean_list, dtype=torch.float)
    neigh_min  = torch.tensor(neigh_min_list,  dtype=torch.float)
    neigh_max  = torch.tensor(neigh_max_list,  dtype=torch.float)

    # Add it to the table
    # The reason for this aggregation is to create context/vibe of the neihborhood of a node to further calculate its score
    x_raw = torch.cat([x_raw, deg, neigh_mean, neigh_min, neigh_max], dim=1)

    data = Data(edge_index=edge_index, y=y)
    data.x_raw = x_raw
    # list of node keys in the same order as x_raw rows
    data.node_names = nodes
    return data
