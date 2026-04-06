# TODO: I included this warning supression to silence urllib3 warning. I need to find a cleaner fix.
import warnings
warnings.filterwarnings("ignore", message=".*urllib3 v2 only supports OpenSSL 1.1.1+.*")

import json
import subprocess
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from data_crawler import run_data_crawler, run_data_crawler_single_package
from db import DataStorage
from helpers import create_dataset, simulate_coordinated_dependency_injection, simulate_coordinated_maintainer_compromise, simulate_coordinated_script_injection
from model.model import run_model

BANNER = """\
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
  """

# Directories
SAMPLES_DIR = Path("samples")
BENIGN_DIR = SAMPLES_DIR / "benign"
MALICIOUS_DIR = SAMPLES_DIR / "malicious"
RESULTS_DIR = Path("results")
MODEL_PATH = "gnn_model.pt"

console = Console()

# Helpers
def print_banner():
    console.print()
    console.print(Text(BANNER, style="bold blue_violet"))
    console.print(Text("NPM Supply-Chain Threat Detection", style="dim"))
    console.print()

def print_separator(title = ""):
    if title:
        console.print(Rule(f"[bold]{title}[/bold]", style="blue_violet"))
    else:
        console.print(Rule(style="dim"))

def success(msg):
    console.print(f"[bold green]\[Success][/bold green]  {msg}")

def error(msg):
    console.print(f"[bold red]\[Error][/bold red]  {msg}")

def info(msg):
    console.print(f"[bold blue]\[Info][/bold blue]  {msg}")

def warn(msg):
    console.print(f"[bold yellow]\[Warn][/bold yellow]  {msg}")

def load_json_file(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        error(f"File not found: [bold]{path}[/bold]")
        return None
    except json.JSONDecodeError as e:
        error(f"Invalid JSON in [bold]{path}[/bold]: {e}")
        return None

def save_json_file(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    success(f"Saved to [bold]{path}[/bold]")

def timestamped_path(prefix, subdir: Path = MALICIOUS_DIR, suffix = ".json"):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(subdir / f"{prefix}_{ts}{suffix}")

def get_pkg_count(path):
    try:
        with open(path) as f:
            data = json.load(f)
        return f"[dim]({len(data)} pkgs)[/dim]"
    except Exception:
        return ""

def pick_json_file(prompt_title, priority_dirs, fallback_dir, fallback_glob, allow_skip = False):
    # list of (display_label, full_path)
    entries = []

    #Shows the json files in the sample directory
    for search_dir in priority_dirs:
        p = Path(search_dir)
        if p.exists():
            found = sorted(p.glob("*.json"))
            if found:
                entries.append((f"[bold dim]-- {p}/ --[/bold dim]", None))  # section header
                for f in found:
                    entries.append((f.name, str(f)))

    # Fallback
    if fallback_dir.exists():
        legacy = sorted(fallback_dir.glob(fallback_glob))
        if legacy:
            entries.append((f"[bold dim]-- {fallback_dir}/ (legacy) --[/bold dim]", None))
            for f in legacy:
                entries.append((f.name, str(f)))

    # Build numbered list (skip headers)
    items = [(label, path) for label, path in entries if path is not None]

    console.print()
    console.print(f"[bold]{prompt_title}[/bold]")
    console.print()

    if not items:
        return Prompt.ask("Path", default="")

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="bold blue_violet", no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(justify="right")

    item_idx = 0
    for label, path in entries:
        if path is None:
            # Section header - span columns visually
            table.add_row("", label, "")
        else:
            item_idx += 1
            table.add_row(str(item_idx), label, get_pkg_count(path))

    table.add_row("m", "Enter path manually", "")
    if allow_skip:
        table.add_row("s", "[dim]Skip (none)[/dim]", "")

    console.print(table)

    valid = [str(i) for i in range(1, len(items) + 1)] + ["m"]
    if allow_skip:
        valid.append("s")

    choice = Prompt.ask("Select", choices=valid)

    if choice == "s":
        return None
    if choice == "m":
        return Prompt.ask("File path")
    return items[int(choice) - 1][1]

# Data Collection
def run_data_collection():
    print_separator("Data Collection")
    console.print()

    packages_file = Prompt.ask(
        "Path to packages list file",
        default="samples/top1000packages.txt",
    )
    if not Path(packages_file).exists():
        error(f"File [bold]{packages_file}[/bold] does not exist.")
        return

    set_verbosity = Confirm.ask("Enable Logging?", default=False)

    console.print()
    info("Starting crawler — press [bold]Ctrl+C[/bold] at any time to stop.")
    console.print()

    try:
        run_data_crawler(packages_file, set_verbosity)
    except KeyboardInterrupt:
        console.print()
        warn("Collection stopped by user.")
        return
    except Exception as e:
        warn(f"Crawler exited with code {e}.")

    console.print()
    success("Data collection completed.")


# Model Training
def run_training():
    print_separator("Train Model")
    console.print()

    source_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    source_table.add_column(style="bold blue_violet")
    source_table.add_column()
    source_table.add_row("1", "Use sample files")
    source_table.add_row("2", "Use real database data  [dim](requires Neo4j + Redis)[/dim]")
    console.print(source_table)

    choice = Prompt.ask("Select data source", choices=["1", "2"], default="1")
    console.print()

    if choice == "1":
        benign_path = pick_json_file(
            "Benign training file",
            priority_dirs=[BENIGN_DIR],
            fallback_dir=SAMPLES_DIR,
            fallback_glob="*benign*.json",
        )
        if not benign_path:
            return
        malicious_path = pick_json_file(
            "Malicious training file",
            priority_dirs=[MALICIOUS_DIR],
            fallback_dir=SAMPLES_DIR,
            fallback_glob="*malicious*.json",
        )
        if not malicious_path:
            return

        benign = load_json_file(benign_path)
        malicious = load_json_file(malicious_path)
        if benign is None or malicious is None:
            return
    else:
        info("Connecting to database...")
        ds = DataStorage()
        if not ds.verify_connection():
            error("Could not connect to the database. Is Neo4j running?")
            return

        info("Fetching packages from database...")
        benign = ds.get_all_packages()
        info(f"Retrieved [bold]{len(benign)}[/bold] packages.")
        malicious = create_dataset(benign, len(benign))

        if Confirm.ask("Save generated data to samples directory?", default=False):
            save_json_file(str(BENIGN_DIR / "db_benign.json"), benign)
            save_json_file(str(MALICIOUS_DIR / "db_malicious.json"), malicious)

    console.print()
    info(f"Training on [bold]{len(benign)}[/bold] benign + [bold]{len(malicious)}[/bold] malicious packages...")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Training GNN...", total=None)
        run_model(True, MODEL_PATH, benign, malicious)
        progress.update(task, completed=True)

    console.print()
    success(f"Model trained and saved to [bold]{MODEL_PATH}[/bold].")


# Model Evaluation
def run_evaluation():
    print_separator("Evaluate Model")
    console.print()

    if not Path(MODEL_PATH).exists():
        error(f"No trained model found at [bold]{MODEL_PATH}[/bold]. Please train and generate the model first.")
        return

    benign_path = pick_json_file(
        "Select benign samples",
        priority_dirs=[BENIGN_DIR],
        fallback_dir=SAMPLES_DIR,
        fallback_glob="*benign*.json",
    )
    if not benign_path:
        return
    benign = load_json_file(benign_path)
    if benign is None:
        return

    malicious_path = pick_json_file(
        "Select malicious samples  [dim](or skip to evaluate benign-only)[/dim]",
        priority_dirs=[MALICIOUS_DIR],
        fallback_dir=SAMPLES_DIR,
        fallback_glob="*malicious*.json",
        allow_skip=True,
    )
    malicious = {}
    if malicious_path:
        loaded = load_json_file(malicious_path)
        if loaded is not None:
            malicious = loaded

    console.print()
    info(
        f"Evaluating [bold]{len(benign)}[/bold] benign + "
        f"[bold]{len(malicious)}[/bold] malicious packages..."
    )
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running evaluation...", total=None)
        acc = run_model(False, MODEL_PATH, benign, malicious)
        progress.update(task, completed=True)

    console.print()

    if acc is None:
        warn("Evaluation completed but no accuracy was returned.")
        return

    accuracy_value = acc.get("accuracy", 0)
    final_overall_acc = float(accuracy_value) * 100
    tp = acc.get("tp", 0)
    tn = acc.get("tn", 0)
    fp = acc.get("fp", 0)
    fn = acc.get("fn", 0)
    color = "green" if final_overall_acc >= 80 else ("yellow" if final_overall_acc >= 65 else "red")

    result_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    result_table.add_column(style="bold", width=36)
    result_table.add_column(justify="right")

    # Overall Accuracy
    result_table.add_row("Accuracy (overall correct)", f"[bold {color}]{final_overall_acc:.1f}%[/bold {color}]")
    result_table.add_row("", "")

    # In-depth eval accuracy results
    # Model guessed malicious and it was malicious
    result_table.add_row("TP (M:M)", f"[green]{tp}[/green]")
    # Model guessed benign and it was benign
    result_table.add_row("TN (B:B)", f"[green]{tn}[/green]")
    # Model guessed malicious and it was benign
    result_table.add_row("FP (M:B)", f"[red]{fp}[/red]")
    # Model guessed benign and it was malicious
    result_table.add_row("FN (B:M)", f"[red]{fn}[/red]")
    result_table.add_row("","")

    # Additional info
    result_table.add_row("Benign packages", str(len(benign)))
    result_table.add_row("Malicious packages", str(len(malicious)))
    result_table.add_row("Benign file", benign_path or "—")
    result_table.add_row("Malicious file", malicious_path or "—")
    result_table.add_row("Model", MODEL_PATH)

    console.print(Panel(result_table, title="[bold]Evaluation Results[/bold]", border_style="blue_violet"))

# Attack Simulation
def load_src_pkgs():
    path = pick_json_file(
        "Source benign packages",
        priority_dirs=[BENIGN_DIR],
        fallback_dir=SAMPLES_DIR,
        fallback_glob="*benign*.json",
    )
    if not path:
        return None
    return load_json_file(path)

# Func to show a preview table of the generated attack packages
def show_atk_preview(result, attack_label):
    console.print()
    preview = Table(
        title=f"[bold]{attack_label}[/bold] — Generated Packages",
        box=box.ROUNDED,
        show_lines=False,
        padding=(0, 1),
    )
    preview.add_column("Package", style="blue_violet", no_wrap=True, max_width=28)
    preview.add_column("Version", style="dim",  no_wrap=True)
    preview.add_column("Maintainers", style="yellow", max_width=22)
    preview.add_column("Install Hook", style="red",  max_width=45)

    for pkg_name, pkg in list(result.items())[:10]:
        scripts = pkg.get("scripts") or {}
        hooks = {k: v for k, v in scripts.items() if k in ("preinstall", "install", "postinstall")}
        hook_str = " | ".join(f"{k}: {str(v)[:28]}..." for k, v in hooks.items()) if hooks else "—"
        maints = pkg.get("maintainers", [])
        if isinstance(maints, list):
            maint_str = ", ".join(
                m.get("name", str(m)) if isinstance(m, dict) else str(m)
                for m in maints[:2]
            )
        else:
            maint_str = "—"
        preview.add_row(pkg_name, str(pkg.get("version", "?")), maint_str, hook_str)

    if len(result) > 10:
        preview.add_row("...", f"(+{len(result)-10} more)", "", "")

    console.print(preview)

def attack_maintainer_compromise():
    print_separator("Attack: Maintainer Compromise")
    console.print()
    info("Simulates an attacker gaining control of a maintainer account and pushing malicious updates to many different packages they control at the same time.")

    packages = load_src_pkgs()
    if not packages:
        return

    attacker = Prompt.ask("Attacker account name", default="compromised_account")
    num_targets = IntPrompt.ask(
        f"Number of packages to compromise (1-{len(packages)})",
        default=min(5, len(packages)),
    )
    num_targets = max(1, min(num_targets, len(packages)))
    out_path = Prompt.ask(
        "Output file",
        default=timestamped_path("attack_maintainer"),
    )

    console.print()
    result = simulate_coordinated_maintainer_compromise(packages, num_targets, attacker)

    show_atk_preview(result, "Maintainer Compromise")
    console.print()
    save_json_file(out_path, result)
    console.print()
    info(f"Graph signal: {num_targets} packages share maintainer [bold blue_violet]{attacker}[/bold blue_violet] + identical high-entropy install scripts.")
    info("Use [bold]Evaluate Model[/bold] and select this file as the malicious input.")

def attack_dependency_injection():
    print_separator("Attack: Dependency Injection")
    console.print()
    info("Simulates a coordinated dependency injection attack where a compromised package is added/injected as a dependency.")

    packages = load_src_pkgs()
    if not packages:
        return

    dep_name = Prompt.ask(
        "Malicious dependency name [dim](blank = auto-generate typosquat)[/dim]",
        default="",
    )
    if not dep_name:
        dep_name = None

    num_targets = IntPrompt.ask(
        f"Number of packages to inject into (1-{len(packages)})",
        default=min(5, len(packages)),
    )
    num_targets = max(1, min(num_targets, len(packages)))
    out_path = Prompt.ask(
        "Output file",
        default=timestamped_path("attack_dep_inject"),
    )

    console.print()
    result = simulate_coordinated_dependency_injection(packages, num_targets, dep_name)

    actual_dep = dep_name or next(
        (v["name"] for v in result.values() if v.get("version") == "0.0.1" and v.get("weekly_downloads", 999) < 100),
        "unknown",
    )

    show_atk_preview(result, "Dependency Injection")
    console.print()
    save_json_file(out_path, result)
    console.print()
    info(f"Graph signal: star-shaped subgraph — {num_targets} packages all gain [bold blue_violet]{actual_dep}[/bold blue_violet] simultaneously.")
    info("Use [bold]Evaluate Model[/bold] and select this file as the malicious input.")

def attack_script_injection():
    print_separator("Attack: Obfuscated Script Injection")
    console.print()
    info("Simulates an attack where the same obfuscated script is injected into many different packages at once.")

    packages = load_src_pkgs()
    if not packages:
        return

    num_targets = IntPrompt.ask(
        f"Number of packages to inject into (1-{len(packages)})",
        default=min(5, len(packages)),
    )
    num_targets = max(1, min(num_targets, len(packages)))
    out_path = Prompt.ask("Output file", default=timestamped_path("attack_script_inject"))

    console.print()
    result = simulate_coordinated_script_injection(packages, num_targets)

    show_atk_preview(result, "Script Injection")
    console.print()
    save_json_file(out_path, result)
    console.print()
    info(f"Graph signal: {num_targets} Package nodes share the same [bold red]Script node[/bold red] through [HAS_SCRIPT] edges.")
    info("Use [bold]Evaluate Model[/bold] and select this file as the malicious input.")

def run_attack_simulation():
    while True:
        print_separator("Simulate Attack")
        console.print()

        menu = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        menu.add_column(style="bold blue_violet")
        menu.add_column()
        menu.add_column(style="dim")
        menu.add_row("a", "Maintainer Compromised",   "Account takeover. Maintainer can spread malicious updates across all owned packages")
        menu.add_row("b", "Dependency Injection",      "Same malicious dep added to many packages simultaneously")
        menu.add_row("c", "Obfuscated Script Injection","Identical encoded payload injected across multiple packages")
        menu.add_row("q", "Back", "")
        console.print(menu)
        choice = Prompt.ask("Select", choices=["a", "b", "c", "q"]).lower()

        if choice == "a":
            attack_maintainer_compromise()
        elif choice == "b":
            attack_dependency_injection()
        elif choice == "c":
            attack_script_injection()
        elif choice == "q":
            return

        console.print()
        if not Confirm.ask("Run another simulation?", default=False):
            return

def start_polling():
        print_separator("Start Monitoring")
        console.print()

        package = Prompt.ask("Package to start monitoring for new changes", default="lodash")
        print(package)

        while True:
            cache_dependency_network()
            run_data_crawler_single_package(package)


# Main menu
def main_menu():
    menu = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    menu.add_column(style="bold blue_violet", width=1)
    menu.add_column()
    menu.add_column(style="dim")
    menu.add_row("1", "Run Data Collection", "Collect data from the NPM registry and store the packages in the database")
    menu.add_row("2", "Train Model",         "Train the GNN on collected or sample data")
    menu.add_row("3", "Evaluate Model",      "Evaluated the accuracy of the trained model against sample data")
    menu.add_row("4", "Simulate Attack",     "Create a coordinated attack simulation")
    menu.add_row("5", "Start Monitoring",    "Start monitoring a package for new updates within the NPM network")
    menu.add_row("q", "Quit")
    console.print(menu)

def main():
    print_banner()

    while True:
        try:
            main_menu()
            choice = Prompt.ask("\nSelect option", choices=["1", "2", "3", "4", "5", "q"]).lower()
            console.print()
            if choice == "1":
                run_data_collection()
            elif choice == "2":
                run_training()
            elif choice == "3":
                run_evaluation()
            elif choice == "4":
                run_attack_simulation()
            elif choice == "5":
                start_polling()
            elif choice == "q":
                console.print(Align.center(Text("\nGoodbye.\n", style="dim")))
                break
        except KeyboardInterrupt as e:
            print("\nEnter q to quit")
        except Exception as e:
            print(e)
            timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"./errors/error_log_{timestamp_str}.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("Error Details:\n")
                    f.write(str(e))
                print(f"Error successfully written to {filename}")
            except IOError:
                print(f"Error writing to file.")
                print(f"Printing error here:\n{e}")

        console.print()

if __name__ == "__main__":
    main()
