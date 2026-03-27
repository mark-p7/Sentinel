from neo4j import GraphDatabase
import json
import hashlib
from datetime import datetime, timezone
from helpers import node_to_package

# Neo4j -- For now only works on locally hosted database
URI = "neo4j://localhost:7687"
USER = "neo4j"
PASSWORD = "password"
DB_NAME = "neo4j"

def safe_json_loads(value, default):
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default

def hash(content):
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]

class DataStorage:
    def __init__(self):
        self.driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))

    def verify_connection(self):
        try:
            self.driver.verify_connectivity()
            print("Connection successful!")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def get_package_data(self, name, version):
        query = """
        MATCH (p:Package {name: $name, version: $version})
        RETURN p
        """
        with self.driver.session() as session:
            result = session.run(query, name=name, version=version)
            return [node_to_package(res["p"]) for res in result]

    def get_package_tree(self, name):
        query = """
        MATCH (root:Package {name: $name})
        OPTIONAL MATCH (root)-[:DEPENDS_ON*0..]->(p:Package)
        RETURN DISTINCT p
        """
        results_dict = {}

        with self.driver.session() as session:
            result = session.run(query, name=name)

            for record in result:
                node = record["p"]

                pkg_name = node.get("name")
                pkg_version = node.get("version")
                pkg_weekly_downloads = node.get("weekly_downloads")

                deps_str = node.get("dependencies", "{}")
                try:
                    deps_dict = json.loads(deps_str)
                    deps_list = list(deps_dict.keys())
                except (json.JSONDecodeError, TypeError):
                    deps_list = []

                key = f"{pkg_name}@{pkg_version}"

                results_dict[key] = {
                    "name": pkg_name,
                    "version": pkg_version,
                    "dependencies": deps_list,
                    "weekly_downloads": pkg_weekly_downloads,
                    "dependency_count": len(deps_list)
                }

        return results_dict

    def get_all_packages(self):
        query = """
        MATCH (p:Package)
        RETURN p
        """
        data = {}
        with self.driver.session() as session:
            result = session.run(query)
            for record in result:
                try:
                    node = record.get("p")
                    if node is None:
                        continue

                    name = node.get("name")
                    if not name:
                        continue

                    version = node.get("version") or "unknown"
                    deps_dict = safe_json_loads(node.get("dependencies", "{}"), {})
                    deps_list = list(deps_dict.keys()) if isinstance(deps_dict, dict) else []

                    data[f"{name}@{version}"] = {
                        "name": name,
                        "version": version,
                        "weekly_downloads": node.get("weekly_downloads", 0) or 0,
                        "dependency_count": len(deps_list),
                        "dependencies": deps_list,
                        "is_deprecated": node.get("is_deprecated", False),
                        "homepage": node.get("homepage", ""),
                        "main": node.get("main", ""),
                        "author": safe_json_loads(node.get("author"), {}),
                        "dist": safe_json_loads(node.get("dist"), {}),
                        "scripts": safe_json_loads(node.get("scripts"), {}),
                        "_npmUser": safe_json_loads(node.get("_npmUser"), {}),
                        "repository": safe_json_loads(node.get("repository"), {}),
                        "maintainers": safe_json_loads(node.get("maintainers"), []),
                        "collected_at": node.get("collected_at"),
                    }
                except Exception as e:
                    print(f"Skipping bad Package record due to error: {e}")
                    continue

        return data

    def store_node(self, data):
        try:
            name = (data.get("name") or "").strip()
            version = (data.get("version") or "").strip()

            if not name or not version:
                print("Skipping node with missing name/version: name={name} version={version}")
                return None

            props = {
                "name": name,
                "version": version,
                "homepage": data.get("homepage") or "",
                "main": data.get("main") or "",
                "weekly_downloads": data.get("weekly_downloads") or 0,
                "is_deprecated": bool(data.get("deprecated")),
                "collected_at": data.get("collected_at") or datetime.now(timezone.utc).isoformat(),
            }

            def dumps(x, fallback):
                try:
                    return json.dumps(x if x is not None else fallback, default=str)
                except Exception:
                    return json.dumps(fallback)

            props.update({
                "author": dumps(data.get("author"), {}),
                "dist": dumps(data.get("dist"), {}),
                "scripts": dumps(data.get("scripts"), {}),
                "_npmUser": dumps(data.get("_npmUser"), {}),
                "repository": dumps(data.get("repository"), {}),
                "dependencies": dumps(data.get("dependencies"), {}),
                "maintainers": dumps(data.get("maintainers"), []),
            })

            query = """
            MERGE (p:Package {name: $name, version: $version})
            SET p += $props
            RETURN p
            """

            with self.driver.session() as session:
                record = session.run(query, name=name, version=version, props=props).single()
                pkg_node = record["p"] if record else None

            # Create and link Maintainer nodes
            maintainers = safe_json_loads(data.get("maintainers"), [])
            if isinstance(maintainers, list):
                for m in maintainers:
                    if isinstance(m, dict):
                        m_name = m.get("name", "")
                        m_email = m.get("email", "")
                    else:
                        m_name = str(m)
                        m_email = ""
                    if m_name:
                        self.store_maintainer_node(m_name, m_email)
                        self.link_maintainer_to_package(m_name, name)

            # Create and link Script nodes for install hooks
            scripts = safe_json_loads(data.get("scripts"), {})
            if isinstance(scripts, dict):
                for hook in ("preinstall", "install", "postinstall"):
                    content = scripts.get(hook)
                    if content:
                        self.store_script_node(str(content), hook)
                        self.link_script_to_package(str(content), name)

            return pkg_node

        except Exception as e:
            print(f"store_node failed. skipping. Error: {e}")
            return None

    def store_maintainer_node(self, name, email = ""):
        query = """
        MERGE (m:Maintainer {name: $name})
        SET m.email = $email
        RETURN m
        """
        try:
            with self.driver.session() as session:
                session.run(query, name=name, email=email)
        except Exception as e:
            print(f"store_maintainer_node failed: {e}")

    def link_maintainer_to_package(self, maintainer_name, pkg_name):
        query = """
        MATCH (m:Maintainer {name: $maintainer_name})
        MATCH (p:Package {name: $pkg_name})
        MERGE (m)-[:MAINTAINS]->(p)
        """
        try:
            with self.driver.session() as session:
                session.run(query, maintainer_name=maintainer_name, pkg_name=pkg_name)
        except Exception as e:
            print(f"link_maintainer_to_package failed: {e}")

    def store_script_node(self, content, hook):
        script_hash = hash(content)
        query = """
        MERGE (s:Script {hash: $hash})
        SET s.content = $content, s.hook = $hook
        RETURN s
        """
        try:
            with self.driver.session() as session:
                session.run(query, hash=script_hash, content=content[:500], hook=hook)
        except Exception as e:
            print(f"store_script_node failed: {e}")

    def link_script_to_package(self, content, pkg_name):
        script_hash = hash(content)
        query = """
        MATCH (p:Package {name: $pkg_name})
        MATCH (s:Script {hash: $hash})
        MERGE (p)-[:HAS_SCRIPT]->(s)
        """
        try:
            with self.driver.session() as session:
                session.run(query, pkg_name=pkg_name, hash=script_hash)
        except Exception as e:
            print(f"link_script_to_package failed: {e}")

    def ensure_version_chain(self, name, version, collected_at):
        if not name or not version or not collected_at:
            return
        query = """
        MATCH (prev:Package {name: $name})
        WHERE prev.version <> $version
          AND prev.collected_at IS NOT NULL
          AND prev.collected_at < $collected_at
        WITH prev ORDER BY prev.collected_at DESC LIMIT 1
        MATCH (curr:Package {name: $name, version: $version})
        MERGE (prev)-[:PRECEDES]->(curr)
        """
        try:
            with self.driver.session() as session:
                session.run(query, name=name, version=version, collected_at=collected_at)
        except Exception as e:
            print(f"ensure_version_chain failed: {e}")

    def get_packages_by_maintainer(self, maintainer_name):
        query = """
        MATCH (m:Maintainer {name: $name})-[:MAINTAINS]->(p:Package)
        RETURN p.name AS name, p.version AS version
        """
        results = []
        try:
            with self.driver.session() as session:
                result = session.run(query, name=maintainer_name)
                for record in result:
                    results.append({"name": record["name"], "version": record["version"]})
        except Exception as e:
            print(f"get_packages_by_maintainer failed: {e}")
        return results

    def get_packages_sharing_script(self, content):
        script_hash = hash(content)
        query = """
        MATCH (p:Package)-[:HAS_SCRIPT]->(s:Script {hash: $hash})
        RETURN p.name AS name, p.version AS version, s.hook AS hook
        """
        results = []
        try:
            with self.driver.session() as session:
                result = session.run(query, hash=script_hash)
                for record in result:
                    results.append({
                        "name": record["name"],
                        "version": record["version"],
                        "hook": record["hook"]
                    })
        except Exception as e:
            print(f"get_packages_sharing_script failed: {e}")
        return results

    def store_edge_by_name(self, pkg_name, dep_name):
        query = """
        MATCH (a:Package {name: $pkg_name})
        MATCH (b:Package {name: $dep_name})
        WHERE a <> b
        MERGE (a)-[:DEPENDS_ON]->(b)
        """
        with self.driver.session() as session:
            result = session.run(query, pkg_name=pkg_name, dep_name=dep_name).single()
            return result["p"] if result else None

    def store_edge_by_package_version(self, pkg, dep):
        query = """
        MATCH (a:Package {name: $pkg_name, version: $pkg_version})
        MATCH (b:Package {name: $dep_name, version: $dep_version})
        WHERE a <> b
        MERGE (a)-[:DEPENDS_ON]->(b)
        """
        with self.driver.session() as session:
            result = session.run(query, pkg_name=pkg["name"], pkg_version=pkg["version"], dep_name=dep["name"], dep_version=dep["version"]).single()
            return result["p"] if result else None

    def store_node_edge(self, pkg, dep):
        pass

    def reset_db(self):
        pass
