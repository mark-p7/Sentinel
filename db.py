from neo4j import GraphDatabase
import json
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
        """
        Retrieves a package and all of its dependencies.
        """
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
                
                # Safely get properties
                pkg_name = node.get("name")
                pkg_version = node.get("version")
                pkg_weekly_downloads = node.get("weekly_downloads")
                
                # Parse dependencies string back to dictionary to get keys
                deps_str = node.get("dependencies", "{}")
                try:
                    deps_dict = json.loads(deps_str)
                    deps_list = list(deps_dict.keys())
                except (json.JSONDecodeError, TypeError):
                    deps_list = []

                # Construct the unique key
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
                    # Parse dependencies
                    deps_dict = safe_json_loads(node.get("dependencies", "{}"), {})
                    deps_list = list(deps_dict.keys()) if isinstance(deps_dict, dict) else []
                    data[name] = {
                        "name": name,
                        "version": node.get("version"),
                        "weekly_downloads": node.get("weekly_downloads", 0) or 0,
                        "dependency_count": len(deps_list),
                        "dependencies": deps_list
                    }
                except Exception as e:
                    print(f"Skipping bad Package record due to error: {e}")
                    continue

        return data

    def store_node(self, data):
        try:
            # Create query props
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
            }
            # Convert JSON objects to JSON formatted strings safely

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
                return record["p"] if record else None

        except Exception as e:
            print(f"store_node failed. skipping. Error: {e}")
            return None
    
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