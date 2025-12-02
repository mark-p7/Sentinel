from neo4j import GraphDatabase
import json
from helpers import node_to_package

# Neo4j -- For now only works on locally hosted database
URI = "neo4j://localhost:7687"
USER = "neo4j"
PASSWORD = "password"
DB_NAME = "neo4j"

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
        """
        Fetches all packages from the database for training.
        Returns a dictionary keyed by package 'name' to facilitate graph building.
        """
        query = """
        MATCH (p:Package)
        RETURN p
        """
        data = {}
        with self.driver.session() as session:
            result = session.run(query)
            for record in result:
                node = record["p"]
                name = node.get("name")
                if not name: 
                    continue
                
                # Parse dependencies
                deps_str = node.get("dependencies", "{}")
                try:
                    deps_dict = json.loads(deps_str)
                    deps_list = list(deps_dict.keys())
                except (json.JSONDecodeError, TypeError):
                    deps_list = []
                
                # Store the package with the name as the key
                data[name] = {
                    "name": name,
                    "version": node.get("version"),
                    "weekly_downloads": node.get("weekly_downloads", 0),
                    "dependency_count": len(deps_list),
                    "dependencies": deps_list
                }
        return data

    def store_node(self, data):
        # Create query props
        props = {
            "name": data.get("name") or "",
            "version": data.get("version") or "",
            "homepage": data.get("homepage") or "",
            "main": data.get("main") or "",
            "weekly_downloads": data.get("weekly_downloads"),
            "is_deprecated": True if "deprecated" in data else False,
        }

        # Convert JSON objects to JSON formatted strings
        props.update({
            "author": json.dumps(data.get("author") or {}),
            "dist": json.dumps(data.get("dist") or {}),
            "scripts": json.dumps(data.get("scripts") or {}),
            "_npmUser": json.dumps(data.get("_npmUser") or {}),
            "repository": json.dumps(data.get("repository") or {}),
            "dependencies": json.dumps(data.get("dependencies") or {}),
            "maintainers": json.dumps(data.get("maintainers") or []),
        })

        query = """
        MERGE (p:Package {name: $name, version: $version})
        SET p += $props
        RETURN p
        """

        with self.driver.session() as session:
            result = session.run(query, name=props["name"], version=props["version"], props=props).single()
            return result["p"] if result else None
    
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