import sys
import requests
import time
from cache import DataCache
from db import DataStorage
from helpers import populate_database
from urllib.parse import quote

# TODO: Add semantic version parsing

# https://registry.npmjs.org/{package_name}/{package_version}
URL = "https://registry.npmjs.org"

class NPMPackageDependencyTraversal:
    def __init__(self, root=None, fn_node=None, fn_data=None, db=DataStorage(), cache=DataCache()):
        self.root = root
        self.fn_node = fn_node # What to do with each node
        self.fn_data = fn_data # What to do with each node's full package data
        self.db = db
        self.cache = cache
        
    def fetch_package_data(self, package_name):
        url = f"{URL}/{quote(package_name, safe='')}"
        response = requests.get(url)
        
        if response.status_code == 200:
            return response.json()

        else:
            print("Error retrieving package data")
            return None
        
    def fetch_weekly_downloads(self, package_name):
        # Add small delay to appease rate imits
        time.sleep(0.1)
        
        # The API returns daily downloads for the range. We sum them up.
        url = f"https://api.npmjs.org/downloads/range/last-week/{quote(package_name, safe='')}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                total_downloads = 0
                if "downloads" in data and isinstance(data["downloads"], list):
                    for day_data in data["downloads"]:
                        total_downloads += day_data.get("downloads", 0)
                return total_downloads
            return 0
        except Exception as e:
            print(f"Error retrieving download stats for {package_name}: {e}")
            return 0
        
    def traverse(self, node=None):
        if not node:
            node = self.root
            
        self.recursively_traverse(node, None)
    
    def recursively_traverse(self, node, prev):
        # Example: 
        # 1. Prev = har-validator (full package json)   node = ajv (just the name)
        # 2. Prev = ajv           (full package json)   node = json-schema-traverse (just the name)
        if not node:
            return
        
        if self.cache.check_is_visited_cache_for_package(node):
            if prev is not None:
                self.db.store_edge_by_name(prev.get("name"), node)
            return
        
        self.cache.add_package_to_visited_cache(node)
        
        print(f"{node}")
        
        data = self.fetch_package_data(node)
        
        if data == None:
            return
        
        latest = data["dist-tags"]["latest"]
        latest_package = data["versions"][latest]
        
        downloads = self.fetch_weekly_downloads(node)
        delay = 1
        # If downloads are 0, add a delay and fetch 1 more time in case it was a rate limiting issue
        while (downloads == 0 and delay < 150):
            time.sleep(delay)
            delay += delay * 2
            downloads = self.fetch_weekly_downloads(node)
        latest_package["weekly_downloads"] = downloads
        print(latest_package["weekly_downloads"])
        self.db.store_node(latest_package)
        
        if prev is not None:
            # print(prev)
            # print(latest_package)
            # self.db.store_edge_by_name(prev, latest_package)
            print(f"Package {latest_package.get("name")} depends on {prev.get("name")}")
        
        if "dependencies" not in latest_package:
            return
        
        for dep in latest_package["dependencies"]:
            self.recursively_traverse(dep, latest_package)

def main():
    # Determine whether to train or evaluate model (train on default)
    sample_packages_file = ""
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--samples":
            if i + 1 < len(sys.argv):
                sample_packages_file = sys.argv[i + 1]
                i += 1
            else:
                print("Error: --samples requires a filename argument.")
                sys.exit(1)
        else:
            print(f"Incorrect arguments passed: {arg}\nUsage: python app.py --samples <file.txt>")
            sys.exit(1)
        i += 1
        
    ds = DataStorage()
    cache = DataCache()
    cache.clear()
    t = NPMPackageDependencyTraversal(db=ds, cache=cache)
    populate_database(file_path=sample_packages_file, fn=t.traverse)
    #t.traverse("@semantic-ui-react/event-stack")
    # print(ds.get_package_data("mongodb", "6.20.0")[0].get("dependencies")s)
        
main()