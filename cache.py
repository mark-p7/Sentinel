import redis

# Redis
CACHE_HOST = "localhost"
CACHE_PORT = 6379
CACHE_DB = 0

VISITED_CACHE = "VCS"

class DataCache:
    def __init__(self):
        self.cache = redis.Redis(host=CACHE_HOST, port=CACHE_PORT, db=CACHE_DB)
        
    def check_is_visited_cache_for_package(self, node):
        return self.cache.sismember(VISITED_CACHE, node)
    
    def add_package_to_visited_cache(self, node):
        self.cache.sadd(VISITED_CACHE, node)
        
    def clear(self):
        self.cache.flushall()