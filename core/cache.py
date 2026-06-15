import os
import json
import hashlib

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".cache")

def get_cache_key(memory_file: str, plugin: str) -> str:
    key_string = f"{os.path.abspath(memory_file)}_{plugin}"
    return hashlib.md5(key_string.encode()).hexdigest() + ".json"

def get_cached_result(memory_file: str, plugin: str):
    if not os.path.exists(CACHE_DIR):
        return None
        
    cache_path = os.path.join(CACHE_DIR, get_cache_key(memory_file, plugin))
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r") as f:
                return json.load(f)
        except:
            return None
    return None

def set_cached_result(memory_file: str, plugin: str, data):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
        
    cache_path = os.path.join(CACHE_DIR, get_cache_key(memory_file, plugin))
    try:
        with open(cache_path, "w") as f:
            json.dump(data, f)
    except Exception as e:
        pass  # Fail gracefully if we can't write to cache
