#!/usr/bin/env python3
import json
import urllib.request
import re
import os
import sys

# Configuration
LIBS = {
    "chart.js": {
        "npm_name": "chart.js",
        "local_file": "internal/web/static/js/chartjs/chart.umd.min.js",
        "version_regex": r"Chart\.js v([\d\.]+)"
    },
    "chartjs-adapter-date-fns": {
        "npm_name": "chartjs-adapter-date-fns",
        "local_file": "internal/web/static/js/chartjs/chartjs-adapter-date-fns.bundle.min.js",
        "version_regex": r"chartjs-adapter-date-fns v([\d\.]+)"
    },
    "chartjs-plugin-zoom": {
        "npm_name": "chartjs-plugin-zoom",
        "local_file": "internal/web/static/js/chartjs/chartjs-plugin-zoom.min.js",
        "version_regex": r"chartjs-plugin-zoom v([\d\.]+)"
    }
}

def get_latest_version(npm_name):
    url = f"https://registry.npmjs.org/{npm_name}/latest"
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            return data.get("version")
    except Exception as e:
        print(f"Error fetching latest version for {npm_name}: {e}")
        return None

def get_local_version(file_path, regex):
    if not os.path.exists(file_path):
        return "Not found"
    
    if not regex:
        return "Unknown"

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            # Read first few KB to find version
            content = f.read(4096)
            match = re.search(regex, content)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"Error reading local file {file_path}: {e}")
    
    return "Unknown"

def main():
    print(f"{'Library':<30} {'Local':<10} {'Latest':<10} {'Status'}")
    print("-" * 65)
    
    all_up_to_date = True
    
    for lib_id, info in LIBS.items():
        npm_name = info["npm_name"]
        local_file = info["local_file"]
        version_regex = info.get("version_regex")
        
        latest = get_latest_version(npm_name)
        local = get_local_version(local_file, version_regex)
        
        status = "OK"
        if latest and local != "Unknown" and local != "Not found":
            if local != latest:
                status = "UPDATE AVAILABLE"
                all_up_to_date = False
        elif local == "Not found":
            status = "MISSING"
            all_up_to_date = False
        
        print(f"{npm_name:<30} {local:<10} {latest:<10} {status}")

    if all_up_to_date:
        print("\nAll Chart.js libraries are up to date.")
    else:
        print("\nAction required: Some libraries have updates available.")

if __name__ == "__main__":
    main()
