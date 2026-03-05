#!/usr/bin/env python3
"""
Kula Update Checker
Checks the local VERSION against the latest GitHub release.
"""

import os
import sys
from typing import Optional, Tuple

import requests


def get_local_version() -> Optional[str]:
    """Reads the current version from the VERSION file in the root directory."""
    # Assume the script is in addons/ and VERSION is in ../
    script_dir = os.path.dirname(os.path.realpath(__file__))
    version_file = os.path.join(script_dir, "..", "VERSION")
    if not os.path.exists(version_file):
        version_file = "/usr/share/kula/VERSION"

    if not os.path.exists(version_file):
        print(f"Error: VERSION file not found at {version_file}", file=sys.stderr)
        return None

    try:
        with open(version_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError as e:
        print(f"Error reading VERSION file: {e}", file=sys.stderr)
        return None


def parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """Parses a version string like '0.7.0' into a tuple of integers."""
    try:
        # Remove any leading 'v' and focus on the numeric part before any suffix like '-beta'
        clean_v = version_str.lstrip("v").split("-")[0]
        return tuple(map(int, clean_v.split(".")))
    except (ValueError, IndexError):
        return None


def check_for_update() -> None:
    """Checks for newer versions of Kula on GitHub and compares with local version."""
    local_version_str = get_local_version()
    if not local_version_str:
        sys.exit(1)

    print(f"Current version: {local_version_str}")

    repo_url = "https://api.github.com/repos/c0m4r/kula/releases/latest"
    headers = {"User-Agent": "kula-update-checker"}
    try:
        response = requests.get(repo_url, timeout=10, headers=headers)
        response.raise_for_status()
        data = response.json()

        remote_version_str = data.get("tag_name")
        if not remote_version_str:
            print(
                "Error: Could not find tag_name in the GitHub API response.",
                file=sys.stderr,
            )
            sys.exit(1)

        print(f"Latest version:  {remote_version_str}")

        local_v = parse_version(local_version_str)
        remote_v = parse_version(remote_version_str)

        if local_v is None or remote_v is None:
            # Fallback to simple string comparison if parsing fails
            if local_version_str == remote_version_str:
                print("\nYou are up-to-date!")
            else:
                print(f"\nA new version might be available: {remote_version_str}")
        else:
            if remote_v > local_v:
                # change the URL to variable
                tag_url = "https://github.com/c0m4r/kula/releases/tag"
                print(
                    f"\nUpdate available! Please visit: {tag_url}/{remote_version_str}"
                )
            elif remote_v < local_v:
                print(
                    "\nYou are running a version ahead of the latest release (development build?)."
                )
            else:
                print("\nYou are up-to-date!")

    except requests.exceptions.RequestException as e:
        print(f"Error checking for updates: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    check_for_update()
