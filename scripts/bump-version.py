#!/usr/bin/env python3
"""Version bump script for ODIN

Automatically increments version numbers and updates build information.
Use before creating PRs to ensure proper version tracking.

Usage:
    python scripts/bump-version.py patch    # 1.0.0 -> 1.0.1
    python scripts/bump-version.py minor    # 1.0.0 -> 1.1.0  
    python scripts/bump-version.py major    # 1.0.0 -> 2.0.0
    python scripts/bump-version.py build    # Only increment build number
"""

import argparse
import re
import subprocess
from datetime import datetime
from pathlib import Path


def get_git_commit_hash() -> str:
    """Get current git commit hash."""
    try:
        result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                              capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def increment_version(current_version: str, bump_type: str) -> str:
    """Increment version based on bump type."""
    major, minor, patch = map(int, current_version.split('.'))
    
    if bump_type == 'major':
        major += 1
        minor = 0
        patch = 0
    elif bump_type == 'minor':
        minor += 1
        patch = 0
    elif bump_type == 'patch':
        patch += 1
    
    return f"{major}.{minor}.{patch}"


def increment_build_number(current_build: str) -> str:
    """Increment build number for same day or reset for new day."""
    today = datetime.now().strftime("%Y%m%d")
    
    if current_build.startswith(today):
        # Same day, increment build number
        parts = current_build.split('.')
        build_num = int(parts[1]) + 1
        return f"{today}.{build_num}"
    else:
        # New day, reset to 1
        return f"{today}.1"


def update_version_file(version_file: Path, new_version: str, new_build: str, git_commit: str):
    """Update the version.py file with new version information."""
    content = version_file.read_text()
    
    # Update version
    content = re.sub(r'__version__ = "[^"]*"', f'__version__ = "{new_version}"', content)
    
    # Update build
    content = re.sub(r'__build__ = "[^"]*"', f'__build__ = "{new_build}"', content)
    
    # Update git commit
    content = re.sub(r'__git_commit__ = "[^"]*"', f'__git_commit__ = "{git_commit}"', content)
    
    # Update release date
    today = datetime.now().strftime("%Y-%m-%d")
    content = re.sub(r'__release_date__ = "[^"]*"', f'__release_date__ = "{today}"', content)
    
    version_file.write_text(content)


def add_version_history_entry(version_file: Path, version: str, build: str, changes: list):
    """Add new entry to version history."""
    content = version_file.read_text()
    
    today = datetime.now().strftime("%Y-%m-%d")
    
    # Create new version entry
    new_entry = f'''    {{
        "version": "{version}",
        "build": "{build}",
        "date": "{today}",
        "name": "TBD",
        "changes": {changes}
    }},'''
    
    # Insert at the beginning of VERSION_HISTORY
    history_pattern = r'(VERSION_HISTORY = \[\s*)'
    content = re.sub(history_pattern, f'\\1\n{new_entry}', content)
    
    version_file.write_text(content)


def main():
    parser = argparse.ArgumentParser(description='Bump ODIN version')
    parser.add_argument('bump_type', choices=['major', 'minor', 'patch', 'build'],
                       help='Type of version bump')
    parser.add_argument('--changes', nargs='+', 
                       help='List of changes for this version')
    
    args = parser.parse_args()
    
    # Find version file
    repo_root = Path(__file__).parent.parent
    version_file = repo_root / 'odin' / 'version.py'
    
    if not version_file.exists():
        print(f"Error: Version file not found at {version_file}")
        return 1
    
    # Read current version
    content = version_file.read_text()
    
    version_match = re.search(r'__version__ = "([^"]*)"', content)
    build_match = re.search(r'__build__ = "([^"]*)"', content)
    
    if not version_match or not build_match:
        print("Error: Could not parse current version from version.py")
        return 1
    
    current_version = version_match.group(1)
    current_build = build_match.group(1)
    
    print(f"Current version: {current_version}")
    print(f"Current build: {current_build}")
    
    # Calculate new version and build
    if args.bump_type == 'build':
        new_version = current_version
        new_build = increment_build_number(current_build)
    else:
        new_version = increment_version(current_version, args.bump_type)
        new_build = increment_build_number(current_build)
    
    # Get git commit
    git_commit = get_git_commit_hash()
    
    print(f"New version: {new_version}")
    print(f"New build: {new_build}")
    print(f"Git commit: {git_commit[:8]}")
    
    # Update version file
    update_version_file(version_file, new_version, new_build, git_commit)
    
    # Add version history entry if changes provided
    if args.changes:
        add_version_history_entry(version_file, new_version, new_build, args.changes)
    
    print(f"✓ Version updated successfully")
    print(f"✓ Run 'git add {version_file}' to stage changes")
    
    return 0


if __name__ == '__main__':
    exit(main())