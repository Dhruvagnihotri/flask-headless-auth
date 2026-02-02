#!/bin/bash
# Publish flask-headless-auth to PyPI
# Usage: export PYPI_TOKEN="your-token-here" && ./publish_auth.sh

set -e

if [ -z "$PYPI_TOKEN" ]; then
    echo "❌ Error: PYPI_TOKEN environment variable not set"
    echo "Usage: export PYPI_TOKEN=\"your-token-here\" && ./publish_auth.sh"
    exit 1
fi

echo "🚀 Publishing flask-headless-auth to PyPI..."
echo ""

# Auto-increment version
echo "📈 Auto-incrementing version..."
python -c "
import re

# Read current version
with open('flask_headless_auth/__version__.py', 'r') as f:
    content = f.read()
    match = re.search(r'__version__\s*=\s*[\\\"\\']([^\\\"\\']+)[\\\"\\']', content)
    current_version = match.group(1) if match else '0.0.0'

# Parse version (major.minor.patch)
parts = current_version.split('.')
if len(parts) == 3:
    major, minor, patch = parts
    # Increment patch version
    new_patch = int(patch) + 1
    new_version = f'{major}.{minor}.{new_patch}'
else:
    # Fallback: just append .1
    new_version = current_version + '.1'

print(f'Current: {current_version} -> New: {new_version}')

# Update __version__.py
updated_content = re.sub(
    r'__version__\s*=\s*[\\\"\\'][^\\\"\\']+[\\\"\\']',
    f'__version__ = \\\"{new_version}\\\"',
    content
)
with open('flask_headless_auth/__version__.py', 'w') as f:
    f.write(updated_content)

print(f'✅ Version updated to {new_version}')
"

# Get new version from __version__.py
VERSION=$(python -c "import re; content = open('flask_headless_auth/__version__.py').read(); match = re.search(r'__version__\s*=\s*[\\\"\\']([^\\\"\\']+)[\\\"\\']', content); print(match.group(1) if match else '0.0.0')")
echo "📦 Version: $VERSION"
echo ""

# Clean previous builds
echo "🧹 Cleaning old builds..."
rm -rf dist/ build/ *.egg-info flask_headless_auth.egg-info
echo ""

# Update pyproject.toml version
echo "📝 Updating pyproject.toml version..."
python -c "
import re
with open('pyproject.toml', 'r') as f:
    content = f.read()
content = re.sub(r'^version = \"[^\"]+\"', f'version = \"${VERSION}\"', content, flags=re.MULTILINE)
with open('pyproject.toml', 'w') as f:
    f.write(content)
"
echo ""

# Build the package
echo "🔨 Building package..."
python -m build
echo ""

# Upload to PyPI
echo "📤 Uploading to PyPI..."
python -m twine upload --username __token__ --password "${PYPI_TOKEN}" dist/*
echo ""

echo "✅ Successfully published flask-headless-auth v${VERSION}!"
echo "🔗 View at: https://pypi.org/project/flask-headless-auth/${VERSION}/"



