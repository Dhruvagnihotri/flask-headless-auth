#!/bin/bash

# Flask-Headless-Auth - Quick Publish Script
# This script helps you publish to PyPI in one command

set -e  # Exit on any error

echo "🚀 Flask-Headless-Auth - PyPI Publishing Script"
echo "================================================"
echo ""

# Navigate to package directory
cd "$(dirname "$0")"

# Step 1: Clean previous builds
echo "📦 Step 1: Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info flask_headless_auth.egg-info
echo "✅ Cleaned"
echo ""

# Step 2: Build the package
echo "🔨 Step 2: Building package..."
python -m build
echo "✅ Built successfully"
echo ""

# Step 3: Check with twine
echo "🔍 Step 3: Validating package..."
twine check dist/*
echo "✅ Validation passed"
echo ""

# Step 4: Show what will be uploaded
echo "📋 Package contents:"
echo "-------------------"
ls -lh dist/
echo ""

# Step 5: Ask for confirmation
echo "🎯 Ready to publish!"
echo ""
echo "Choose an option:"
echo "  1) Publish to TestPyPI (recommended first)"
echo "  2) Publish to Production PyPI"
echo "  3) Cancel"
echo ""
read -p "Enter choice (1/2/3): " choice

case $choice in
  1)
    echo ""
    echo "📤 Uploading to TestPyPI..."
    echo "You will be prompted for:"
    echo "  Username: __token__"
    echo "  Password: <your-testpypi-token>"
    echo ""
    twine upload --repository testpypi dist/*
    echo ""
    echo "✅ Uploaded to TestPyPI!"
    echo ""
    echo "Test installation with:"
    echo "  pip install --index-url https://test.pypi.org/simple/ flask-headless-auth"
    ;;
  2)
    echo ""
    echo "⚠️  WARNING: Publishing to PRODUCTION PyPI"
    echo "This action cannot be undone for this version!"
    echo ""
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
      echo ""
      echo "📤 Uploading to Production PyPI..."
      echo "You will be prompted for:"
      echo "  Username: __token__"
      echo "  Password: <your-pypi-token>"
      echo ""
      twine upload dist/*
      echo ""
      echo "✅ Published to PyPI!"
      echo ""
      echo "🎉 Package is now live at:"
      echo "   https://pypi.org/project/flask-headless-auth/"
      echo ""
      echo "Test installation with:"
      echo "  pip install flask-headless-auth"
      echo ""
      echo "📝 Don't forget to:"
      echo "  1. Commit and push to GitHub"
      echo "  2. Create a git tag: git tag -a v0.1.0 -m 'Release v0.1.0'"
      echo "  3. Push tag: git push origin v0.1.0"
      echo "  4. Create GitHub release"
    else
      echo "❌ Cancelled"
    fi
    ;;
  3)
    echo "❌ Cancelled"
    ;;
  *)
    echo "❌ Invalid choice"
    exit 1
    ;;
esac

echo ""
echo "Done! 🎉"




