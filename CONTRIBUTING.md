# Contributing to Flask-Headless-Auth

Thank you for your interest in contributing to Flask-Headless-Auth! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/flask-headless-auth.git
   cd flask-headless-auth
   ```

3. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

## Development Workflow

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and ensure they follow the project's coding standards

3. Run tests to ensure nothing is broken:
   ```bash
   pytest
   ```

4. Format your code with black:
   ```bash
   black flask_headless_auth/
   ```

5. Check for linting errors:
   ```bash
   flake8 flask_headless_auth/
   ```

## Submitting Changes

1. Commit your changes with clear, descriptive commit messages:
   ```bash
   git commit -m "Add feature: description of your changes"
   ```

2. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

3. Open a Pull Request on GitHub with:
   - A clear title and description
   - Reference to any related issues
   - Examples of how to use new features (if applicable)

## Code Style Guidelines

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write docstrings for public functions and classes
- Keep functions focused and modular
- Add tests for new features

## Testing

- Write tests for all new features and bug fixes
- Ensure all tests pass before submitting a PR
- Aim for high code coverage
- Test with multiple Python versions if possible (3.8+)

## Reporting Bugs

When reporting bugs, please include:

- Python version
- Flask version
- Steps to reproduce the issue
- Expected vs actual behavior
- Any relevant error messages or stack traces

## Feature Requests

We welcome feature requests! Please:

- Check if the feature has already been requested
- Provide a clear use case
- Explain how it benefits other users
- Consider contributing the implementation yourself

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what's best for the community
- Show empathy towards other contributors

## Questions?

If you have questions, feel free to:
- Open an issue on GitHub
- Contact the maintainer: Dhruv Agnihotri (dagni@umich.edu)

Thank you for contributing! 🎉




