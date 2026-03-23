# Security Fix: PyPI Installation Issue

## Problem
The original implementation assumed KYRA was already published on PyPI:
```yaml
run: |
  python -m pip install --upgrade pip
  pip install kyra
```

This creates two critical issues:
1. **Installation Failure**: If no package named "kyra" exists on PyPI, the action fails
2. **Security Risk**: If someone else has published a package named "kyra", users would unknowingly install malicious or unrelated software

## Solution
Updated the action to install directly from the GitHub repository by default:

```yaml
run: |
  python -m pip install --upgrade pip
  if [ "${{ inputs.install-from-pypi }}" = "true" ]; then
    echo "Installing KYRA from PyPI..."
    pip install kyra
  else
    echo "Installing KYRA from GitHub repository..."
    pip install git+https://github.com/rahulhiremath15/kyra.git@${{ inputs.kyra-ref }}
  fi
```

## New Inputs
Two new optional inputs were added:

1. **`kyra-ref`** (default: `main`)
   - Allows installing from a specific branch, tag, or commit
   - Example: `kyra-ref: v1.0.0`

2. **`install-from-pypi`** (default: `false`)
   - Enables PyPI installation once the package is published
   - Example: `install-from-pypi: true`

## Benefits
✅ **Secure by default**: Installs from the verified GitHub repository
✅ **Version control**: Can pin to specific commits, tags, or branches
✅ **Future-proof**: Easy switch to PyPI when ready
✅ **No namespace conflicts**: Doesn't rely on PyPI package name availability

## Migration Path

### Current (Pre-Publication)
```yaml
- uses: ./.github/actions/kyra-scan
  with:
    path: .
    kyra-ref: main  # Optional: specify version
```

### After PyPI Publication
```yaml
- uses: ./.github/actions/kyra-scan
  with:
    path: .
    install-from-pypi: true
```

## Before Publishing to PyPI
1. Secure the "kyra" namespace on PyPI: https://pypi.org/account/register/
2. Set up automated releases (GitHub Actions + PyPI tokens)
3. Publish initial version: `python -m build && twine upload dist/*`
4. Update documentation to recommend PyPI installation
5. Consider keeping GitHub installation as an option for development versions

## Files Updated
- `.github/actions/kyra-scan/action.yml` - Added inputs and conditional installation
- `.github/actions/kyra-scan/README.md` - Updated documentation with installation notes
- `.github/actions/kyra-scan/DOCS_ADDITION.md` - Updated input reference table
