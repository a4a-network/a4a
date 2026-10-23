"""Compare exact inherited and final inventories for a bounded Debian replay."""

from debian_lock_contract import LockContractError, _ARCHITECTURES, _NAME, _VERSION, _locked


def _inventory(text):
    if not isinstance(text, str) or not text or len(text) > 8 * 1024 * 1024:
        raise LockContractError("invalid or oversized inventory")
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise LockContractError("bare carriage return in inventory")
    result = {}
    architectures = set()
    for line in text.split("\n"):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 3 or len(line) > 8192:
            raise LockContractError("malformed inventory row")
        binary_name, version, architecture = fields
        name, separator, qualifier = binary_name.partition(":")
        if (not _NAME.fullmatch(name) or not _VERSION.fullmatch(version)
                or architecture not in _ARCHITECTURES | {"all"}
                or separator and qualifier != architecture):
            raise LockContractError("invalid inventory package identity")
        key = name, architecture
        if key in result:
            raise LockContractError("duplicate inventory package")
        if len(result) >= 100_000:
            raise LockContractError("too many inventory packages")
        result[key] = version
        if architecture != "all":
            architectures.add(architecture)
    if not result or len(architectures) > 1:
        raise LockContractError("empty or multiarch inventory is unsupported")
    return result


def validate_install_inventory(before, after, locked_packages, *, expected_base):
    """Accept only an exact base plus explicit target versions, never removals.

    Inputs are dpkg-query binary:Package/Version/Architecture tab-separated rows.
    Package configuration health must be checked separately. These counts do
    not authenticate artifacts or order Debian versions; an existing version
    change is not automatically described as an upgrade.
    """
    base, inherited, installed = _inventory(expected_base), _inventory(before), _inventory(after)
    if inherited != base:
        raise LockContractError("inherited base inventory mismatch")
    expected = dict(base)
    targets = _locked(locked_packages)
    for name, version, architecture in targets:
        expected[name, architecture] = version
    if installed != expected:
        raise LockContractError("final inventory differs from exact base and locked package set")
    added = len(set(installed) - set(base))
    changed = sum(installed[key] != version for key, version in base.items())
    return {"base_package_count": len(base), "installed_package_count": len(installed),
            "added_packages": added, "changed_existing_packages": changed,
            "unchanged_packages": len(base) - changed}
