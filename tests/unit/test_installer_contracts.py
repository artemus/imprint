from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_byte_pinned_installer_inputs_force_lf_git_checkouts():
    attributes = {
        line.strip()
        for line in _read(".gitattributes").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert {
        "tools/install/verify_wheelhouse.py text eol=lf",
        "release/wheelhouse/manifest.json text eol=lf",
        "release/wheelhouse/manifest.sha256 text eol=lf",
        "requirements/runtime-*.lock text eol=lf",
    } <= attributes


def test_posix_installer_rejects_unsafe_adoption_and_only_chmods_created_roots():
    source = _read("install/install.sh")
    assert "Refusing to adopt a non-private pre-existing Imprint directory" in source
    assert 'if [ "${CONFIG_PARENT_CREATED}" -eq 1 ]; then chmod 700' in source
    assert 'if [ "${DATA_ROOT_CREATED}" -eq 1 ]; then chmod 700' in source


def test_windows_installer_rejects_unsafe_adoption_and_only_acls_created_roots():
    source = _read("install/install.ps1")
    assert "Refusing to adopt a non-private pre-existing Imprint directory" in source
    assert "if ($ConfigParentCreated) { Set-PrivateAcl $ConfigParent }" in source
    assert "if ($DataRootCreated) { Set-PrivateAcl $DataRoot }" in source


def test_launchers_and_path_blocks_are_version_agnostic_and_location_is_recorded():
    posix_install = _read("install/install.sh")
    posix_uninstall = _read("install/uninstall.sh")
    windows_install = _read("install/install.ps1")
    windows_uninstall = _read("install/uninstall.ps1")
    assert "# imprint-local-owned-launcher" in posix_install
    assert "# imprint-local-owned-launcher:" not in posix_install
    assert "# >>> imprint-local-owned-path >>>" in posix_install
    assert ".imprint-launcher-dir" in posix_install and ".imprint-launcher-dir" in posix_uninstall
    assert "rem imprint-local-owned-launcher" in windows_install
    assert ".imprint-launcher-dir" in windows_install and ".imprint-launcher-dir" in windows_uninstall
    assert "--expected-version" in posix_uninstall and "--expected-version" in windows_uninstall


def test_windows_installer_writes_config_without_a_utf8_bom():
    source = _read("install/install.ps1")
    assert "$Utf8NoBom = [Text.UTF8Encoding]::new($false)" in source
    assert "[IO.File]::WriteAllText($TempConfig, ($ConfigValue | ConvertTo-Json -Depth 8), $Utf8NoBom)" in source
    # Windows PowerShell 5.1 writes a BOM for -Encoding utf8, which the config
    # loader would have reported as a corrupt config.
    assert "Set-Content -Encoding utf8" not in source


def test_windows_installer_reads_existing_config_on_windows_powershell_5():
    source = _read("install/install.ps1")
    # -AsHashtable is PowerShell 6+ only; on 5.1 it aborts every upgrade that
    # has an existing config, discarding configured values such as
    # hook_timeout_seconds.
    assert "-AsHashtable" not in source
    assert "$Utf8NoBom.GetString([IO.File]::ReadAllBytes($Config)).TrimStart([char]0xFEFF)" in source


def test_installers_tolerate_a_bom_when_merging_an_existing_config():
    assert 'path.read_text(encoding="utf-8-sig")' in _read("install/install.sh")
