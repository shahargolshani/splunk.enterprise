# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib
import io
from unittest.mock import MagicMock, mock_open, patch

import pytest

from plugins.modules.splunk_universal_forwarder_linux import (
    check_if_downgrade,
    check_rhel_version,
    check_splunk_service,
    create_user_seed_conf,
    download_file,
    enable_systemd_service,
    get_deployment_server,
    get_existing_forward_servers,
    get_installed_version,
    install_rpm,
    is_splunk_installed,
    main,
    manage_forward_servers,
    purge_splunk_home,
    remove_deployment_server,
    remove_rpm,
    set_deployment_server,
    start_splunk,
    uninstall_splunk,
    verify_checksum,
)


@pytest.fixture
def mock_module():
    """Create a mock AnsibleModule for testing.

    The fail_json mock raises SystemExit to simulate real Ansible behavior
    where fail_json terminates module execution.
    """
    mock = MagicMock()
    mock.fail_json = MagicMock(side_effect=SystemExit(1))
    mock.warn = MagicMock()
    return mock


class DummyModule:
    """Minimal module stub for main() tests."""

    def __init__(self, params, check_mode=False):
        self.params = params
        self.check_mode = check_mode
        self.exit_json_called = False
        self.fail_json_called = False
        self.exit_json_args = {}
        self.fail_json_args = {}
        self.warn_calls = []
        self.log_calls = []

    def exit_json(self, **kwargs):
        self.exit_json_called = True
        self.exit_json_args = kwargs
        raise SystemExit(0)

    def fail_json(self, **kwargs):
        self.fail_json_called = True
        self.fail_json_args = kwargs
        raise SystemExit(1)

    def warn(self, msg=None, *args, **kwargs):  # pragma: no cover - trivial stub
        if msg is not None:
            self.warn_calls.append(msg)
        return None

    def log(self, msg=None, *args, **kwargs):  # pragma: no cover - trivial stub
        if msg is not None:
            self.log_calls.append(msg)
        return None


def make_module(params, check_mode=False):
    """Create a stub AnsibleModule for main() tests."""
    return DummyModule(params, check_mode=check_mode)


# ============================================================================
# Tests for check_rhel_version
# ============================================================================


def test_check_rhel_version_rhel8(mock_module):
    """Test successful detection of RHEL 8."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="8.9"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = check_rhel_version(mock_module)

    assert result == "8"
    mock_module.fail_json.assert_not_called()


def test_check_rhel_version_rhel9(mock_module):
    """Test successful detection of RHEL 9."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="9.3"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = check_rhel_version(mock_module)

    assert result == "9"
    mock_module.fail_json.assert_not_called()


def test_check_rhel_version_rhel10(mock_module):
    """Test successful detection of RHEL 10."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="10"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = check_rhel_version(mock_module)

    assert result == "10"
    mock_module.fail_json.assert_not_called()


def test_check_rhel_version_not_rhel(mock_module):
    """Test failure when system is not RHEL."""
    fake_content = 'NAME="Ubuntu"\nVERSION_ID="22.04"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            with pytest.raises(SystemExit):
                check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert "only supports RHEL" in mock_module.fail_json.call_args[1]["msg"]


def test_check_rhel_version_unsupported_version(mock_module):
    """Test failure when RHEL version is not 8, 9, or 10."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="7.9"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            with pytest.raises(SystemExit):
                check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert "Unsupported RHEL version" in mock_module.fail_json.call_args[1]["msg"]


def test_check_rhel_version_no_os_release(mock_module):
    """Test failure when /etc/os-release does not exist."""
    with patch("os.path.exists", return_value=False):
        with pytest.raises(SystemExit):
            check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert "/etc/os-release not found" in mock_module.fail_json.call_args[1]["msg"]


def test_check_rhel_version_no_version_id(mock_module):
    """Test failure when VERSION_ID is missing from os-release."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nPRETTY_NAME="RHEL"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            with pytest.raises(SystemExit):
                check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert (
        "Could not determine RHEL version" in mock_module.fail_json.call_args[1]["msg"]
    )


def test_check_rhel_version_with_rhel_in_name(mock_module):
    """Test successful detection when 'RHEL' is in content."""
    fake_content = 'NAME="RHEL"\nVERSION_ID="9"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = check_rhel_version(mock_module)

    assert result == "9"
    mock_module.fail_json.assert_not_called()


def test_check_rhel_version_exception(mock_module):
    """Test unexpected exception triggers fail_json."""
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", side_effect=Exception("boom")):
            with pytest.raises(SystemExit):
                check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert "Error checking RHEL version" in mock_module.fail_json.call_args[1]["msg"]


# ============================================================================
# Tests for is_splunk_installed
# ============================================================================


def test_is_splunk_installed_true(mock_module):
    """Test when Splunk is installed."""
    mock_module.run_command.return_value = (0, "splunkforwarder-10.0.0-1234.x86_64", "")

    result = is_splunk_installed(mock_module)

    assert result is True
    mock_module.run_command.assert_called_once_with(["rpm", "-qa", "splunkforwarder"])


def test_is_splunk_installed_false_not_found(mock_module):
    """Test when Splunk is not installed (package not found)."""
    mock_module.run_command.return_value = (1, "", "error")

    result = is_splunk_installed(mock_module)

    assert result is False


def test_is_splunk_installed_false_empty_output(mock_module):
    """Test when rpm returns success but empty output."""
    mock_module.run_command.return_value = (0, "", "")

    result = is_splunk_installed(mock_module)

    assert result is False


def test_is_splunk_installed_false_wrong_package(mock_module):
    """Test when output doesn't contain splunkforwarder."""
    mock_module.run_command.return_value = (0, "some-other-package-1.0.0", "")

    result = is_splunk_installed(mock_module)

    assert result is False


# ============================================================================
# Tests for get_installed_version
# ============================================================================


def test_get_installed_version_success(mock_module):
    """Test successful version retrieval."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (0, "10.0.0", "")
        result = get_installed_version(mock_module)

    assert result == "10.0.0"


def test_get_installed_version_not_installed(mock_module):
    """Test when Splunk is not installed."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=False,
    ):
        result = get_installed_version(mock_module)

    assert result is None
    mock_module.run_command.assert_not_called()


def test_get_installed_version_rpm_fails(mock_module):
    """Test when rpm query fails."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (1, "", "error")
        result = get_installed_version(mock_module)

    assert result is None


def test_get_installed_version_empty_output(mock_module):
    """Test when rpm returns empty output."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (0, "", "")
        result = get_installed_version(mock_module)

    assert result is None


def test_get_installed_version_strips_whitespace(mock_module):
    """Test that version output is stripped of whitespace."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (0, "  10.0.0  \n", "")
        result = get_installed_version(mock_module)

    assert result == "10.0.0"


def test_get_installed_version_exception_returns_none(mock_module):
    """Test exception in rpm query returns None."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.side_effect = Exception("rpm failed")
        result = get_installed_version(mock_module)

    assert result is None


# ============================================================================
# Tests for check_if_downgrade
# ============================================================================


def test_check_if_downgrade_major_downgrade():
    """Test downgrade detection when major version is lower."""
    result = check_if_downgrade("10.0.0", "9.0.0")
    assert result is True


def test_check_if_downgrade_minor_downgrade():
    """Test downgrade detection when minor version is lower."""
    result = check_if_downgrade("10.2.0", "10.1.0")
    assert result is True


def test_check_if_downgrade_patch_downgrade():
    """Test downgrade detection when patch version is lower."""
    result = check_if_downgrade("10.0.2", "10.0.1")
    assert result is True


def test_check_if_downgrade_major_upgrade():
    """Test upgrade detection when major version is higher."""
    result = check_if_downgrade("9.0.0", "10.0.0")
    assert result is False


def test_check_if_downgrade_minor_upgrade():
    """Test upgrade detection when minor version is higher."""
    result = check_if_downgrade("10.0.0", "10.1.0")
    assert result is False


def test_check_if_downgrade_patch_upgrade():
    """Test upgrade detection when patch version is higher."""
    result = check_if_downgrade("10.0.0", "10.0.1")
    assert result is False


def test_check_if_downgrade_same_version():
    """Test when both versions are identical."""
    result = check_if_downgrade("10.0.0", "10.0.0")
    assert result is False


def test_check_if_downgrade_complex_upgrade():
    """Test upgrade with lower minor but higher major."""
    result = check_if_downgrade("9.5.3", "10.0.0")
    assert result is False


def test_check_if_downgrade_complex_downgrade():
    """Test downgrade with higher minor but lower major."""
    result = check_if_downgrade("10.0.0", "9.5.3")
    assert result is True


# ============================================================================
# Tests for get_existing_forward_servers
# ============================================================================


def test_get_existing_forward_servers_success(mock_module):
    """Test successful parsing of forward servers."""
    mock_module.check_mode = False
    splunk_output = """Active forwards:
    10.0.0.1:9997
    10.0.0.2:9997
Configured but inactive forwards:
    none
"""
    mock_module.run_command.return_value = (0, splunk_output, "")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == ["10.0.0.1:9997", "10.0.0.2:9997"]


def test_get_existing_forward_servers_check_mode(mock_module):
    """Test that check mode returns empty list without running command."""
    mock_module.check_mode = True

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == []
    mock_module.run_command.assert_not_called()


def test_get_existing_forward_servers_command_fails(mock_module):
    """Test that command failure returns empty list and warns."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (1, "", "error message")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == []
    mock_module.warn.assert_called_once()
    assert "Failed to list forward-servers" in mock_module.warn.call_args[0][0]


def test_get_existing_forward_servers_no_servers(mock_module):
    """Test parsing when no forward servers are configured."""
    mock_module.check_mode = False
    splunk_output = """Active forwards:
    none
Configured but inactive forwards:
    none
"""
    mock_module.run_command.return_value = (0, splunk_output, "")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == []


def test_get_existing_forward_servers_mixed_active_inactive(mock_module):
    """Test parsing with both active and inactive servers."""
    mock_module.check_mode = False
    splunk_output = """Active forwards:
    10.0.0.1:9997
Configured but inactive forwards:
    10.0.0.2:9997
"""
    mock_module.run_command.return_value = (0, splunk_output, "")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == ["10.0.0.1:9997", "10.0.0.2:9997"]


def test_get_existing_forward_servers_empty_output(mock_module):
    """Test parsing with empty output."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "", "")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == []


# ============================================================================
# Tests for get_deployment_server
# ============================================================================


def test_get_deployment_server_success(mock_module):
    """Test successful extraction of the URI."""
    fake_content = "[target-broker:deploymentServer]\ntargetUri = 10.0.0.1:8089"

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = get_deployment_server(mock_module, "/opt/splunkforwarder")

    assert result == "10.0.0.1:8089"


def test_get_deployment_server_no_file(mock_module):
    """Test when file does not exist."""
    with patch("os.path.exists", return_value=False):
        result = get_deployment_server(mock_module, "/opt/splunkforwarder")

    assert result is None


def test_get_deployment_server_missing_uri(mock_module):
    """Test when file exists but targetUri is missing."""
    fake_content = "[some-other-section]\nkey = value"

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = get_deployment_server(mock_module, "/opt/splunkforwarder")

    assert result is None


def test_get_deployment_server_exception_warns(mock_module):
    """Test exception reading config warns and returns None."""
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", side_effect=Exception("read error")):
            result = get_deployment_server(mock_module, "/opt/splunkforwarder")

    assert result is None
    mock_module.warn.assert_called_once()


# ============================================================================
# Tests for check_splunk_service
# ============================================================================


def test_check_splunk_service_start_success(mock_module):
    """Test successful detection of running service."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "splunkd is running", "")
    mock_module.log = MagicMock()

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        result = check_splunk_service(
            mock_module,
            "/opt/splunkforwarder",
            "start",
            max_retries=1,
        )

    assert result is True
    mock_module.fail_json.assert_not_called()


def test_check_splunk_service_stop_success(mock_module):
    """Test successful detection of stopped service."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (3, "splunkd is not running", "")
    mock_module.log = MagicMock()

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        result = check_splunk_service(
            mock_module,
            "/opt/splunkforwarder",
            "stop",
            max_retries=1,
        )

    assert result is True
    mock_module.fail_json.assert_not_called()


def test_check_splunk_service_check_mode(mock_module):
    """Test that check mode returns True without running command."""
    mock_module.check_mode = True

    result = check_splunk_service(mock_module, "/opt/splunkforwarder", "start")

    assert result is True
    mock_module.run_command.assert_not_called()


def test_check_splunk_service_invalid_state(mock_module):
    """Test failure with invalid desired state."""
    mock_module.check_mode = False

    with pytest.raises(SystemExit):
        check_splunk_service(mock_module, "/opt/splunkforwarder", "invalid")

    mock_module.fail_json.assert_called_once()
    assert "Invalid desired_state" in mock_module.fail_json.call_args[1]["msg"]


def test_check_splunk_service_start_retry_success(mock_module):
    """Test that service check retries and eventually succeeds."""
    mock_module.check_mode = False
    mock_module.log = MagicMock()
    # First call returns not running, second call returns running
    mock_module.run_command.side_effect = [
        (3, "splunkd is not running", ""),
        (0, "splunkd is running", ""),
    ]

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        result = check_splunk_service(
            mock_module,
            "/opt/splunkforwarder",
            "start",
            max_retries=2,
            retry_delay=1,
        )

    assert result is True
    assert mock_module.run_command.call_count == 2


def test_check_splunk_service_max_retries_exhausted(mock_module):
    """Test that max retries returns False."""
    mock_module.check_mode = False
    mock_module.log = MagicMock()
    # Always return not running
    mock_module.run_command.return_value = (3, "splunkd is not running", "")

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        result = check_splunk_service(
            mock_module,
            "/opt/splunkforwarder",
            "start",
            max_retries=2,
            retry_delay=1,
        )

    assert result is False
    assert mock_module.run_command.call_count == 2


# ============================================================================
# Tests for download_file
# ============================================================================


def test_download_file_check_mode(mock_module):
    """Test that check mode skips download."""
    mock_module.check_mode = True
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.open_url",
    ) as mock_open_url:
        with patch("builtins.open", mock_open()) as mocked_open:
            download_file(mock_module, "http://example.com/file.rpm", "/tmp/file.rpm")

    mock_open_url.assert_not_called()
    mocked_open.assert_not_called()


def test_download_file_success(mock_module):
    """Test successful download writes to file."""
    mock_module.check_mode = False
    response = MagicMock()
    response.read.return_value = b"rpm-bytes"

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.open_url",
        return_value=response,
    ) as mock_open_url:
        with patch("builtins.open", mock_open()) as mocked_open:
            download_file(mock_module, "http://example.com/file.rpm", "/tmp/file.rpm")

    mock_open_url.assert_called_once_with("http://example.com/file.rpm", timeout=300)
    mocked_open.assert_called_once_with("/tmp/file.rpm", "wb")
    mocked_open().write.assert_called_once_with(b"rpm-bytes")


def test_download_file_failure(mock_module):
    """Test download failure triggers fail_json."""
    mock_module.check_mode = False
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.open_url",
        side_effect=Exception("network error"),
    ):
        with pytest.raises(SystemExit):
            download_file(mock_module, "http://example.com/file.rpm", "/tmp/file.rpm")

    mock_module.fail_json.assert_called_once()
    assert "Failed to download" in mock_module.fail_json.call_args[1]["msg"]


# ============================================================================
# Tests for verify_checksum
# ============================================================================


def test_verify_checksum_success(mock_module):
    """Test successful checksum verification."""
    rpm_bytes = b"test-rpm"
    expected_checksum = hashlib.sha512(rpm_bytes).hexdigest()
    checksum_content = f"SHA512(file)= {expected_checksum}\n"

    def open_side_effect(path, mode="r", *args, **kwargs):
        if path == "/tmp/file.rpm.sha512":
            return io.StringIO(checksum_content)
        if path == "/tmp/file.rpm":
            return io.BytesIO(rpm_bytes)
        raise FileNotFoundError(path)

    with patch("builtins.open", side_effect=open_side_effect):
        assert (
            verify_checksum(mock_module, "/tmp/file.rpm", "/tmp/file.rpm.sha512")
            is True
        )


def test_verify_checksum_missing_pattern(mock_module):
    """Test checksum parsing failure triggers fail_json."""
    checksum_content = "invalid checksum format"

    def open_side_effect(path, mode="r", *args, **kwargs):
        if path == "/tmp/file.rpm.sha512":
            return io.StringIO(checksum_content)
        if path == "/tmp/file.rpm":
            return io.BytesIO(b"data")
        raise FileNotFoundError(path)

    with patch("builtins.open", side_effect=open_side_effect):
        with pytest.raises(SystemExit):
            verify_checksum(mock_module, "/tmp/file.rpm", "/tmp/file.rpm.sha512")

    mock_module.fail_json.assert_called_once()
    assert "Could not parse checksum file" in mock_module.fail_json.call_args[1]["msg"]


def test_verify_checksum_exception(mock_module):
    """Test unexpected exception triggers fail_json."""
    with patch("builtins.open", side_effect=Exception("read error")):
        with pytest.raises(SystemExit):
            verify_checksum(mock_module, "/tmp/file.rpm", "/tmp/file.rpm.sha512")

    mock_module.fail_json.assert_called_once()
    assert "Error verifying checksum" in mock_module.fail_json.call_args[1]["msg"]


# ============================================================================
# Tests for install_rpm / remove_rpm
# ============================================================================


def test_install_rpm_check_mode(mock_module):
    """Test install in check mode."""
    mock_module.check_mode = True
    rc, out, err = install_rpm(mock_module, "/tmp/file.rpm")
    assert rc == 0
    assert "Check mode" in out


def test_install_rpm_runs_command(mock_module):
    """Test install uses rpm command."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "ok", "")
    rc, out, err = install_rpm(mock_module, "/tmp/file.rpm")
    assert rc == 0
    mock_module.run_command.assert_called_once_with(["rpm", "-i", "/tmp/file.rpm"])


def test_remove_rpm_check_mode(mock_module):
    """Test remove in check mode."""
    mock_module.check_mode = True
    rc, out, err = remove_rpm(mock_module, "splunkforwarder")
    assert rc == 0
    assert "Check mode" in out


def test_remove_rpm_runs_command(mock_module):
    """Test remove uses rpm erase."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "ok", "")
    rc, out, err = remove_rpm(mock_module, "splunkforwarder")
    assert rc == 0
    mock_module.run_command.assert_called_once_with(["rpm", "-e", "splunkforwarder"])


# ============================================================================
# Tests for create_user_seed_conf
# ============================================================================


def test_create_user_seed_conf_check_mode(mock_module):
    """Test check mode skips creating user-seed.conf."""
    mock_module.check_mode = True
    with patch("builtins.open", mock_open()) as mocked_open:
        create_user_seed_conf(mock_module, "/opt/splunkforwarder", "admin", "pass")
    mocked_open.assert_not_called()


def test_create_user_seed_conf_success(mock_module):
    """Test creating user-seed.conf writes expected content."""
    mock_module.check_mode = False
    writes = []

    class DummyFile:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def write(self, data):
            writes.append(data)

    with patch("os.makedirs") as mocked_mkdirs:
        with patch("builtins.open", return_value=DummyFile()) as mocked_open:
            with patch("os.chmod") as mocked_chmod:
                create_user_seed_conf(
                    mock_module,
                    "/opt/splunkforwarder",
                    "admin",
                    "pass",
                )

    mocked_mkdirs.assert_called_once()
    mocked_open.assert_called_once()
    assert "[user_info]\n" in writes
    assert "USERNAME = admin\n" in writes
    assert "PASSWORD = pass\n" in writes
    mocked_chmod.assert_called_once()


def test_create_user_seed_conf_mkdir_fails(mock_module):
    """Test failure to create directory triggers fail_json."""
    mock_module.check_mode = False
    with patch("os.makedirs", side_effect=Exception("mkdir failed")):
        with pytest.raises(SystemExit):
            create_user_seed_conf(mock_module, "/opt/splunkforwarder", "admin", "pass")

    mock_module.fail_json.assert_called_once()
    assert "Failed to create directory" in mock_module.fail_json.call_args[1]["msg"]


def test_create_user_seed_conf_write_fails(mock_module):
    """Test failure to write user-seed.conf triggers fail_json."""
    mock_module.check_mode = False
    with patch("os.makedirs"):
        with patch("builtins.open", side_effect=Exception("write failed")):
            with pytest.raises(SystemExit):
                create_user_seed_conf(
                    mock_module,
                    "/opt/splunkforwarder",
                    "admin",
                    "pass",
                )

    mock_module.fail_json.assert_called_once()
    assert (
        "Failed to create user-seed.conf" in mock_module.fail_json.call_args[1]["msg"]
    )


# ============================================================================
# Tests for manage_forward_servers
# ============================================================================


def test_manage_forward_servers_check_mode(mock_module):
    """Test check mode returns changed if servers provided."""
    mock_module.check_mode = True
    assert manage_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "pass",
        ["10.0.0.1:9997"],
        action="add",
    )


def test_manage_forward_servers_success(mock_module):
    """Test adding servers marks changed."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "ok", "")
    changed = manage_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "pass",
        ["10.0.0.1:9997", "10.0.0.2:9997"],
        action="add",
    )

    assert changed is True
    assert mock_module.run_command.call_count == 2


def test_manage_forward_servers_partial_failure(mock_module):
    """Test failures warn and only successful commands mark changed."""
    mock_module.check_mode = False
    mock_module.run_command.side_effect = [
        (1, "", "error"),
        (0, "ok", ""),
    ]
    changed = manage_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "pass",
        ["10.0.0.1:9997", "10.0.0.2:9997"],
        action="remove",
    )

    assert changed is True
    mock_module.warn.assert_called_once()


# ============================================================================
# Tests for set_deployment_server
# ============================================================================


def test_set_deployment_server_check_mode(mock_module):
    """Test check mode returns True."""
    mock_module.check_mode = True
    assert set_deployment_server(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "pass",
        "server:8089",
    )


def test_set_deployment_server_success(mock_module):
    """Test deploy-poll set success."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "ok", "")
    assert set_deployment_server(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "pass",
        "server:8089",
    )


def test_set_deployment_server_failure(mock_module):
    """Test deploy-poll set failure warns and returns False."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (1, "", "error")
    assert (
        set_deployment_server(
            mock_module,
            "/opt/splunkforwarder",
            "admin",
            "pass",
            "server:8089",
        )
        is False
    )
    mock_module.warn.assert_called_once()


# ============================================================================
# Tests for remove_deployment_server
# ============================================================================


def test_remove_deployment_server_check_mode(mock_module):
    """Test check mode returns True."""
    mock_module.check_mode = True
    assert remove_deployment_server(mock_module, "/opt/splunkforwarder")


def test_remove_deployment_server_success(mock_module):
    """Test removal success with restart and healthy service."""
    mock_module.check_mode = False
    mock_module.log = MagicMock()
    mock_module.run_command.return_value = (0, "", "")

    with patch("os.path.exists", return_value=True):
        with patch("os.remove") as mocked_remove:
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.check_splunk_service",
                return_value=True,
            ):
                assert remove_deployment_server(mock_module, "/opt/splunkforwarder")

    mocked_remove.assert_called_once()


def test_remove_deployment_server_restart_failure(mock_module):
    """Test restart failure returns False."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (1, "", "error")

    with patch("os.path.exists", return_value=True):
        with patch("os.remove"):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.check_splunk_service",
                return_value=True,
            ):
                assert (
                    remove_deployment_server(mock_module, "/opt/splunkforwarder")
                    is False
                )
    mock_module.warn.assert_called_once()


def test_remove_deployment_server_remove_fails(mock_module):
    """Test failure to remove config returns False and warns."""
    mock_module.check_mode = False
    with patch("os.path.exists", return_value=True):
        with patch("os.remove", side_effect=Exception("remove failed")):
            assert (
                remove_deployment_server(mock_module, "/opt/splunkforwarder") is False
            )

    mock_module.warn.assert_called_once()


# ============================================================================
# Tests for start_splunk
# ============================================================================


def test_start_splunk_check_mode(mock_module):
    """Test check mode returns simulated result."""
    mock_module.check_mode = True
    rc, out, err = start_splunk(mock_module, "/opt/splunkforwarder")
    assert rc == 0
    assert "Check mode" in out


def test_start_splunk_success(mock_module):
    """Test successful start with healthy service."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "ok", "")

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_splunk_service",
            return_value=True,
        ):
            rc, out, err = start_splunk(mock_module, "/opt/splunkforwarder")

    assert rc == 0


def test_start_splunk_service_fails(mock_module):
    """Test failure when service does not come up."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "ok", "")

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_splunk_service",
            return_value=False,
        ):
            with pytest.raises(SystemExit):
                start_splunk(mock_module, "/opt/splunkforwarder")

    mock_module.fail_json.assert_called_once()


# ============================================================================
# Tests for enable_systemd_service
# ============================================================================


def test_enable_systemd_service_check_mode(mock_module):
    """Test check mode returns simulated result."""
    mock_module.check_mode = True
    rc, out, err = enable_systemd_service(mock_module, "/opt/splunkforwarder")
    assert rc == 0
    assert "Check mode" in out


def test_enable_systemd_service_success(mock_module):
    """Test successful enable/start of systemd service."""
    mock_module.check_mode = False
    mock_module.log = MagicMock()
    mock_module.run_command.side_effect = [
        (0, "stopped", ""),  # splunk stop
        (8, "already enabled", ""),  # enable boot-start
        (0, "started", ""),  # systemctl start
    ]

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_splunk_service",
            side_effect=[True, True],
        ):
            rc, out, err = enable_systemd_service(mock_module, "/opt/splunkforwarder")

    assert rc == 0


def test_enable_systemd_service_start_failure(mock_module):
    """Test systemctl start failure triggers fail_json."""
    mock_module.check_mode = False
    mock_module.run_command.side_effect = [
        (0, "stopped", ""),  # splunk stop
        (0, "enabled", ""),  # enable boot-start
        (1, "", "error"),  # systemctl start
    ]

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_splunk_service",
            side_effect=[True, True],
        ):
            with pytest.raises(SystemExit):
                enable_systemd_service(mock_module, "/opt/splunkforwarder")

    mock_module.fail_json.assert_called_once()


def test_enable_systemd_service_status_check_failure(mock_module):
    """Test status check failure triggers fail_json after systemctl start."""
    mock_module.check_mode = False
    mock_module.run_command.side_effect = [
        (0, "stopped", ""),  # splunk stop
        (0, "enabled", ""),  # enable boot-start
        (0, "started", ""),  # systemctl start
    ]

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_splunk_service",
            side_effect=[True, False],
        ):
            with pytest.raises(SystemExit):
                enable_systemd_service(mock_module, "/opt/splunkforwarder")

    mock_module.fail_json.assert_called_once()
    assert (
        "Failed to start SplunkForwarder service"
        in mock_module.fail_json.call_args[1]["msg"]
    )


# ============================================================================
# Tests for uninstall_splunk
# ============================================================================


def test_uninstall_splunk_not_installed(mock_module):
    """Test uninstall when package is not installed."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=False,
    ):
        result = uninstall_splunk(mock_module, "/opt/splunkforwarder")

    assert result["changed"] is False
    assert "not installed" in result["msg"]


def test_uninstall_splunk_check_mode_installed(mock_module):
    """Test uninstall in check mode skips systemctl calls."""
    mock_module.check_mode = True
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.remove_rpm",
            return_value=(0, "ok", ""),
        ):
            result = uninstall_splunk(mock_module, "/opt/splunkforwarder")

    assert result["changed"] is True


def test_uninstall_splunk_remove_rpm_fails(mock_module):
    """Test rpm removal failure triggers fail_json."""
    mock_module.check_mode = True
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.remove_rpm",
            return_value=(1, "", "fatal error"),
        ):
            with pytest.raises(SystemExit):
                uninstall_splunk(mock_module, "/opt/splunkforwarder")

    mock_module.fail_json.assert_called_once()


def test_uninstall_splunk_disable_service_fails(mock_module):
    """Test systemctl disable failure triggers fail_json."""
    mock_module.check_mode = False
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (1, "", "disable error")
        with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
            with pytest.raises(SystemExit):
                uninstall_splunk(mock_module, "/opt/splunkforwarder")

    mock_module.fail_json.assert_called_once()
    assert (
        "Failed to disable SplunkForwarder" in mock_module.fail_json.call_args[1]["msg"]
    )


def test_uninstall_splunk_stop_service_fails(mock_module):
    """Test systemctl stop failure triggers fail_json."""
    mock_module.check_mode = False
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.side_effect = [
            (0, "", ""),  # disable ok
            (1, "", "stop error"),  # stop fails
        ]
        with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
            with pytest.raises(SystemExit):
                uninstall_splunk(mock_module, "/opt/splunkforwarder")

    mock_module.fail_json.assert_called_once()
    assert "Failed to stop Splunk service" in mock_module.fail_json.call_args[1]["msg"]


def test_uninstall_splunk_service_not_stopped(mock_module):
    """Test service stop verification failure triggers fail_json."""
    mock_module.check_mode = False
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.side_effect = [
            (0, "", ""),  # disable ok
            (0, "", ""),  # stop ok
        ]
        with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.check_splunk_service",
                return_value=False,
            ):
                with pytest.raises(SystemExit):
                    uninstall_splunk(mock_module, "/opt/splunkforwarder")

    mock_module.fail_json.assert_called_once()
    assert "Failed to stop Splunk service" in mock_module.fail_json.call_args[1]["msg"]


# ============================================================================
# Tests for purge_splunk_home
# ============================================================================


def test_purge_splunk_home_safety_check(mock_module):
    """Test safety check rejects non-splunk paths."""
    mock_module.check_mode = False
    with pytest.raises(SystemExit):
        purge_splunk_home(mock_module, "/opt/non-spl-home")

    mock_module.fail_json.assert_called_once()
    assert "restricted" in mock_module.fail_json.call_args[1]["msg"]


def test_purge_splunk_home_removes_dir(mock_module):
    """Test purge removes existing directory."""
    mock_module.check_mode = False
    fake_path = MagicMock()
    fake_path.exists.return_value = True
    fake_path.is_dir.return_value = True

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.Path",
        return_value=fake_path,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.shutil.rmtree",
        ) as mocked_rmtree:
            purge_splunk_home(mock_module, "/opt/splunkforwarder")

    mocked_rmtree.assert_called_once_with(fake_path)


# ============================================================================
# Tests for main
# ============================================================================


def test_main_state_absent():
    """Test main handles state=absent and exits with removal result."""
    params = dict(
        state="absent",
        version=None,
        release_id=None,
        cpu="64-bit",
        username=None,
        password=None,
        forward_servers=None,
        deployment_server=None,
    )
    module = make_module(params)

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.uninstall_splunk",
                return_value={"changed": True, "msg": "removed"},
            ) as mocked_uninstall:
                with patch(
                    "plugins.modules.splunk_universal_forwarder_linux.purge_splunk_home",
                ) as mocked_purge:
                    with pytest.raises(SystemExit):
                        main()

    mocked_uninstall.assert_called_once()
    mocked_purge.assert_called_once()
    assert module.exit_json_called is True
    assert module.exit_json_args["changed"] is True
    assert "removed" in module.exit_json_args["msg"]


def test_main_downgrade_blocked():
    """Test main blocks downgrade and exits with failed result."""
    params = dict(
        state="present",
        version="9.0.0",
        release_id="r1",
        cpu="64-bit",
        username="admin",
        password="pass",
        forward_servers=None,
        deployment_server=None,
    )
    module = make_module(params)

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.get_installed_version",
                return_value="10.0.0",
            ):
                with pytest.raises(SystemExit):
                    main()

    assert module.exit_json_called is True
    assert module.exit_json_args["failed"] is True
    assert (
        "Only universal forwarder upgrades are allowed" in module.exit_json_args["msg"]
    )


def test_main_installed_version_updates_forwarders_and_deploy():
    """Test main updates forward-servers and deployment server on same version."""
    params = dict(
        state="present",
        version="9.0.0",
        release_id="r1",
        cpu="64-bit",
        username="admin",
        password="pass",
        forward_servers=["10.0.0.1:9997", "10.0.0.2:9997"],
        deployment_server="deploy:8089",
    )
    module = make_module(params)

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.get_installed_version",
                return_value="9.0.0",
            ):
                with patch(
                    "plugins.modules.splunk_universal_forwarder_linux.get_existing_forward_servers",
                    return_value=["10.0.0.1:9997", "10.0.0.3:9997"],
                ):
                    with patch(
                        "plugins.modules.splunk_universal_forwarder_linux.manage_forward_servers",
                        return_value=True,
                    ) as mocked_manage:
                        with patch(
                            "plugins.modules.splunk_universal_forwarder_linux.get_deployment_server",
                            return_value="old:8089",
                        ):
                            with patch(
                                "plugins.modules.splunk_universal_forwarder_linux.set_deployment_server",
                                return_value=True,
                            ) as mocked_set:
                                with pytest.raises(SystemExit):
                                    main()

    assert mocked_manage.call_count == 2
    mocked_set.assert_called_once()
    assert module.exit_json_called is True
    assert module.exit_json_args["changed"] is True
    assert "deployment server set" in module.exit_json_args["msg"]


def test_main_fresh_install_flow():
    """Test main install path when not installed."""
    params = dict(
        state="present",
        version="9.0.0",
        release_id="r1",
        cpu="64-bit",
        username="admin",
        password="pass",
        forward_servers=["10.0.0.1:9997"],
        deployment_server=None,
    )
    module = make_module(params)
    rpm_filename = "splunkforwarder-9.0.0-r1.x86_64.rpm"
    rpm_path = f"/opt/{rpm_filename}"
    checksum_path = f"{rpm_path}.sha512"
    passwd_path = "/opt/splunkforwarder/etc/passwd"

    def exists_side_effect(path):
        if path in (rpm_path, checksum_path):
            return True
        if path == passwd_path:
            return False
        return False

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.get_installed_version",
                return_value=None,
            ):
                with patch(
                    "plugins.modules.splunk_universal_forwarder_linux.os.path.exists",
                    side_effect=exists_side_effect,
                ):
                    with patch(
                        "plugins.modules.splunk_universal_forwarder_linux.verify_checksum",
                        return_value=True,
                    ) as mocked_verify:
                        with patch(
                            "plugins.modules.splunk_universal_forwarder_linux.install_rpm",
                            return_value=(0, "ok", ""),
                        ) as mocked_install:
                            with patch(
                                "plugins.modules.splunk_universal_forwarder_linux.create_user_seed_conf",
                            ) as mocked_seed:
                                with patch(
                                    "plugins.modules.splunk_universal_forwarder_linux.start_splunk",
                                    return_value=(0, "ok", ""),
                                ) as mocked_start:
                                    with patch(
                                        "plugins.modules.splunk_universal_forwarder_linux.enable_systemd_service",
                                        return_value=(0, "ok", ""),
                                    ) as mocked_enable:
                                        with patch(
                                            "plugins.modules.splunk_universal_forwarder_linux.manage_forward_servers",
                                            return_value=True,
                                        ) as mocked_forward:
                                            with pytest.raises(SystemExit):
                                                main()

    mocked_verify.assert_called_once()
    mocked_install.assert_called_once()
    mocked_seed.assert_called_once()
    mocked_start.assert_called_once()
    mocked_enable.assert_called_once()
    mocked_forward.assert_called_once()
    assert module.exit_json_called is True
    assert module.exit_json_args["changed"] is True


def test_main_installed_version_remove_deployment_server():
    """Test main removes deployment server when empty string provided."""
    params = dict(
        state="present",
        version="9.0.0",
        release_id="r1",
        cpu="64-bit",
        username="admin",
        password="pass",
        forward_servers=[],
        deployment_server="",
    )
    module = make_module(params)

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.get_installed_version",
                return_value="9.0.0",
            ):
                with patch(
                    "plugins.modules.splunk_universal_forwarder_linux.get_existing_forward_servers",
                    return_value=[],
                ):
                    with patch(
                        "plugins.modules.splunk_universal_forwarder_linux.get_deployment_server",
                        return_value="old:8089",
                    ):
                        with patch(
                            "plugins.modules.splunk_universal_forwarder_linux.remove_deployment_server",
                            return_value=True,
                        ):
                            with pytest.raises(SystemExit):
                                main()

    assert module.exit_json_called is True
    assert module.exit_json_args["changed"] is True
    assert "deployment server removed" in module.exit_json_args["msg"]


def test_main_installed_version_no_forward_servers_or_deploy():
    """Test main exits cleanly when no forward/deploy updates are provided."""
    params = dict(
        state="present",
        version="9.0.0",
        release_id="r1",
        cpu="64-bit",
        username="admin",
        password="pass",
        forward_servers=None,
        deployment_server=None,
    )
    module = make_module(params)

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.get_installed_version",
                return_value="9.0.0",
            ):
                with pytest.raises(SystemExit):
                    main()

    assert module.exit_json_called is True
    assert module.exit_json_args["changed"] is False
    assert "already installed" in module.exit_json_args["msg"]


def test_main_install_downloads_and_warns():
    """Test install path downloads artifacts and warns on non-zero rc."""
    params = dict(
        state="present",
        version="9.0.0",
        release_id="r1",
        cpu="ARM",
        username="admin",
        password="pass",
        forward_servers=None,
        deployment_server=None,
    )
    module = make_module(params)
    rpm_filename = "splunkforwarder-9.0.0-r1.aarch64.rpm"
    rpm_path = f"/opt/{rpm_filename}"
    checksum_path = f"{rpm_path}.sha512"
    passwd_path = "/opt/splunkforwarder/etc/passwd"

    def exists_side_effect(path):
        if path in (rpm_path, checksum_path):
            return False
        if path == passwd_path:
            return True
        return False

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.get_installed_version",
                return_value=None,
            ):
                with patch(
                    "plugins.modules.splunk_universal_forwarder_linux.os.path.exists",
                    side_effect=exists_side_effect,
                ):
                    with patch(
                        "plugins.modules.splunk_universal_forwarder_linux.download_file",
                    ) as mocked_download:
                        with patch(
                            "plugins.modules.splunk_universal_forwarder_linux.verify_checksum",
                            return_value=True,
                        ):
                            with patch(
                                "plugins.modules.splunk_universal_forwarder_linux.install_rpm",
                                return_value=(0, "ok", ""),
                            ):
                                with patch(
                                    "plugins.modules.splunk_universal_forwarder_linux.start_splunk",
                                    return_value=(1, "", "start fail"),
                                ):
                                    with patch(
                                        "plugins.modules.splunk_universal_forwarder_linux.enable_systemd_service",
                                        return_value=(1, "", "enable fail"),
                                    ):
                                        with pytest.raises(SystemExit):
                                            main()

    assert mocked_download.call_count == 2
    assert len(module.warn_calls) == 2
    assert module.exit_json_called is True


def test_main_install_rpm_failure():
    """Test install RPM failure triggers fail_json."""
    params = dict(
        state="present",
        version="9.0.0",
        release_id="r1",
        cpu="64-bit",
        username="admin",
        password="pass",
        forward_servers=None,
        deployment_server=None,
    )
    module = make_module(params)
    rpm_filename = "splunkforwarder-9.0.0-r1.x86_64.rpm"
    rpm_path = f"/opt/{rpm_filename}"
    checksum_path = f"{rpm_path}.sha512"

    def exists_side_effect(path):
        if path in (rpm_path, checksum_path):
            return True
        return False

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.get_installed_version",
                return_value=None,
            ):
                with patch(
                    "plugins.modules.splunk_universal_forwarder_linux.os.path.exists",
                    side_effect=exists_side_effect,
                ):
                    with patch(
                        "plugins.modules.splunk_universal_forwarder_linux.verify_checksum",
                        return_value=True,
                    ):
                        with patch(
                            "plugins.modules.splunk_universal_forwarder_linux.install_rpm",
                            return_value=(1, "", "rpm error"),
                        ):
                            with pytest.raises(SystemExit):
                                main()

    assert module.fail_json_called is True
    assert "Failed to install RPM" in module.fail_json_args["msg"]


def test_main_upgrade_with_forwarders_and_deploy_remove():
    """Test upgrade path handles uninstall, forwarders, and deploy removal."""
    params = dict(
        state="present",
        version="9.0.0",
        release_id="r1",
        cpu="64-bit",
        username="admin",
        password="pass",
        forward_servers=["10.0.0.2:9997"],
        deployment_server="",
    )
    module = make_module(params)
    rpm_filename = "splunkforwarder-9.0.0-r1.x86_64.rpm"
    rpm_path = f"/opt/{rpm_filename}"
    checksum_path = f"{rpm_path}.sha512"
    passwd_path = "/opt/splunkforwarder/etc/passwd"

    def exists_side_effect(path):
        if path in (rpm_path, checksum_path):
            return True
        if path == passwd_path:
            return True
        return False

    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.AnsibleModule",
        return_value=module,
    ):
        with patch(
            "plugins.modules.splunk_universal_forwarder_linux.check_rhel_version",
            return_value="9",
        ):
            with patch(
                "plugins.modules.splunk_universal_forwarder_linux.get_installed_version",
                return_value="8.0.0",
            ):
                with patch(
                    "plugins.modules.splunk_universal_forwarder_linux.get_existing_forward_servers",
                    return_value=["10.0.0.1:9997"],
                ):
                    with patch(
                        "plugins.modules.splunk_universal_forwarder_linux.os.path.exists",
                        side_effect=exists_side_effect,
                    ):
                        with patch(
                            "plugins.modules.splunk_universal_forwarder_linux.verify_checksum",
                            return_value=True,
                        ):
                            with patch(
                                "plugins.modules.splunk_universal_forwarder_linux.uninstall_splunk",
                                return_value={"changed": True, "msg": "removed"},
                            ) as mocked_uninstall:
                                with patch(
                                    "plugins.modules.splunk_universal_forwarder_linux.install_rpm",
                                    return_value=(0, "ok", ""),
                                ):
                                    with patch(
                                        "plugins.modules.splunk_universal_forwarder_linux.start_splunk",
                                        return_value=(0, "ok", ""),
                                    ):
                                        with patch(
                                            "plugins.modules.splunk_universal_forwarder_linux.enable_systemd_service",
                                            return_value=(0, "ok", ""),
                                        ):
                                            with patch(
                                                "plugins.modules.splunk_universal_forwarder_linux.manage_forward_servers",
                                                return_value=True,
                                            ) as mocked_manage:
                                                with patch(
                                                    "plugins.modules.splunk_universal_forwarder_linux.get_deployment_server",
                                                    return_value="old:8089",
                                                ):
                                                    with patch(
                                                        "plugins.modules.splunk_universal_forwarder_linux.remove_deployment_server",
                                                        return_value=True,
                                                    ) as mocked_remove:
                                                        with pytest.raises(SystemExit):
                                                            main()

    mocked_uninstall.assert_called_once()
    assert mocked_manage.call_count == 2
    mocked_remove.assert_called_once()
    assert module.exit_json_called is True
