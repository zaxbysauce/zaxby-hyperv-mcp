"""Shared unit-test fixtures. No real Hyper-V is touched."""

import pytest

from hyperv_mcp.config import Config


@pytest.fixture()
def deny_all_cfg() -> Config:
    return Config()


@pytest.fixture()
def unrestricted_cfg() -> Config:
    return Config(unrestricted=True)


@pytest.fixture()
def lab_cfg(tmp_path) -> Config:
    """A realistic restrictive lab config: one VM pattern, tmp roots."""
    return Config(
        allowed_vm_patterns=["test-vm-*"],
        host_read_roots=[str(tmp_path / "host-read")],
        host_write_roots=[str(tmp_path / "host-write")],
        guest_read_roots=["C:\\guest-read"],
        guest_write_roots=["C:\\guest-write"],
    )
