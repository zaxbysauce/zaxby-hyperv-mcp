"""AC7 acceptance check: README documents the remote Hyper-V host layout.

The README must mention the "hyperv" config section (with its "host" key),
the host-credential environment variables, the Invoke-Command -ComputerName
guidance, and the WinRM prerequisite. RED on a tree whose README predates
the feature (HYPERV_HOST_USERNAME / HYPERV_HOST_PASSWORD_FILE / ComputerName
are absent today).
"""

from pathlib import Path

README = Path(__file__).resolve().parents[2] / "README.md"


def test_readme_documents_remote_host_layout():
    text = README.read_text(encoding="utf-8")
    required = (
        "hyperv",  # the config section
        "host",  # its key
        "HYPERV_HOST_USERNAME",
        "HYPERV_HOST_PASSWORD_FILE",
        "ComputerName",
        "WinRM",
    )
    missing = [token for token in required if token not in text]
    assert missing == [], f"README.md lacks remote-host documentation: {missing}"
