import pytest

from app.plugins.nmap_tool import NmapTool


@pytest.mark.parametrize(
    "target",
    ["192.168.1.1", "192.168.1.0/24", "scanme.nmap.org", "server-1.local"],
)
def test_validate_target_accepts_safe_targets(target: str) -> None:
    NmapTool._validate_target(target)


@pytest.mark.parametrize("target", ["", "10.0.0.1;rm -rf /", "bad*host"])
def test_validate_target_rejects_unsafe_targets(target: str) -> None:
    with pytest.raises(ValueError):
        NmapTool._validate_target(target)
