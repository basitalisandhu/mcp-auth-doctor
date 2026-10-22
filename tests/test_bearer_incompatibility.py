import pytest

from mcp_auth_doctor.checks import FAIL, diagnose
from tests.conftest import MCP, by_id, mount


@pytest.mark.parametrize("methods", [[], ["query"], ["body"], ["body", "query"]])
def test_explicit_incompatible_methods_fail_the_report(router, methods):
    mount(router, prm_extra={"bearer_methods_supported": methods})
    report = diagnose(MCP)
    check = by_id(report, "prm-bearer-methods")
    assert check.status == FAIL
    assert check.evidence["bearer_methods_supported"] == methods
    assert report.exit_code == 1
