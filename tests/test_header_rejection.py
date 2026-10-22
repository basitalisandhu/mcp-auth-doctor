"""Authorization overrides must not invalidate the unauthenticated probe."""

import pytest

from mcp_auth_doctor.cli import main
from mcp_auth_doctor.mcpclient import mcp_headers
from tests.conftest import MCP


@pytest.mark.parametrize("name", ["Authorization", "authorization", "aUtHoRiZaTiOn"])
@pytest.mark.parametrize("login", [False, True])
def test_cli_rejects_authorization_before_network(router, capsys, name, login):
    args = [MCP, "-H", f"{name}: Bearer synthetic-private-value"]
    if login:
        args.append("--login")
    with pytest.raises(SystemExit) as exc:
        main(args)
    assert exc.value.code == 3
    assert len(router.calls) == 0
    captured = capsys.readouterr()
    assert "Authorization" in captured.err
    assert "synthetic-private-value" not in captured.out + captured.err


@pytest.mark.parametrize("token", [None, "login-token"])
def test_mcp_headers_rejects_authorization_even_with_login_token(token):
    with pytest.raises(ValueError, match="Authorization is not allowed"):
        mcp_headers("2026-07-28", token=token, extra_headers={"Authorization": "Bearer override"})
