import httpx
import pytest

from mcp_auth_doctor.checks import FAIL, PASS, SKIP, WARN, Options, diagnose
from tests.conftest import AS, MCP, PRM_PATH, PRM_ROOT, as_metadata, by_id, mount

ALL_IDS = [
    "unauth-401",
    "www-authenticate",
    "prm-fetch",
    "prm-resource",
    "prm-authorization-servers",
    "as-metadata",
    "as-issuer",
    "as-endpoints",
    "as-https",
    "as-pkce",
    "as-registration",
    "as-iss",
    "dcr-probe",
    "token-error-json",
    "login-token",
    "login-tools-list",
]


def test_correct_server_passes_everything(router):
    mount(router)
    report = diagnose(MCP)
    assert [c.id for c in report.checks] == ALL_IDS
    assert report.exit_code == 0 and report.verdict == "pass"
    statuses = {c.id: c.status for c in report.checks}
    assert statuses["dcr-probe"] == SKIP and statuses["login-token"] == SKIP
    assert statuses["login-tools-list"] == SKIP
    assert all(
        s == PASS
        for i, s in statuses.items()
        if i not in ("dcr-probe", "login-token", "login-tools-list")
    )
    assert by_id(report, "www-authenticate").evidence["scope"] == "mcp:read"
    assert by_id(report, "prm-fetch").evidence["url"] == PRM_PATH


@pytest.mark.parametrize(
    "member",
    ["authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri"],
)
def test_non_https_public_authorization_endpoint_fails(router, member):
    value = f"http://auth.example.com/{member}"
    mount(router, metadata={AS: as_metadata(**{member: value})})
    report = diagnose(MCP)
    check = by_id(report, "as-https")
    assert check.status == FAIL
    assert check.evidence["endpoints"] == {member: value}
    assert report.exit_code == 1


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
def test_http_loopback_authorization_endpoint_warns(router, host):
    value = f"http://{host}:8080/token"
    mount(router, metadata={AS: as_metadata(token_endpoint=value)})
    check = by_id(diagnose(MCP), "as-https")
    assert check.status == WARN
    assert check.evidence["endpoints"] == {"token_endpoint": value}


def test_all_https_authorization_endpoints_pass(router):
    mount(router, metadata={AS: as_metadata(jwks_uri=f"{AS}/jwks")})
    assert by_id(diagnose(MCP), "as-https").status == PASS


def test_public_failure_takes_precedence_over_loopback_warning(router):
    mount(
        router,
        metadata={
            AS: as_metadata(
                authorization_endpoint="http://localhost/authorize",
                token_endpoint="http://public.example/token",
            )
        },
    )
    check = by_id(diagnose(MCP), "as-https")
    assert check.status == FAIL
    assert set(check.evidence["endpoints"]) == {"authorization_endpoint", "token_endpoint"}


def test_json_document_shape(router):
    mount(router)
    doc = diagnose(MCP).to_dict()
    assert set(doc) == {"url", "checks", "summary"}
    assert doc["url"] == MCP
    assert all(set(c) == {"id", "status", "reason", "evidence"} for c in doc["checks"])
    assert doc["summary"]["verdict"] == "pass" and doc["summary"]["exit_code"] == 0
    assert doc["summary"]["pass"] == 13 and doc["summary"]["skip"] == 3
    assert doc["summary"]["spec"] == "2026-07-28"


def test_trailing_slash_mismatch_fails_explicitly(router):
    mount(router, resource=MCP + "/")
    report = diagnose(MCP)
    check = by_id(report, "prm-resource")
    assert check.status == FAIL
    assert "trailing slash" in check.reason
    assert check.evidence["trailing_slash_only"] is True
    assert report.exit_code == 1


def test_form_encoded_token_endpoint_fails(router):
    mount(router, token_error=(400, "application/x-www-form-urlencoded", "error=invalid_grant"))
    report = diagnose(MCP)
    check = by_id(report, "token-error-json")
    assert check.status == FAIL
    assert "application/json" in check.reason
    assert check.evidence["content_type"] == "application/x-www-form-urlencoded"
    assert report.exit_code == 1


def test_token_endpoint_variants(router):
    mount(router, token_error=(200, "application/json", '{"access_token":"x"}'))
    assert by_id(diagnose(MCP), "token-error-json").status == FAIL
    router.reset()
    mount(router, token_error=(500, "text/html", "<h1>oops</h1>"))
    assert "500" in by_id(diagnose(MCP), "token-error-json").reason
    router.reset()
    mount(router, token_error=(400, "application/json", '{"message":"bad"}'))
    assert by_id(diagnose(MCP), "token-error-json").status == WARN
    router.reset()
    mount(router, token_error=(400, "application/json", "not json"))
    assert by_id(diagnose(MCP), "token-error-json").status == FAIL


def test_token_request_carries_resource_and_pkce(router):
    mount(router)
    diagnose(MCP, Options(client_id="pre-registered"))
    request = router.post(f"{AS}/token").calls.last.request
    from tests.conftest import form

    data = form(request)
    assert data["resource"] == MCP
    assert data["grant_type"] == "authorization_code"
    assert data["client_id"] == "pre-registered"
    assert len(data["code_verifier"]) >= 43


def test_server_without_pkce_fails(router):
    mount(router, metadata={AS: as_metadata(code_challenge_methods_supported=None)})
    check = by_id(diagnose(MCP), "as-pkce")
    assert check.status == FAIL and "MUST refuse" in check.reason
    router.reset()
    mount(router, metadata={AS: as_metadata(code_challenge_methods_supported=["plain"])})
    check = by_id(diagnose(MCP), "as-pkce")
    assert check.status == FAIL and "S256" in check.reason


def test_200_without_auth_and_no_metadata_is_inconclusive(router):
    mount(router, unauth_status=200, prm_urls=())
    report = diagnose(MCP)
    assert by_id(report, "unauth-401").status == FAIL
    assert by_id(report, "www-authenticate").status == SKIP
    assert by_id(report, "prm-fetch").status == FAIL
    assert report.inconclusive and report.exit_code == 2 and report.verdict == "inconclusive"
    assert by_id(report, "as-metadata").status == SKIP


def test_200_without_auth_but_metadata_present_fails(router):
    mount(router, unauth_status=200)
    report = diagnose(MCP)
    assert by_id(report, "unauth-401").status == FAIL
    assert by_id(report, "prm-fetch").status == PASS
    assert not report.inconclusive and report.exit_code == 1


@pytest.mark.parametrize(
    "status,fragment",
    [(404, "wrong path"), (405, "POST not allowed"), (403, "401"), (500, "expected 401")],
)
def test_other_statuses_fail_with_hint(router, status, fragment):
    mount(router, unauth_status=status)
    check = by_id(diagnose(MCP), "unauth-401")
    assert check.status == FAIL and fragment in check.reason


def test_redirect_on_post_fails(router):
    mount(router)
    router.post(MCP).mock(return_value=httpx.Response(307, headers={"Location": MCP + "/"}))
    check = by_id(diagnose(MCP), "unauth-401")
    assert check.status == FAIL and "redirected" in check.reason


def test_401_without_header_falls_back_to_well_known(router):
    mount(router, header=False)
    report = diagnose(MCP)
    assert by_id(report, "www-authenticate").status == WARN
    assert by_id(report, "prm-fetch").status == PASS
    assert by_id(report, "prm-fetch").evidence["url"] == PRM_PATH
    assert report.exit_code == 0


def test_401_header_without_resource_metadata_warns(router):
    mount(router, header=False)
    router.post(MCP).mock(
        return_value=httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="mcp"'})
    )
    report = diagnose(MCP)
    assert by_id(report, "www-authenticate").status == WARN
    assert by_id(report, "prm-fetch").status == PASS


def test_root_well_known_used_when_path_form_missing(router):
    mount(router, header=False, prm_urls=(PRM_ROOT,))
    report = diagnose(MCP)
    check = by_id(report, "prm-fetch")
    assert check.status == PASS and check.evidence["url"] == PRM_ROOT
    assert [a["status"] for a in check.evidence["attempts"]] == [404, 200]


def test_header_url_404_fails_even_when_well_known_works(router):
    mount(router, header_url="https://mcp.example.com/missing-prm")
    report = diagnose(MCP)
    check = by_id(report, "prm-fetch")
    assert check.status == FAIL and "did not return metadata" in check.reason
    assert report.exit_code == 1


def test_prm_served_as_text_warns(router):
    mount(router)
    router.get(PRM_PATH).mock(
        return_value=httpx.Response(
            200,
            content=f'{{"resource":"{MCP}","authorization_servers":["{AS}"]}}',
            headers={"Content-Type": "text/plain"},
        )
    )
    check = by_id(diagnose(MCP), "prm-fetch")
    assert check.status == WARN and "text/plain" in check.reason


def test_prm_missing_resource_and_servers(router):
    mount(router, resource=None, issuers=())
    report = diagnose(MCP)
    assert by_id(report, "prm-resource").status == FAIL
    assert by_id(report, "prm-authorization-servers").status == FAIL
    assert by_id(report, "as-metadata").status == SKIP
    assert report.exit_code == 1


def test_openid_configuration_fallback(router):
    mount(router, metadata_urls={AS: f"{AS}/.well-known/openid-configuration"})
    check = by_id(diagnose(MCP), "as-metadata")
    assert check.status == PASS and "openid-configuration" in check.reason
    assert [a["status"] for a in check.evidence["attempts"]] == [404, 200]


def test_issuer_with_path_uses_path_insertion_order(router):
    issuer = "https://auth.example.com/tenant1"
    mount(
        router,
        issuers=(issuer,),
        metadata={issuer: as_metadata(issuer)},
        metadata_urls={issuer: "https://auth.example.com/tenant1/.well-known/openid-configuration"},
    )
    check = by_id(diagnose(MCP), "as-metadata")
    assert check.status == PASS
    assert [a["url"] for a in check.evidence["attempts"]] == [
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]


def test_no_as_metadata_anywhere_fails_and_skips_dependents(router):
    mount(router, metadata_urls={AS: f"{AS}/nowhere"})
    report = diagnose(MCP)
    assert by_id(report, "as-metadata").status == FAIL
    for check_id in (
        "as-issuer",
        "as-endpoints",
        "as-pkce",
        "as-registration",
        "as-iss",
        "token-error-json",
    ):
        assert by_id(report, check_id).status == SKIP
    assert report.exit_code == 1


def test_issuer_mismatch_fails(router):
    mount(router, metadata={AS: as_metadata(issuer="https://evil.example")})
    check = by_id(diagnose(MCP), "as-issuer")
    assert check.status == FAIL and "MUST NOT" in check.reason
    router.reset()
    without_issuer = as_metadata()
    del without_issuer["issuer"]
    mount(router, metadata={AS: without_issuer})
    assert by_id(diagnose(MCP), "as-issuer").status == WARN


def test_missing_endpoints_fail(router):
    mount(router, metadata={AS: as_metadata(token_endpoint=None)})
    report = diagnose(MCP)
    assert by_id(report, "as-endpoints").status == FAIL
    assert "token_endpoint" in by_id(report, "as-endpoints").reason
    assert by_id(report, "token-error-json").status == SKIP


def test_relative_endpoint_fails_without_crashing(router):
    mount(router, metadata={AS: as_metadata(token_endpoint="/token")})
    report = diagnose(MCP)
    check = by_id(report, "as-endpoints")
    assert check.status == FAIL and check.evidence["token_endpoint"] == "/token"
    assert by_id(report, "token-error-json").status == SKIP


def test_registration_variants(router):
    mount(
        router,
        metadata={
            AS: as_metadata(registration_endpoint=None, client_id_metadata_document_supported=None)
        },
    )
    check = by_id(diagnose(MCP), "as-registration")
    assert check.status == WARN and "cannot register" in check.reason
    router.reset()
    mount(router, metadata={AS: as_metadata(client_id_metadata_document_supported=None)})
    check = by_id(diagnose(MCP), "as-registration")
    assert check.status == PASS and "deprecated" in check.reason
    router.reset()
    mount(router, metadata={AS: as_metadata(client_id_metadata_document_supported=None)})
    check = by_id(diagnose(MCP, Options(spec="2025-11-25")), "as-registration")
    assert check.status == PASS and "deprecated" not in check.reason
    router.reset()
    mount(router, metadata={AS: as_metadata(registration_endpoint=None)})
    assert by_id(diagnose(MCP), "as-registration").status == PASS


def test_iss_depends_on_spec_version(router):
    mount(router, metadata={AS: as_metadata(authorization_response_iss_parameter_supported=None)})
    assert by_id(diagnose(MCP), "as-iss").status == WARN
    assert by_id(diagnose(MCP, Options(spec="2025-11-25")), "as-iss").status == SKIP
    router.reset()
    mount(router)
    assert by_id(diagnose(MCP, Options(spec="2025-11-25")), "as-iss").status == PASS


def test_dcr_probe_is_opt_in_and_reports(router):
    mount(router)
    assert by_id(diagnose(MCP), "dcr-probe").status == SKIP
    report = diagnose(MCP, Options(dcr_probe=True))
    check = by_id(report, "dcr-probe")
    assert (
        check.status == PASS and check.evidence["status"] == 201 and check.evidence["json"] is True
    )
    sent = router.post(f"{AS}/register").calls.last.request
    from tests.conftest import body_json

    body = body_json(sent)
    assert body["application_type"] == "native"
    assert body["redirect_uris"] == ["http://127.0.0.1:1/callback"]
    assert body["token_endpoint_auth_method"] == "none"


def test_dcr_probe_rejections(router):
    mount(router, dcr=(422, "text/html", "<h1>Unprocessable</h1>"))
    check = by_id(diagnose(MCP, Options(dcr_probe=True)), "dcr-probe")
    assert (
        check.status == FAIL and check.evidence["json"] is False and check.evidence["status"] == 422
    )
    router.reset()
    mount(
        router,
        dcr=(
            400,
            "application/json",
            '{"error":"invalid_redirect_uri","error_description":"loopback not allowed"}',
        ),
    )
    check = by_id(diagnose(MCP, Options(dcr_probe=True)), "dcr-probe")
    assert (
        check.status == FAIL
        and "invalid_redirect_uri" in check.reason
        and "loopback" in check.reason
    )
    router.reset()
    mount(router, metadata={AS: as_metadata(registration_endpoint=None)})
    assert by_id(diagnose(MCP, Options(dcr_probe=True)), "dcr-probe").status == SKIP


def test_multiple_authorization_servers_each_checked(router):
    second = "https://auth2.example.com"
    mount(
        router,
        issuers=(AS, second),
        metadata={
            AS: as_metadata(AS),
            second: as_metadata(second, code_challenge_methods_supported=None),
        },
    )
    report = diagnose(MCP)
    assert by_id(report, "as-pkce", AS).status == PASS
    assert by_id(report, "as-pkce", second).status == FAIL
    assert sum(1 for c in report.checks if c.id == "as-metadata") == 2
    assert report.exit_code == 1


def test_connection_error_is_inconclusive(router):
    mount(router)
    router.post(MCP).mock(side_effect=httpx.ConnectError("connection refused"))
    report = diagnose(MCP)
    assert by_id(report, "unauth-401").status == FAIL
    assert "could not reach" in by_id(report, "unauth-401").reason
    assert report.exit_code == 2
    assert all(c.status == SKIP for c in report.checks[1:])


def test_metadata_fetch_errors_are_recorded(router):
    mount(router)
    router.get(PRM_PATH).mock(side_effect=httpx.ReadTimeout("slow"))
    check = by_id(diagnose(MCP), "prm-fetch")
    assert check.status == FAIL
    assert "ReadTimeout" in check.evidence["attempts"][0]["error"]


def test_unauthenticated_request_is_a_minimal_initialize(router):
    mount(router)
    diagnose(MCP)
    request = router.post(MCP).calls[0].request
    assert "authorization" not in request.headers
    assert request.headers["accept"] == "application/json, text/event-stream"
    assert request.headers["mcp-protocol-version"] == "2026-07-28"
    from tests.conftest import body_json

    body = body_json(request)
    assert body["method"] == "initialize" and body["params"]["capabilities"] == {}
