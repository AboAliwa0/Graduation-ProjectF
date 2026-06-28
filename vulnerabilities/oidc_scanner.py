from __future__ import annotations

from urllib.parse import urljoin, urlparse

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
from vulnerabilities.common import error_result, make_result, safe_request, validate_target_url

meta = {
    "name": "OAuth 2.0 / OpenID Connect Discovery",
    "severity": "Medium",
    "description": "Inventories OIDC metadata and identifies high-confidence transport or algorithm configuration risks without performing a login.",
    "category": "Identity",
}
inputs = [
    {
        "name": "discovery_url",
        "label": "OIDC discovery URL/path",
        "type": "url",
        "required": False,
        "placeholder": "/.well-known/openid-configuration",
        "help": "The discovery document must be hosted on the authorized target hostname.",
    }
]


def _same_host(left: str, right: str) -> bool:
    return (urlparse(left).hostname or "").lower() == (urlparse(right).hostname or "").lower()


def scan(url, discovery_url="/.well-known/openid-configuration"):
    runtime = current_runtime()
    target = urljoin(url.rstrip("/") + "/", discovery_url or "/.well-known/openid-configuration")
    try:
        target = validate_target_url(target)
        if not _same_host(target, url):
            return make_result(
                False,
                "OIDC discovery URL must use the authorized target hostname.",
                severity="Info",
                confidence="High",
                status="inconclusive",
                endpoint=target,
            )
        response = safe_request("GET", target, allow_redirects=True)
        if response.status_code >= 400:
            return make_result(
                False,
                f"OIDC discovery document returned HTTP {response.status_code}.",
                severity="Info",
                confidence="High",
                status="inconclusive",
                evidence={"status_code": response.status_code},
                endpoint=response.url,
            )
        try:
            payload = response.json()
        except ValueError:
            return make_result(False, "OIDC discovery response was not JSON.", severity="Info", confidence="High", status="inconclusive", endpoint=response.url)
        if not isinstance(payload, dict) or not payload.get("issuer"):
            return make_result(False, "The document is not a valid OIDC discovery document.", severity="Info", confidence="High", status="inconclusive", endpoint=response.url)

        artifact = {
            "issuer": str(payload.get("issuer") or "")[:1000],
            "authorization_endpoint": str(payload.get("authorization_endpoint") or "")[:1000],
            "token_endpoint": str(payload.get("token_endpoint") or "")[:1000],
            "userinfo_endpoint": str(payload.get("userinfo_endpoint") or "")[:1000],
            "jwks_uri": str(payload.get("jwks_uri") or "")[:1000],
            "grant_types_supported": list(payload.get("grant_types_supported") or [])[:50],
            "response_types_supported": list(payload.get("response_types_supported") or [])[:50],
            "code_challenge_methods_supported": list(payload.get("code_challenge_methods_supported") or [])[:20],
            "id_token_signing_alg_values_supported": list(payload.get("id_token_signing_alg_values_supported") or [])[:50],
            "token_endpoint_auth_methods_supported": list(payload.get("token_endpoint_auth_methods_supported") or [])[:50],
            "status_code": response.status_code,
        }
        if runtime is not None:
            runtime.artifacts["oidc"] = artifact

        endpoints = [artifact[key] for key in ("issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri") if artifact.get(key)]
        insecure = [item for item in endpoints if item.startswith("http://")]
        algorithms = {str(item).lower() for item in artifact["id_token_signing_alg_values_supported"]}
        response_types = {str(item).lower() for item in artifact["response_types_supported"]}
        pkce = {str(item).upper() for item in artifact["code_challenge_methods_supported"]}

        if insecure:
            return make_result(
                True,
                "OIDC metadata advertises unencrypted HTTP endpoints.",
                severity="High",
                confidence="High",
                status="confirmed",
                evidence={**artifact, "insecure_endpoints": insecure},
                recommendation="Serve the issuer, authorization, token, userinfo, and JWKS endpoints exclusively over HTTPS.",
                endpoint=response.url,
                cwe="CWE-319",
                cvss=7.4,
            )
        if "none" in algorithms:
            return make_result(
                True,
                "OIDC metadata advertises the unsigned 'none' algorithm for ID tokens.",
                severity="High",
                confidence="High",
                status="potential",
                evidence=artifact,
                recommendation="Remove the 'none' algorithm and enforce a vetted asymmetric signing algorithm with strict issuer, audience, expiry, and nonce validation.",
                endpoint=response.url,
                cwe="CWE-347",
                cvss=7.5,
            )

        warnings = []
        if any(item in response_types for item in {"token", "id_token", "id_token token"}):
            warnings.append("Legacy implicit or hybrid response types are advertised.")
        if "code" in response_types and "S256" not in pkce:
            warnings.append("Authorization code flow is advertised without declaring PKCE S256 support.")
        if warnings:
            return make_result(
                True,
                "OIDC metadata contains modern-client hardening warnings.",
                severity="Medium",
                confidence="Medium",
                status="potential",
                evidence={**artifact, "warnings": warnings},
                recommendation="Prefer authorization code flow with PKCE S256, avoid legacy implicit response types, and validate redirect URIs exactly.",
                endpoint=response.url,
                cwe="CWE-346",
                cvss=5.3,
            )
        return make_result(
            False,
            "OIDC discovery metadata was inventoried without a high-confidence transport, unsigned-token, implicit-flow, or PKCE warning.",
            severity="Info",
            confidence="High",
            evidence=artifact,
            recommendation="Continue with authorized end-to-end tests for redirect URI validation, state, nonce, token audience, refresh rotation, revocation, and logout behavior.",
            endpoint=response.url,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"OIDC discovery assessment failed: {exc}", endpoint=target)
