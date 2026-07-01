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
    started = runtime.request_count if runtime is not None else 0
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
                requests_made=0,
            )
        response = safe_request("GET", target, allow_redirects=True)
        requests_made = max(0, runtime.request_count - started) if runtime is not None else 1
        if response.status_code >= 400:
            return make_result(
                False,
                f"OIDC discovery document returned HTTP {response.status_code}.",
                severity="Info",
                confidence="High",
                status="inconclusive",
                evidence={"status_code": response.status_code},
                endpoint=response.url,
                requests_made=requests_made,
            )
        try:
            payload = response.json()
        except ValueError:
            return make_result(
                False,
                "OIDC discovery response was not JSON.",
                severity="Info",
                confidence="High",
                status="inconclusive",
                evidence={"status_code": response.status_code, "content_type": response.headers.get("Content-Type", "")},
                endpoint=response.url,
                requests_made=requests_made,
            )
        if not isinstance(payload, dict) or not payload.get("issuer"):
            return make_result(
                False,
                "The document is not a valid OIDC discovery document.",
                severity="Info",
                confidence="High",
                status="inconclusive",
                evidence={"status_code": response.status_code, "valid_discovery_document": False},
                endpoint=response.url,
                requests_made=requests_made,
            )

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
        security_evidence = {
            **artifact,
            "supported_flows": artifact["grant_types_supported"],
            "algorithms": artifact["id_token_signing_alg_values_supported"],
            "pkce_support": artifact["code_challenge_methods_supported"],
            "redirect_security_metadata": {
                "response_types_supported": artifact["response_types_supported"],
                "all_advertised_endpoints_https": not insecure,
            },
        }

        if insecure:
            return make_result(
                True,
                "OIDC metadata advertises unencrypted HTTP endpoints.",
                severity="High",
                confidence="Medium",
                status="potential",
                evidence={**security_evidence, "insecure_endpoints": insecure},
                recommendation="Serve the issuer, authorization, token, userinfo, and JWKS endpoints exclusively over HTTPS.",
                endpoint=response.url,
                cwe="CWE-319",
                cvss=7.4,
                requests_made=requests_made,
            )
        if "none" in algorithms:
            return make_result(
                True,
                "OIDC metadata advertises the unsigned 'none' algorithm for ID tokens.",
                severity="High",
                confidence="High",
                status="potential",
                evidence=security_evidence,
                recommendation="Remove the 'none' algorithm and enforce a vetted asymmetric signing algorithm with strict issuer, audience, expiry, and nonce validation.",
                endpoint=response.url,
                cwe="CWE-347",
                cvss=7.5,
                requests_made=requests_made,
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
                evidence={**security_evidence, "warnings": warnings},
                recommendation="Prefer authorization code flow with PKCE S256, avoid legacy implicit response types, and validate redirect URIs exactly.",
                endpoint=response.url,
                cwe="CWE-346",
                cvss=5.3,
                requests_made=requests_made,
            )
        return make_result(
            False,
            "OIDC discovery metadata was inventoried without a high-confidence transport, unsigned-token, implicit-flow, or PKCE warning.",
            severity="Info",
            confidence="High",
            evidence=security_evidence,
            recommendation="Continue with authorized end-to-end tests for redirect URI validation, state, nonce, token audience, refresh rotation, revocation, and logout behavior.",
            endpoint=response.url,
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except ValueError as exc:
        return make_result(
            False,
            f"OIDC discovery URL is invalid: {exc}",
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={"discovery_url": discovery_url or "/.well-known/openid-configuration"},
            endpoint=target,
            requests_made=0,
        )
    except Exception as exc:
        requests_made = max(0, runtime.request_count - started) if runtime is not None else 1
        return error_result(f"OIDC discovery assessment failed: {exc}", endpoint=target, requests_made=requests_made)
