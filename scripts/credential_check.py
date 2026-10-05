#!/usr/bin/env python3
"""Select a local API credential; optionally GET model metadata. Never emit secrets."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from urllib import error, parse, request

KEY_LIMIT = 16_384
BODY_LIMIT = 1_048_576
PROVIDERS = {
    "openai": ("OPENAI_API_KEY", "https://api.openai.com/v1/models"),
    "anthropic": ("ANTHROPIC_API_KEY", "https://api.anthropic.com/v1/models"),
}


class SelectionError(ValueError):
    """Only fixed, secret-free messages may be used here."""


def select_key(provider: str, key_file: str | None, allow_env: bool,
               scoped: bool = False) -> tuple[str, str]:
    """Return key and source in memory. Never fall back from an explicit file."""
    if key_file is not None:
        try:
            # Nonblocking open also avoids hanging on a FIFO passed as a key file.
            fd = os.open(Path(key_file).expanduser(), os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise SelectionError("key file must be a regular file owned by this user")
                if info.st_mode & 0o077:
                    raise SelectionError("key file permissions must exclude group and others")
                if info.st_size > KEY_LIMIT:
                    raise SelectionError("key file exceeds the credential size limit")
                raw = stream.read(KEY_LIMIT + 1)
            if len(raw) > KEY_LIMIT:
                raise SelectionError("key file exceeds the credential size limit")
            key = raw.decode("ascii").strip()
        except (OSError, UnicodeError, ValueError) as exc:
            if isinstance(exc, SelectionError):
                raise
            raise SelectionError("explicit key file unavailable or invalid; no fallback") from None
        source = "file"
    else:
        if scoped:
            raise SelectionError("account/project scope requires an explicit matched key file")
        if not allow_env:
            raise SelectionError("select a key file or explicitly allow a verified environment key")
        key = os.environ.get(PROVIDERS[provider][0], "").strip()
        source = "environment"
    if not key or len(key) > KEY_LIMIT or not key.isascii() or any(
        char.isspace() or ord(char) < 33 or ord(char) > 126 for char in key
    ):
        raise SelectionError("credential must be one nonempty bounded ASCII token")
    return key, source


def classify(status: int, payload: object) -> str:
    """Classify using structured fields; never return raw server strings."""
    detail = payload.get("error", {}) if isinstance(payload, dict) else {}
    if not isinstance(detail, dict):
        detail = {}
    code, kind = detail.get("code"), detail.get("type")
    if code == "credit_balance_exhausted":
        return "credit_balance_exhausted"
    if code in ("organization_spend_limit_exceeded", "project_spend_limit_exceeded"):
        return "spend_limit"
    if code == "organization_usage_limit_exceeded":
        return "usage_limit"
    if code == "insufficient_quota" or kind in ("insufficient_quota", "billing_error") or status == 402:
        return "billing_or_quota"
    if status == 401:
        return "authentication"
    if status in (403, 404):
        return "permission_or_model_access"
    if status == 429:
        if code in ("rate_limit_exceeded", "slow_down") or kind == "rate_limit_error":
            return "rate_limit"
        return "unclassified_429"
    if status >= 500:
        return "service"
    return "request_error"


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe(provider: str, key: str, *, model: str | None = None,
          organization: str | None = None, project: str | None = None) -> dict:
    url = PROVIDERS[provider][1]
    if model is not None:
        url += "/" + parse.quote(model, safe="")
    headers = {"Accept": "application/json"}
    if provider == "openai":
        headers["Authorization"] = "Bearer " + key
        if organization:
            headers["OpenAI-Organization"] = organization
        if project:
            headers["OpenAI-Project"] = project
    else:
        headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
    # Fixed TLS endpoints, no environment proxy or redirect credential forwarding.
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        try:
            response = opener.open(request.Request(url, headers=headers, method="GET"), timeout=10)
        except error.HTTPError as exc:
            response = exc
        with response:
            status = response.code
            body = response.read(BODY_LIMIT + 1)
        if len(body) > BODY_LIMIT:
            return {"ok": False, "check": "response_too_large"}
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            return {"ok": False, "http_status": status, "check": "invalid_response"}
        if status != 200:
            return {"ok": False, "http_status": status, "check": classify(status, payload)}
        valid = isinstance(payload, dict) and (
            isinstance(payload.get("id"), str) if model is not None
            else isinstance(payload.get("data"), list)
        )
        if not valid:
            return {"ok": False, "http_status": status, "check": "invalid_response"}
        return {"ok": True, "http_status": status, "check": "metadata_accepted",
                "model_metadata": "available" if model is not None else "not_checked"}
    except Exception:
        # Network/HTTP exceptions can include credentials or private response data.
        return {"ok": False, "check": "transport_or_protocol_error"}


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes invalid arguments; those might be pasted secrets.
        self.exit(2, "invalid arguments; use --help; never pass a key value\n")


def main(argv: list[str] | None = None) -> int:
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("provider", choices=tuple(PROVIDERS))
    parser.add_argument("--key-file")
    parser.add_argument("--allow-env", action="store_true")
    parser.add_argument("--account", help="intended provenance label, not identity verification")
    parser.add_argument("--organization")
    parser.add_argument("--project")
    parser.add_argument("--model")
    parser.add_argument("--probe", action="store_true", help="one non-generating metadata GET")
    args = parser.parse_args(argv)
    if args.provider == "anthropic" and (args.organization or args.project):
        parser.error("OpenAI-only headers")
    for value in (args.organization, args.project, args.model, args.account):
        if value is not None and (not value or len(value) > 256 or not value.isascii()
                                  or any(ord(c) < 33 or ord(c) > 126 for c in value)):
            parser.error("invalid scope or model")
    try:
        key, source = select_key(args.provider, args.key_file, args.allow_env,
                                 any(v is not None for v in (args.account, args.organization, args.project)))
    except SelectionError as exc:
        print(json.dumps({"ok": False, "check": "selection", "reason": str(exc)}))
        return 1
    result = {"ok": True, "provider": args.provider, "source": source,
              "check": "local_available", "identity": "unverified", "billing": "unverified"}
    if args.probe:
        result.update(probe(args.provider, key, model=args.model,
                            organization=args.organization, project=args.project))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
