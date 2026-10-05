"""Synthetic behavioral contracts; no provider network or model calls.

The reviewer scenario deliberately supplies an unrelated inherited key. File
selection must win, and missing intended credentials must not silently fall back.
"""

from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/credential_check.py"
SPEC = importlib.util.spec_from_file_location("credential_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
INTENDED = "synthetic-intended-secret"
INHERITED = "synthetic-unrelated-secret"


class CredentialBehavior(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / "private-key.txt"
        self.file.write_text(INTENDED + "\n")
        self.file.chmod(0o600)
        self.env = patch.dict(os.environ, {"OPENAI_API_KEY": INHERITED,
                                          "ANTHROPIC_API_KEY": INHERITED})
        self.env.start()
        self.addCleanup(self.env.stop)

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = CHECK.main(list(args))
        for secret in (INTENDED, INHERITED):
            self.assertNotIn(secret, out.getvalue() + err.getvalue())
        return rc, json.loads(out.getvalue())

    def test_explicit_company_file_wins_over_unrelated_environment(self):
        for provider in ("openai", "anthropic"):
            self.assertEqual(CHECK.select_key(provider, str(self.file), True, True),
                             (INTENDED, "file"))

    def test_missing_explicit_file_never_falls_back(self):
        rc, result = self.cli("openai", "--key-file", str(self.file) + "-missing", "--allow-env")
        self.assertEqual(rc, 1)
        self.assertEqual(result["check"], "selection")
        self.assertNotIn(str(self.file), json.dumps(result))

    def test_environment_requires_deliberate_selection(self):
        self.assertEqual(self.cli("openai")[0], 1)
        rc, result = self.cli("anthropic", "--allow-env")
        self.assertEqual(rc, 0)
        self.assertEqual(result["source"], "environment")
        self.assertEqual(result["identity"], "unverified")

    def test_named_scope_cannot_attest_unrelated_environment(self):
        for flag in ("--account", "--organization", "--project"):
            self.assertEqual(self.cli("openai", "--allow-env", flag, "intended")[0], 1)
        rc, result = self.cli("openai", "--key-file", str(self.file), "--account", "company")
        self.assertEqual(rc, 0)
        self.assertEqual(result["identity"], "unverified")

    def test_offline_check_never_opens_network_and_keeps_billing_unknown(self):
        with patch.object(CHECK.request, "build_opener", side_effect=AssertionError("network forbidden")):
            rc, result = self.cli("openai", "--key-file", str(self.file))
        self.assertEqual(rc, 0)
        self.assertEqual(result["check"], "local_available")
        self.assertEqual(result["billing"], "unverified")

    def test_rejects_world_readable_file_without_modifying_it(self):
        self.file.chmod(0o644)
        self.assertEqual(self.cli("openai", "--key-file", str(self.file))[0], 1)
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o644)

    def test_rejects_empty_multiline_nonascii_control_and_oversize_files(self):
        for raw in (b"", b"one\ntwo", b"bad\x00token", b"bad\xfftoken", b"x" * (CHECK.KEY_LIMIT + 1),
                    b"first" + b" " * CHECK.KEY_LIMIT + b"second"):
            with self.subTest(size=len(raw)):
                self.file.write_bytes(raw)
                self.assertEqual(self.cli("openai", "--key-file", str(self.file))[0], 1)

    def test_nonregular_file_fails_without_blocking(self):
        fifo = Path(self.temp.name) / "fifo"
        os.mkfifo(fifo, 0o600)
        result = subprocess.run([sys.executable, str(SCRIPT), "openai", "--key-file", str(fifo)],
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(INTENDED, result.stdout + result.stderr)

    def test_invalid_cli_argument_does_not_echo_pasted_secret(self):
        for args in (("openai", "--key", INTENDED), (INTENDED,)):
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                CHECK.main(list(args))
            self.assertEqual(raised.exception.code, 2)
            self.assertNotIn(INTENDED, err.getvalue())

    def fake_probe(self, provider="openai", *, status=200, body=None, failure=None, **kwargs):
        captured = []
        class Reply(io.BytesIO):
            code = status
        class Opener:
            def open(self, req, timeout):
                captured.append((req, timeout))
                if failure:
                    raise failure
                return Reply(json.dumps(body if body is not None else {"data": []}).encode())
        with patch.object(CHECK.request, "build_opener", return_value=Opener()) as builder:
            result = CHECK.probe(provider, INTENDED, **kwargs)
        self.assertNotIn(INTENDED, json.dumps(result))
        return result, captured, builder

    def test_metadata_probe_is_one_fixed_get_with_explicit_scope(self):
        with patch.dict(os.environ, {"OPENAI_BASE_URL": "https://untrusted.invalid",
                                     "OPENAI_PROJECT_ID": "wrong", "HTTPS_PROXY": "http://wrong.invalid"}):
            result, captured, builder = self.fake_probe(project="intended", organization="org")
        self.assertTrue(result["ok"])
        self.assertEqual(result["check"], "metadata_accepted")
        self.assertEqual(len(captured), 1)
        req, timeout = captured[0]
        self.assertEqual(req.full_url, "https://api.openai.com/v1/models")
        self.assertEqual(req.get_method(), "GET")
        self.assertIsNone(req.data)
        self.assertEqual(timeout, 10)
        self.assertEqual(req.get_header("Authorization"), "Bearer " + INTENDED)
        self.assertEqual(req.get_header("Openai-project"), "intended")
        self.assertEqual(builder.call_args.args[0].proxies, {})
        self.assertIsInstance(builder.call_args.args[1], CHECK.NoRedirect)

    def test_anthropic_model_retrieval_avoids_pagination_and_encodes_id(self):
        result, captured, _ = self.fake_probe("anthropic", model="model/alias", body={"id": "model-id"})
        self.assertEqual(result["model_metadata"], "available")
        req = captured[0][0]
        self.assertEqual(req.full_url, "https://api.anthropic.com/v1/models/model%2Falias")
        self.assertEqual(req.get_header("X-api-key"), INTENDED)
        self.assertEqual(req.get_header("Anthropic-version"), "2023-06-01")
        self.assertIsNone(req.get_header("Authorization"))

    def test_probe_preserves_identity_and_billing_uncertainty(self):
        with patch.object(CHECK, "probe", return_value={"ok": True, "check": "metadata_accepted"}):
            rc, result = self.cli("openai", "--key-file", str(self.file), "--probe")
        self.assertEqual(rc, 0)
        self.assertEqual(result["billing"], "unverified")
        self.assertEqual(result["identity"], "unverified")

    def test_specific_error_codes_distinguish_credit_caps_rate_and_auth(self):
        cases = [(429, "credit_balance_exhausted", "insufficient_quota", "credit_balance_exhausted"),
                 (429, "project_spend_limit_exceeded", "insufficient_quota", "spend_limit"),
                 (429, "organization_spend_limit_exceeded", "insufficient_quota", "spend_limit"),
                 (429, "organization_usage_limit_exceeded", None, "usage_limit"),
                 (429, "rate_limit_exceeded", "rate_limit_error", "rate_limit"),
                 (429, None, "insufficient_quota", "billing_or_quota"),
                 (429, None, None, "unclassified_429"),
                 (401, None, "authentication_error", "authentication"),
                 (403, None, None, "permission_or_model_access"),
                 (404, None, None, "permission_or_model_access"),
                 (402, None, "billing_error", "billing_or_quota"),
                 (503, None, None, "service")]
        for status, code, kind, expected in cases:
            with self.subTest(status=status, code=code):
                result, calls, _ = self.fake_probe(status=status, body={
                    "error": {"code": code, "type": kind, "message": INTENDED}})
                self.assertFalse(result["ok"])
                self.assertEqual(result["check"], expected)
                self.assertEqual(len(calls), 1)

    def test_http_error_response_is_classified_without_echoing_it(self):
        reply = io.BytesIO(json.dumps({"error": {"code": "credit_balance_exhausted",
                                                 "message": INTENDED}}).encode())
        failure = HTTPError("https://api.openai.com/v1/models", 429, INTENDED, {}, reply)
        result, calls, _ = self.fake_probe(failure=failure)
        self.assertEqual(result["check"], "credit_balance_exhausted")
        self.assertEqual(len(calls), 1)

    def test_transport_exception_cannot_leak_credential(self):
        result, _, _ = self.fake_probe(failure=RuntimeError(INTENDED))
        self.assertEqual(result, {"ok": False, "check": "transport_or_protocol_error"})

    def test_rejects_malformed_success_and_oversize_responses(self):
        for body in ([], {"error": {"message": INTENDED}}, {"data": "incorrect"}):
            result, _, _ = self.fake_probe(body=body)
            self.assertEqual(result["check"], "invalid_response")
        result, _, _ = self.fake_probe(body={"data": [], "padding": "x" * CHECK.BODY_LIMIT})
        self.assertEqual(result["check"], "response_too_large")

    def test_redirect_handler_refuses_forwarding(self):
        self.assertIsNone(CHECK.NoRedirect().redirect_request(None, None, 302, "", {},
                                                            "https://untrusted.invalid"))


if __name__ == "__main__":
    unittest.main()
