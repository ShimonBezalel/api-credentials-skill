---
name: api-credentials
description: Select and troubleshoot OpenAI or Anthropic (Claude) API credentials before API work, reviewer measurements, or recovery from authentication, model access, rate limit, quota or billing errors. Honor account, project and key-file choices before inherited environment keys; keep secrets local. Use for API access, not ordinary Codex or Claude subscription status.
---

# API credentials

Resolve the intended provider, account/project/workspace and credential source before
an API call. A valid inherited key can belong to the wrong billing account.

## Select and locate

1. Honor the user's explicit credential file and account/project/workspace. An
   explicit file wins over `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`; if it is missing,
   unreadable or invalid, stop selection rather than falling back. An account name
   or project header does not establish that an arbitrary environment key belongs
   to it. Match the source to trusted local setup documentation or the provider
   console. Treat identity as unverified when that evidence is absent.
2. Inspect the supplied locator first, then relevant local setup notes, project
   configuration and documented secret-file/keychain locations. Inspect filenames
   and variable presence without printing values. A bounded filename search in the
   home directory for `*openai*key*` or `*anthropic*key*` can find a previously
   documented file. Do not dump `.env`, shell profiles, keychains or runtime auth
   stores. Do not start a cloud/SSH/secret-manager hunt without evidence pointing
   there. Multiple plausible keys for different accounts are a true fork.
3. If the intended key remains unavailable, promptly ask one precise question:
   “Which local credential file or secret-store entry should I use for [provider,
   account/project] on this machine?” Ask for a locator, never a pasted key. Do
   independent work while awaiting the answer; do not substitute another account.
4. Use an inherited environment credential only when its provenance matches the
   task and no explicit choice conflicts. Report the provider and source kind,
   observed checks and uncertainty; omit private locators from shared artifacts.

### Private machine notes

When selecting a previously configured task or account, read
`~/.config/api-credentials/locations.md` if it exists on this machine. These
user-maintained notes contain task/account labels and secret-file locators only.
Resolve and validate the selected local file before using an inherited key.
Keep the notes private and outside Git; public skill instructions may document
this lookup convention, but must not include actual secret values or private
account/file records. Do not sync credentials or machine-specific notes.

## Check safely, then use

The optional stdlib helper [scripts/credential_check.py](scripts/credential_check.py)
checks a raw single-key file offline by default. It refuses silent environment
fallback, unsafe file permissions, redirects and custom endpoints. It does not
create keys, export secrets, run children or change billing/configuration.

```bash
python3 /absolute/path/to/api-credentials/scripts/credential_check.py openai --key-file /private/local/key.txt
```

Add `--probe` for one non-generating GET to the provider's `/v1/models`; add
`--model MODEL_ID` to retrieve that specific model instead. For OpenAI, explicitly
chosen `--organization ORG_ID` and `--project PROJECT_ID` set request headers.
`--account LABEL` expresses intended provenance and requires a file, but does not
verify ownership. Environment selection requires `--allow-env` and cannot express
account scope. The helper ignores inherited base URLs and organization/project
variables; pass intended IDs explicitly. Offline success proves only local
availability. GET success proves that endpoint accepted the credential and, for
a model retrieval, exposed metadata. Neither proves generation permission,
available credits, spending headroom or account ownership. A restricted key may
allow generation yet forbid model metadata; do not widen permissions for a probe.

For actual authorized work, read the selected file inside the intended process
and pass the key directly to the SDK/client in memory. If a tool requires an
environment variable, build that child's environment in memory, overriding the
inherited provider key and explicitly setting/removing stale scope/base-URL
variables. Do not export globally or edit shell profiles. Disable SDK HTTP/debug
logging and secret-bearing exception output. Keep model calls within the user's
authorized measurement/task budget; a probe does not authorize paid testing.

Never put key values in commands, subprocess arguments, logs, HTTP traces,
messages, screenshots, artifacts or Git. Do not print prefixes, suffixes or
fingerprints. New secret files belong outside the checkout with mode `0600`
(private parent directory `0700`); repair overly broad permissions on an owned
file before reading it. Keep credentials on the machine where provisioned. Sync
the skill, not secrets, and resolve local locators again on another machine.

## Recover the specific failure

Check the **selected source first**, then the HTTP status and structured
`error.code` / `error.type` from a sanitized response. Do not repeat raw server
messages: they can echo secrets. Do not declare all API work blocked from a
failure on an unintended credential.

| Observation | Next action |
| --- | --- |
| Authentication (401) | Check source, revocation/expiry, selected org and any IP restrictions. A new key may be needed; do not create one without authorization. |
| Permission/model access (403/404) | Check exact model/endpoint, key permissions and project/workspace policy. Do not infer credit exhaustion or silently change models/accounts. |
| Rate limit (429 with rate-limit code/type) | Respect retry timing; use bounded backoff and reduce concurrency within the task budget. |
| `credit_balance_exhausted` | The selected OpenAI organization has depleted prepaid credits. Verify intended source; a new key in the same account does not replenish credits. Ask for the necessary billing action if this is the intended account. |
| `organization_spend_limit_exceeded`, `project_spend_limit_exceeded`, `organization_usage_limit_exceeded` | Distinguish enforced caps/approved usage limits from rate limits and credit balance. Verify the specific control in the intended account. |
| `insufficient_quota` or Claude billing error | Inspect the specific code and intended console billing evidence; retain uncertainty when only a broad type is available. Stop billing retries. |
| Timeout/network/5xx | A connectivity or service failure does not establish invalid credentials or billing status. Retry only within a bounded task budget. |

API billing is separate from ChatGPT/Codex and Claude subscription usage. Verify
how the particular process authenticated: subscription login and API-key mode
can bill differently. Platform ownership is capability, not permission to create
or rotate keys, alter IAM/model access/spend controls, or buy credits.

When a new key is needed, explain the supported path: the human selects the
intended OpenAI organization and project in Platform settings, opens that
project's API Keys and creates a secret with appropriate permissions. For
automation, a project service account is an option when expressly authorized;
use current supported documentation rather than inventing a generic user-key
creation endpoint. For Claude, select the intended Console organization/workspace
and API Keys. Store a new secret locally without displaying it. Never replace or
revoke an existing production key as an incidental troubleshooting step.

## Sources and maintenance

Checked 2026-10-02. Refresh official guidance for mutations or changed errors:
[OpenAI errors](https://developers.openai.com/api/docs/guides/error-codes),
[OpenAI permissions](https://developers.openai.com/api/docs/guides/rbac),
[project API keys](https://platform.openai.com/docs/api-reference/project-api-keys),
[service-account key creation](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/service_accounts/subresources/api_keys/methods/create),
[OpenAI models](https://developers.openai.com/api/reference/resources/models/methods/list),
[Claude models](https://platform.claude.com/docs/en/api/models/list),
[Claude errors](https://platform.claude.com/docs/en/api/errors),
[Codex authentication](https://developers.openai.com/codex/auth),
[Claude Code costs](https://code.claude.com/docs/en/costs).

Reuse review: existing GCP credential skills cover a different provider; imagegen's
environment-presence check does not select account provenance. Reuse the repo's
skill sync and stdlib HTTP/file APIs. Keep one bounded selection/probe helper;
defer registries, remote discovery, key provisioning and subprocess launchers.
