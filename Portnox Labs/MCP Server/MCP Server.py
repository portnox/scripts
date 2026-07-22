#!/usr/bin/env python3
"""Portnox CLEAR MCP Server.

This module implements a Model Context Protocol (MCP) server that wraps the
Portnox CLEAR REST API. It exposes API operations as MCP "tools" so that
AI assistants (e.g. Claude, Copilot) can call them directly by name.

Covered API areas:
  - NAS devices          : list and batch-update network access switches.
  - Sites                : CRUD operations on Portnox deployment sites.
  - Site rules           : update subnet / IP-range rules on a site.
  - Devices (endpoints)  : list, search, block, unblock, and delete end-user
                           devices tracked by Portnox.

Transport modes supported:
  - stdio        : used by local MCP clients (e.g. Claude Desktop). The server
                   reads JSON-RPC messages from stdin and writes replies to
                   stdout.
  - sse          : Server-Sent Events over HTTP; useful for web-based clients.
  - streamable-http : bidirectional HTTP streaming introduced in newer MCP SDKs.
  - daemon       : any of the above, but the process detaches from the
                   terminal using a standard Unix double-fork so it runs as a
                   background service.

Authentication:
	Portnox CLEAR can authenticate using either:
	- A long-lived API token (PORTNOX_TOKEN / PORTNOX_TOKEN_FILE), or
	- Local Portnox Cloud admin credentials (PORTNOX_USERNAME + PORTNOX_PASSWORD).

	Note: Federated identities (Entra ID, Okta, Google Workspace, Active
	Directory) are not supported for this credential flow; use only local
	Portnox Cloud admin accounts.

	When token auth is used, the token is sent on every request as both a
	standard Bearer token (Authorization header) and the proprietary
	X-API-Token header for compatibility with all deployment variants.

# Legal Disclaimer

The Portnox MCP Server is an open source project sponsored by Portnox and
licensed under the Apache License, Version 2.0. The terms of the Apache 2.0
license govern your use of this software.

## Support

The Portnox MCP Server is not an officially supported Portnox product. It is
provided as a community-supported project, and Portnox does not provide
technical support, service level agreements (SLAs), maintenance commitments,
or guaranteed response times for issues related to this software.

Bug reports, feature requests, and questions should be submitted through the
project's GitHub repository.

## Community Contributions

Community contributions are welcome. Bug fixes, new features, documentation
improvements, and other enhancements may be submitted as GitHub pull requests.

Portnox may periodically review community submissions and, at its sole
discretion, accept, reject, modify, or merge contributions that are
appropriate for the project. Submission of a contribution does not guarantee
that it will be incorporated into future releases.

## Use Responsibly

The Portnox MCP Server is capable of reading from and writing to your Portnox
Cloud tenant. Depending on the prompts provided and the permissions granted to
the MCP server, it may create, modify, or delete configuration objects and
settings.

Before using the software in a production environment, you should carefully
review the permissions granted to the MCP server, validate the actions it is
authorized to perform, and test any automation or AI workflows in a
non-production environment whenever practical.

Improper configuration, unintended prompts, software defects, or misuse of the
MCP server may result in unintended configuration changes, including changes
that could disrupt authentication, authorization, network connectivity, policy
enforcement, or other services managed by your Portnox Cloud tenant.

You are solely responsible for reviewing, validating, and approving any
changes made through the MCP server and for ensuring that appropriate backup,
recovery, and change management procedures are in place.

## License

This project is licensed under the Apache License, Version 2.0. By using,
modifying, or distributing this software, you agree to the terms and
conditions of that license, including its provisions regarding warranties,
liability, and patent rights.

Security Notice: We recommend creating a dedicated Portnox Cloud
administrator account for use with the MCP server and granting it only the
permissions required for your intended workflows. Avoid using personal
administrator accounts or credentials with unrestricted administrative access.
Following the principle of least privilege can significantly reduce the impact
of unintended or incorrect MCP operations.
"""

# Allow deferred evaluation of type annotations (PEP 563).
# This lets us write `-> "PortnoxClient"` in methods before the class is fully
# defined without causing a NameError at import time.
from __future__ import annotations

# ---------------------------------------------------------------------------
# Standard-library imports
# ---------------------------------------------------------------------------
import argparse   # CLI argument parsing for transport/host/port/daemon flags.
import inspect    # Runtime introspection used to call SDK methods safely.
import json       # Serialising request payloads to JSON strings.
import logging    # Structured log output (timestamps, levels, logger names).
import os         # Environment variable access and low-level Unix fork/dup2.
import signal     # SIGTERM / SIGINT handlers for graceful daemon shutdown.
import subprocess  # Shell out to openssl for TLS cert generation/conversion.
import sys        # stdin/stdout manipulation and sys.exit.
from dataclasses import dataclass   # Lightweight value-object for config.
from pathlib import Path            # Typed filesystem path operations.
from typing import Any, Dict, List, Optional  # Generic type hints.

# ---------------------------------------------------------------------------
# Third-party imports
# ---------------------------------------------------------------------------
import requests          # HTTP client used for all Portnox REST calls.
import uvicorn           # ASGI server used to host the MCP app over HTTP.
from mcp.server.fastmcp import FastMCP  # MCP server framework.

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Default base URL for the Portnox CLEAR cloud portal REST API.
# Can be overridden via the PORTNOX_BASE_URL environment variable to point at
# an on-premises or staging deployment.
DEFAULT_BASE_URL = "https://clear.portnox.com:8081/CloudPortalBackEnd"

# Default value for the `Mode` field expected by the /api/nases endpoint.
# Mode controls which subset of NAS data the server returns; 0 = standard.
DEFAULT_MODE = 0

# Default value for the `Info` field expected by the /api/nases endpoint.
# Info is a bitmask that controls additional data inclusions; 0 = minimal.
DEFAULT_INFO = 0


def _as_bool(value: str) -> bool:
	"""Parse common truthy string values from env/CLI text."""
	return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _run_openssl(command: List[str]) -> None:
	"""Run an openssl command and raise ValueError with concise stderr on failure."""
	try:
		subprocess.run(command, check=True, capture_output=True, text=True)
	except FileNotFoundError as exc:
		raise ValueError(
			"OpenSSL is required for HTTPS certificate generation/conversion but was not found."
		) from exc
	except subprocess.CalledProcessError as exc:
		stderr = (exc.stderr or "").strip().replace("\n", " ")
		raise ValueError(f"OpenSSL command failed: {stderr[:300]}") from exc


def _generate_self_signed_cert(cert_file: Path, key_file: Path, common_name: str) -> None:
	"""Create a self-signed certificate pair if one does not already exist."""
	if cert_file.exists() and key_file.exists():
		return

	cert_file.parent.mkdir(parents=True, exist_ok=True)

	_run_openssl(
		[
			"openssl",
			"req",
			"-x509",
			"-newkey",
			"rsa:2048",
			"-sha256",
			"-nodes",
			"-days",
			"825",
			"-subj",
			f"/CN={common_name}",
			"-addext",
			"subjectAltName=DNS:localhost,IP:127.0.0.1",
			"-keyout",
			str(key_file),
			"-out",
			str(cert_file),
		]
	)

	os.chmod(key_file, 0o600)
	os.chmod(cert_file, 0o644)


def _convert_pkcs12_to_pem(
	pfx_file: Path,
	pfx_password: str,
	out_cert_file: Path,
	out_key_file: Path,
) -> None:
	"""Convert PKCS#12 (.pfx/.p12) into PEM cert+key files for uvicorn."""
	if not pfx_file.exists():
		raise ValueError(f"TLS PKCS#12 file does not exist: {pfx_file}")

	out_cert_file.parent.mkdir(parents=True, exist_ok=True)
	passin = f"pass:{pfx_password}" if pfx_password else "pass:"

	_run_openssl(
		[
			"openssl",
			"pkcs12",
			"-in",
			str(pfx_file),
			"-clcerts",
			"-nokeys",
			"-out",
			str(out_cert_file),
			"-passin",
			passin,
		]
	)

	_run_openssl(
		[
			"openssl",
			"pkcs12",
			"-in",
			str(pfx_file),
			"-nocerts",
			"-nodes",
			"-out",
			str(out_key_file),
			"-passin",
			passin,
		]
	)

	os.chmod(out_key_file, 0o600)
	os.chmod(out_cert_file, 0o644)


def _resolve_tls_files(args: argparse.Namespace) -> Dict[str, Optional[str]]:
	"""Resolve effective TLS settings and ensure certificate files exist.

	Precedence:
	1) Explicit PEM/CRT + KEY
	2) PKCS#12 bundle conversion
	3) Auto-generated self-signed cert
	"""
	enabled = bool(getattr(args, "https", False))
	if not enabled:
		return {"enabled": False, "certfile": None, "keyfile": None}

	tls_cert_file = (getattr(args, "tls_cert_file", "") or "").strip()
	tls_key_file = (getattr(args, "tls_key_file", "") or "").strip()
	tls_pfx_file = (getattr(args, "tls_pfx_file", "") or "").strip()
	tls_pfx_password = (getattr(args, "tls_pfx_password", "") or "")
	tls_cert_dir = Path((getattr(args, "tls_cert_dir", "") or "/tmp/portnox-mcp-tls").strip())
	tls_self_signed_cn = (getattr(args, "tls_self_signed_cn", "localhost") or "localhost").strip()

	if tls_cert_file or tls_key_file:
		if not tls_cert_file or not tls_key_file:
			raise ValueError("When using PEM/CRT TLS files, provide both --tls-cert-file and --tls-key-file.")
		cert_path = Path(tls_cert_file)
		key_path = Path(tls_key_file)
		if not cert_path.exists():
			raise ValueError(f"TLS cert file does not exist: {cert_path}")
		if not key_path.exists():
			raise ValueError(f"TLS key file does not exist: {key_path}")
		return {"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)}

	if tls_pfx_file:
		pfx_path = Path(tls_pfx_file)
		converted_cert = tls_cert_dir / "tls-from-pkcs12.crt"
		converted_key = tls_cert_dir / "tls-from-pkcs12.key"
		_convert_pkcs12_to_pem(pfx_path, tls_pfx_password, converted_cert, converted_key)
		return {"enabled": True, "certfile": str(converted_cert), "keyfile": str(converted_key)}

	self_cert = tls_cert_dir / "selfsigned.crt"
	self_key = tls_cert_dir / "selfsigned.key"
	_generate_self_signed_cert(self_cert, self_key, tls_self_signed_cn)
	return {"enabled": True, "certfile": str(self_cert), "keyfile": str(self_key)}


def _configure_logging(level: str = "INFO") -> None:
	"""Initialise the root Python logger.

	Called once at startup so every module that uses `logging.getLogger()`
	inherits the same format and threshold.  The format includes a timestamp,
	severity level, logger name, and the message, which is useful for
	diagnosing issues when running as a daemon with output redirected to a
	log file.
	"""
	logging.basicConfig(
		level=getattr(logging, level.upper(), logging.INFO),
		# Fall back to INFO if an unrecognised level string is supplied.
		format="%(asctime)s %(levelname)s %(name)s: %(message)s",
	)


@dataclass
class PortnoxConfig:
	"""Immutable configuration bundle read from environment variables.

	Using a dataclass keeps all configuration in one place and makes it easy
	to inject alternatives in tests without monkey-patching os.environ.
	"""

	# Full base URL of the Portnox CLEAR REST API, without a trailing slash.
	base_url: str

	# Long-lived API token issued by Portnox CLEAR.  Treat as a secret;
	# never log or expose this value.  Optional when using username/password.
	token: Optional[str] = None

	# Optional local Portnox Cloud admin username for credential-based auth.
	# Federated accounts are not supported by this flow.
	username: Optional[str] = None

	# Optional local Portnox Cloud admin password for credential-based auth.
	# Treat as a secret and never log it.
	password: Optional[str] = None

	# How long (in seconds) to wait for a response before raising a timeout
	# error.  30 seconds is a generous default for a cloud API.
	timeout_seconds: int = 30

	# Whether to verify the server's TLS certificate.  Should always be True
	# in production; set False only in isolated test environments.
	verify_tls: bool = True

	@classmethod
	def from_env(cls) -> "PortnoxConfig":
		"""Construct a PortnoxConfig from environment variables.

		Environment variables consulted:
		  PORTNOX_BASE_URL         - override the default cloud URL.
		  PORTNOX_TOKEN            - long-lived API token (fallback input).
		  PORTNOX_TOKEN_FILE       - preferred path to a file containing the
		                             long-lived API token (for container secrets).
		  PORTNOX_USERNAME         - Portnox Cloud administrator username.
		  PORTNOX_PASSWORD         - Portnox Cloud administrator password.
		  PORTNOX_TIMEOUT_SECONDS  - per-request HTTP timeout (default 30).
		  PORTNOX_VERIFY_TLS       - set to "false" to skip TLS verification.

		Raises ValueError if neither token auth nor username/password auth is
		fully configured, because every API call would fail with a 401 without
		authentication.
		"""
		# Strip any trailing slash from the base URL so we can safely append
		# paths with a leading slash later.
		base_url = os.getenv("PORTNOX_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

		# Prefer loading the token from a file path so operators can mount a
		# Docker/OCI secret as a read-only file rather than exposing the token
		# in process environments and shell history.
		token = ""
		token_file = os.getenv("PORTNOX_TOKEN_FILE", "").strip()
		if token_file:
			try:
				token = Path(token_file).read_text(encoding="utf-8").strip()
			except OSError as exc:
				raise ValueError(
					f"Unable to read PORTNOX_TOKEN_FILE '{token_file}': {exc}"
				) from exc

		# Backward-compatible fallback for existing local/dev deployments.
		if not token:
			token = os.getenv("PORTNOX_TOKEN", "").strip()

		# Optional credential-based authentication input.  When provided, these
		# are used as HTTP Basic auth credentials on each API request.
		username = os.getenv("PORTNOX_USERNAME", "").strip()
		password = os.getenv("PORTNOX_PASSWORD", "")
		if password is not None:
			password = password.strip()

		# Coerce to int; an invalid value will raise ValueError at startup,
		# which is preferable to silently using a default.
		timeout_seconds = int(os.getenv("PORTNOX_TIMEOUT_SECONDS", "30"))

		# Any value other than the literal string "false" (case-insensitive)
		# keeps TLS verification enabled, which is the safe default.
		verify_tls = os.getenv("PORTNOX_VERIFY_TLS", "true").lower() != "false"

		# Validate that at least one auth mechanism is configured.
		has_token_auth = bool(token)
		has_password_auth = bool(username and password)

		# Reject partial username/password configuration because it is almost
		# always an operator mistake and would otherwise fail later at runtime.
		if (username and not password) or (password and not username):
			raise ValueError(
				"Incomplete credential configuration. Set both PORTNOX_USERNAME "
				"and PORTNOX_PASSWORD, or use PORTNOX_TOKEN_FILE/PORTNOX_TOKEN."
			)

		if not has_token_auth and not has_password_auth:
			raise ValueError(
				"Missing authentication configuration. Set PORTNOX_TOKEN_FILE "
				"(preferred) or PORTNOX_TOKEN, or set PORTNOX_USERNAME and "
				"PORTNOX_PASSWORD for HTTP Basic authentication."
			)

		return cls(
			base_url=base_url,
			token=token or None,
			username=username or None,
			password=password or None,
			timeout_seconds=timeout_seconds,
			verify_tls=verify_tls,
		)


class PortnoxApiError(RuntimeError):
	"""Raised when the Portnox API returns an error or unexpected response.

	Wrapping all API errors in a single exception type lets callers (and MCP
	tool handlers) catch one exception class rather than distinguishing between
	HTTP errors, JSON decode failures, and schema validation failures.
	"""
	pass


class PortnoxClient:
	"""Low-level HTTP client for the Portnox CLEAR REST API.

	Each method maps 1-to-1 to a single REST endpoint.  All request/response
	serialisation and HTTP status code mapping is done here so that the MCP
	tool layer above only deals with Python objects and PortnoxApiError.

	The client uses a persistent requests.Session so that the underlying TCP
	connection (and TLS handshake) can be reused across multiple calls during a
	single tool invocation, reducing latency.
	"""

	def __init__(self, config: PortnoxConfig):
		"""Initialise the client and configure the shared HTTP session.

		The session is created once and reused for all API calls.  Common
		headers are set at the session level so they are included automatically
		on every request without needing to pass them individually.
		"""
		self._config = config

		# A Session object maintains a connection pool and default headers,
		# making it more efficient than issuing isolated requests.get() calls.
		self._session = requests.Session()

		# Always set request/response content headers, regardless of auth mode.
		self._session.headers.update(
			{
				"Content-Type": "application/json",
				"Accept": "application/json",
			}
		)

		# Primary auth path: long-lived token (most stable for automation).
		if isinstance(config.token, str) and config.token.strip():
			self._apply_token_auth_headers(config.token.strip())
			return

		# Secondary auth path: Portnox Cloud administrator credentials.
		# Per Portnox documentation, API requests use HTTP Basic auth directly
		# on each request rather than a separate login handshake endpoint.
		if config.username and config.password:
			self._apply_basic_auth_credentials(
				username=config.username,
				password=config.password,
			)
			return

		# Defensive fallback: from_env() should have prevented this state.
		raise PortnoxApiError(
			"No valid authentication configuration found. Configure token auth "
			"or username/password auth."
		)

	def _apply_token_auth_headers(self, token: str) -> None:
		"""Apply token-based auth headers to the shared HTTP session.

		The Portnox API may validate either standard Bearer auth or the
		proprietary X-API-Token header depending on deployment/version.  We set
		both for broad compatibility.
		"""
		self._session.headers.update(
			{
				"Authorization": f"Bearer {token}",
				"X-API-Token": token,
			}
		)

	def _apply_basic_auth_credentials(self, username: str, password: str) -> None:
		"""Apply HTTP Basic authentication credentials to the shared session.

		Portnox Cloud API documentation states that administrator credentials are
		sent using HTTP Basic auth with each request. requests.Session handles
		this by attaching an Authorization header automatically per call.
		"""
		self._session.auth = (username, password)

	def _extract_error_detail_from_response(self, response: requests.Response) -> str:
		"""Extract a concise human-readable error detail from an HTTP response."""
		def _first_string(value: Any) -> Optional[str]:
			if isinstance(value, str) and value.strip():
				return value.strip()
			if isinstance(value, dict):
				for key in (
					"message",
					"error",
					"detail",
					"details",
					"reason",
					"title",
					"description",
				):
					if key in value:
						found = _first_string(value.get(key))
						if found:
							return found
				for nested in value.values():
					found = _first_string(nested)
					if found:
						return found
			if isinstance(value, list):
				for nested in value:
					found = _first_string(nested)
					if found:
						return found
			return None

		try:
			body = response.json()
		except ValueError:
			body = None

		if body is not None:
			found = _first_string(body)
			if found:
				return found[:500]

		text = (response.text or "").replace("\n", " ").replace("\r", " ").strip()
		if text.startswith("\ufeff"):
			text = text.lstrip("\ufeff")
		return text[:500]

	def _extract_token_from_login_response(self, body: Any) -> Optional[str]:
		"""Try to extract an API token from common login response shapes.

		Portnox deployment variants may return token fields with different key
		names and nesting.  This helper searches known field names recursively.
		"""
		candidate_keys = {
			"token",
			"access_token",
			"accesstoken",
			"api_token",
			"apitoken",
			"jwttoken",
			"id_token",
			"bearer",
		}

		def _walk(value: Any) -> Optional[str]:
			if isinstance(value, dict):
				for key, nested in value.items():
					if key.lower() in candidate_keys and isinstance(nested, str) and nested.strip():
						return nested.strip()
					found = _walk(nested)
					if found:
						return found
			elif isinstance(value, list):
				for nested in value:
					found = _walk(nested)
					if found:
						return found
			return None

		return _walk(body)

	def _login_with_local_admin_credentials(self, username: str, password: str) -> Optional[str]:
		"""Authenticate using local Portnox Cloud admin credentials.

		Tries a small set of common login endpoints/payload shapes used by
		Portnox deployment variants.  On success, returns a token when provided,
		or None when authentication is cookie/session based.
		"""
		endpoints = [
			"/api/account/login",
			"/api/auth/login",
			"/api/login",
			"/account/login",
			"/auth/login",
		]

		# Many Portnox variants accept different key names and body formats.
		# Try JSON payloads first, then form-encoded fallbacks.
		request_variants = [
			("json", {"Username": username, "Password": password}),
			("json", {"UserName": username, "Password": password}),
			("json", {"username": username, "password": password}),
			("json", {"Email": username, "Password": password}),
			("json", {"Login": username, "Password": password}),
			("form", {"Username": username, "Password": password}),
			("form", {"UserName": username, "Password": password}),
			("form", {"username": username, "password": password}),
			("form", {"Email": username, "Password": password}),
			("form", {"Login": username, "Password": password}),
		]

		last_error: Optional[str] = None
		attempt_summaries: List[str] = []

		for path in endpoints:
			endpoint = f"{self._config.base_url}{path}"
			for mode, payload in request_variants:
				try:
					kwargs: Dict[str, Any] = {
						"timeout": self._config.timeout_seconds,
						"verify": self._config.verify_tls,
					}
					if mode == "json":
						kwargs["json"] = payload
					else:
						kwargs["data"] = payload
						kwargs["headers"] = {
							"Content-Type": "application/x-www-form-urlencoded",
							"Accept": "application/json, text/plain, */*",
						}

					response = self._session.post(endpoint, **kwargs)
				except requests.RequestException as exc:
					last_error = f"{endpoint} ({mode}): {exc}"
					attempt_summaries.append(last_error)
					continue

				if response.status_code == 404:
					# Endpoint not present on this deployment variant; try next.
					attempt_summaries.append(f"{endpoint} ({mode}): HTTP 404")
					continue

				if response.status_code in (401, 403):
					raise PortnoxApiError(
						"Local admin credential authentication failed (HTTP "
						f"{response.status_code}). Verify PORTNOX_USERNAME/PORTNOX_PASSWORD "
						"and ensure the account is a local Portnox Cloud admin (not federated)."
					)

				if response.status_code >= 400:
					body_preview = response.text.replace("\n", " ").replace("\r", " ").strip()
					if body_preview.startswith("\ufeff"):
						body_preview = body_preview.lstrip("\ufeff")
					body_preview = body_preview[:220]
					last_error = (
						f"{endpoint} ({mode}): HTTP {response.status_code}: {body_preview}"
					)
					attempt_summaries.append(last_error)
					continue

				# Success status.  Try parsing token from JSON response first.
				try:
					body = response.json()
				except ValueError:
					body = None

				token = self._extract_token_from_login_response(body) if body is not None else None
				if token:
					return token

				# If no token was returned but the session now has cookies, assume
				# cookie-based login succeeded and let subsequent API calls use them.
				if self._session.cookies:
					return None

				last_error = (
					f"{endpoint} ({mode}): login succeeded but no token/cookie session was returned"
				)
				attempt_summaries.append(last_error)

		detail = ""
		if attempt_summaries:
			detail = " Tried: " + " | ".join(attempt_summaries[-5:])
		raise PortnoxApiError(
			"Unable to authenticate with local admin credentials. "
			f"Last error: {last_error or 'no login endpoint accepted the request'}.{detail}"
		)

	def close(self) -> None:
		"""Explicitly close the session and release all pooled connections.

		Called in the `finally` block of main() to ensure TCP connections are
		torn down cleanly even if the server exits due to an exception.
		"""
		if self._session:
			self._session.close()

	def __enter__(self) -> "PortnoxClient":
		"""Support usage as a context manager (with PortnoxClient(...) as c:).

		Returns self so the caller can immediately use the client inside the
		`with` block.
		"""
		return self

	def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
		"""Ensure close() is always called when exiting a `with` block.

		exc_type/exc_val/exc_tb are the exception details if an error occurred
		inside the block; we do not suppress them (returning None is falsy).
		"""
		self.close()

	def get_sites(self) -> List[Dict[str, Any]]:
		"""Retrieve all Portnox sites via GET /api/nases/sites.

		Sites are logical groupings of NAS devices (e.g. by physical location
		or network segment).  Each site can contain IP-based membership rules
		that determine which devices belong to it.

		Returns:
			A list of site objects.  Each site typically contains keys:
			Id, Name, Description, ParentId, Rules.

		Raises:
			PortnoxApiError: on any HTTP error or unexpected response shape.
		"""
		# Build the full endpoint URL by appending the path to the base URL.
		# The base URL has already had its trailing slash stripped in from_env().
		endpoint = f"{self._config.base_url}/api/nases/sites"

		try:
			response = self._session.get(
				endpoint,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			# Catches connection errors, DNS failures, timeouts, etc.
			# We re-raise as PortnoxApiError so callers only need to catch one
			# exception type, and the original exception is chained for context.
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				# The server returned a 200 but with non-JSON body (e.g. an HTML
				# error page from a proxy).  Surface this as an API error.
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict wrapping a "Sites" array.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			# Extract the Sites array; default to empty list if key is absent.
			sites = body.get("Sites", [])
			if not isinstance(sites, list):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")
			return sites

		# Map documented error codes to human-readable messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		# Any other unexpected status code is surfaced with the first 500 chars
		# of the body to aid debugging without logging excessively large payloads.
		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def create_or_update_site(self, site_data: Dict[str, Any]) -> Dict[str, Any]:
		"""Create or update a Portnox site via PUT /api/nases/sites.

		The Portnox API uses a single PUT endpoint for both create and update
		operations; it distinguishes between them by the presence of an Id field
		in the payload.  This method sends the full site object as-is so the
		caller is responsible for providing the correct Id when updating.

		Args:
			site_data: Site object with Name, Description, ParentId, Rules array.
			           Include Id to update an existing site; omit it to create.

		Returns:
			The created/updated site object returned by the API.

		Raises:
			PortnoxApiError: on any HTTP error or unexpected response shape.
		"""
		endpoint = f"{self._config.base_url}/api/nases/sites"

		try:
			# PUT replaces the entire site resource.  We use json.dumps() rather
			# than the `json=` kwarg so the payload is explicitly serialised as a
			# string; this avoids any encoding issues with the Content-Type header
			# we set at the session level.
			response = self._session.put(
				endpoint,
				data=json.dumps(site_data),
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The API returns the saved site as a dict on success.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")
			return body

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def delete_site(self, site_id: str) -> None:
		"""Delete a Portnox site via DELETE /api/nases/sites/{siteId}.

		Args:
			site_id: The unique site identifier as returned in the Id field.

		Raises:
			PortnoxApiError: on any HTTP error.
		"""
		# Embed the site ID directly in the URL path as a path parameter.
		endpoint = f"{self._config.base_url}/api/nases/sites/{site_id}"

		try:
			response = self._session.delete(
				endpoint,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		# 200 with no body means the site was deleted successfully.
		if response.status_code == 200:
			return

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		# 404 is unique to delete; the site ID may already be gone.
		if response.status_code == 404:
			raise PortnoxApiError("Site was not found (HTTP 404).")
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def update_site_rules(self, site_id: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
		"""Replace all subnet/IP-range membership rules for a site.

		Sends POST /api/nases/sites/{siteId}/rules with the complete new rules
		array.  This is a full replacement, not a merge — existing rules not
		present in the new list will be removed.

		Rule object fields:
		  Type  (int)  : 1 = CIDR subnet, 2 = IP range.
		  From  (str)  : Start IP address (or network address for CIDR).
		  To    (str)  : End IP address for range rules; null for CIDR rules.
		  Mask  (str)  : Prefix length (e.g. "24") for CIDR rules; null for ranges.

		Args:
			site_id: The unique site identifier.
			rules:   List of rule objects as described above.

		Returns:
			The updated site object returned by the API.

		Raises:
			PortnoxApiError: on any HTTP error or unexpected response shape.
		"""
		endpoint = f"{self._config.base_url}/api/nases/sites/{site_id}/rules"

		# The API expects the rules wrapped in a `Rules` key.
		payload = {"Rules": rules}

		try:
			response = self._session.post(
				endpoint,
				data=json.dumps(payload),
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			# Some API versions nest the site object under a "Site" key.
			site = body.get("Site")
			if isinstance(site, dict):
				return site

			# Other deployment variants return the site object at the top level.
			# Detect this by checking for known site fields.
			if "Id" in body and "Rules" in body:
				return body

			raise PortnoxApiError("Portnox API returned unexpected response shape.")

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 404:
			raise PortnoxApiError("Site was not found (HTTP 404).")
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def list_devices(
		self,
		page_number: int = 1,
		page_size: int = 10,
		search_value: Optional[str] = None,
		search_field: Optional[int] = None,
		include_account_without_devices: bool = False,
		client_time_offset: int = 0,
		start_time_limit: Optional[Any] = None,
		end_time_limit: Optional[Any] = None,
		start_reported_time_limit: Optional[str] = None,
		end_reported_time_limit: Optional[str] = None,
		start_created_time_limit: Optional[str] = None,
		end_created_time_limit: Optional[str] = None,
	) -> Dict[str, Any]:
		"""Retrieve a single page of device records via POST /api/device/list.

		The Portnox device list API is paginated; this method retrieves exactly
		one page.  To retrieve all pages automatically, use the higher-level
		`find_devices_by_account_name` method or the `list_all_devices` MCP tool.

		The endpoint accepts a complex JSON body rather than URL query parameters.
		We build the body here from individual Python arguments so callers do not
		need to know the JSON schema.

		Args:
			page_number:                   1-based page index (first page = 1).
			page_size:                     Number of records per page.
			search_value:                  Optional search string.
			search_field:                  Integer field selector for the search.
			                               Common values: 0 = all fields, 1 = email.
			include_account_without_devices: Include account rows that have no
			                               associated devices in the result set.
			client_time_offset:            Client UTC offset in minutes, used by
			                               the server to localise time filters.
			start_time_limit:              Filter: only devices last seen after this.
			end_time_limit:                Filter: only devices last seen before this.
			start_reported_time_limit:     Filter: start of reported-time range.
			end_reported_time_limit:       Filter: end of reported-time range.
			start_created_time_limit:      Filter: start of created-time range.
			end_created_time_limit:        Filter: end of created-time range.

		Returns:
			The raw API response dict, which typically contains:
			  Result       : list of account/device entries for this page.
			  TotalDevices : total number of devices across all pages.
			  TotalPages   : total number of pages given the requested page_size.

		Raises:
			PortnoxApiError: on invalid parameters, HTTP errors, or bad JSON.
		"""
		# Validate pagination inputs before sending a request that would fail
		# with an opaque 400 error from the server.
		if page_number < 1:
			raise PortnoxApiError("Missing or malformed parameter: 'page_number' must be >= 1.")
		if page_size < 1:
			raise PortnoxApiError("Missing or malformed parameter: 'page_size' must be >= 1.")

		endpoint = f"{self._config.base_url}/api/device/list"

		# The "Query" sub-object controls pagination and ordering.
		# Filter is intentionally null; Portnox uses a separate Search object.
		query_obj: Dict[str, Any] = {
			"Filter": None,
			"PageNumber": page_number,
			"PageSize": page_size,
			"Order": 0,       # 0 = ascending; the API ignores this if OrderBy is null.
			"OrderBy": None,  # null means use the server's default sort.
		}

		# The "Search" sub-object is optional.  Only populate it when a search
		# value is provided to avoid sending an empty search that may behave
		# differently from sending no search at all.
		search_obj: Optional[Dict[str, Any]] = None
		if search_value is not None:
			if not isinstance(search_value, str) or not search_value.strip():
				raise PortnoxApiError(
					"Missing or malformed parameter: 'search_value' must be a non-empty string when provided."
				)
			search_obj = {
				"Value": search_value.strip(),
				# Default to field 0 (all fields) when no specific field is given.
				"Field": int(search_field) if search_field is not None else 0,
			}

		# Assemble the full request body.  Time-limit fields are forwarded
		# as-is; null values tell the server to apply no time constraint.
		payload: Dict[str, Any] = {
			"Query": query_obj,
			"Search": search_obj,
			"ClientTimeOffset": client_time_offset,
			"IncludeAccountWithoutDevices": include_account_without_devices,
			"Order": None,
			"StartTimeLimit": start_time_limit,
			"EndTimeLimit": end_time_limit,
			"StartReportedTimeLimit": start_reported_time_limit,
			"EndReportedTimeLimit": end_reported_time_limit,
			"StartCreatedTimeLimit": start_created_time_limit,
			"EndCreatedTimeLimit": end_created_time_limit,
		}

		try:
			response = self._session.post(
				endpoint,
				data=json.dumps(payload),
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			# Validate that `Result` is a list if present.  A non-list Result
			# indicates an undocumented API change we should surface loudly.
			result = body.get("Result")
			if result is not None and not isinstance(result, list):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			# Return the full response dict so callers can inspect pagination
			# fields like TotalPages alongside the actual Result data.
			return body

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def block_device(self, entity_id: str, reason: str) -> None:
		"""Quarantine a device so it cannot access the network.

		Sends POST /api/device/block with the device's EntityId and a mandatory
		reason string.  Portnox records the reason in the audit log so admins
		can understand why a device was blocked when reviewing history.

		Args:
			entity_id: The unique device identifier (also called DeviceId).
			reason:    Human-readable explanation for the block action.

		Raises:
			PortnoxApiError: on any HTTP error.
		"""
		endpoint = f"{self._config.base_url}/api/device/block"

		# Build the minimal payload required by the block endpoint.
		payload = {"EntityId": entity_id, "Reason": reason}

		try:
			response = self._session.post(
				endpoint,
				data=json.dumps(payload),
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		# 200 with no meaningful body indicates success.
		if response.status_code == 200:
			return

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def block_account(self, entity_id: str, reason: str) -> None:
		"""Block a Portnox account so it can no longer access the network.

		Sends POST /api/account/block with the account's EntityId and a reason.
		This is the account-level equivalent of blocking a device: it is used when
		an account should be immediately denied access because of policy, security,
		or administrative reasons.

		Important operational context:
		  - The block reason is preserved in Portnox audit/history so operators
		    can understand why access was revoked later.
		  - Blocking an account is typically used for administrative containment,
		    temporary suspension, or policy enforcement.
		  - This does not delete the account; it only marks it as blocked.

		Common use cases:
		  - Security incident response: block an account immediately after a
		    compromise is detected to stop further network access.
		  - Administrative suspension: temporarily block an account while an issue
		    is investigated or until access is re-approved.
		  - Policy enforcement: block accounts that violate acceptable use or
		    onboarding requirements.
		  - Temporary containment: block access while credentials are being reset
		    or a user is moved to a different access path.

		Args:
			entity_id: The account identifier to block.  The API expects this in the
			           EntityId field and it is commonly an account username or ID.
			reason: Human-readable explanation that will be stored for auditability.

		Returns:
			None.  HTTP 200 indicates the account was successfully blocked.

		Raises:
			PortnoxApiError: if entity_id/reason are empty, or on any HTTP error
			               (400/401/403/500).
		"""
		# Validate inputs locally so we fail with a precise message instead of
		# relying on a generic server-side 400 response.
		if not isinstance(entity_id, str) or not entity_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'entity_id' must be a non-empty string."
			)
		if not isinstance(reason, str) or not reason.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'reason' must be a non-empty string."
			)

		# Build the exact payload the API expects for account blocking.
		payload = {"EntityId": entity_id.strip(), "Reason": reason.strip()}

		# Use the dedicated account block endpoint rather than the device block
		# endpoint so the server applies the correct account-level policy action.
		endpoint = f"{self._config.base_url}/api/account/block"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		# The API returns HTTP 200 with no body when the account is blocked.
		if response.status_code == 200:
			return None

		# Map documented error codes to clear, consistent messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def unblock_account(self, entity_id: str) -> None:
		"""Restore network access for a previously blocked Portnox account.

		Sends POST /api/account/unblock with the account's EntityId.  This is the
		account-level counterpart to `block_account()` and is used when a blocked
		account has been cleared for access again.

		Important operational context:
		  - Unblocking does not delete or recreate the account; it simply removes
		    the blocked state so the account can resume normal policy evaluation.
		  - Use this after investigations, approvals, or remediation steps are complete.
		  - The endpoint does not require a reason because the unblock itself is the
		    audit action.

		Common use cases:
		  - Incident resolution: restore access once a security incident has been
		    contained and the account is cleared for use.
		  - Administrative reinstatement: re-enable an account after manual review.
		  - Temporary suspension ended: remove a short-term block once the issue is fixed.

		Args:
			entity_id: The account identifier to unblock.  The API expects this in
			           the EntityId field and it should match the blocked account.

		Returns:
			None.  HTTP 200 indicates the account was successfully unblocked.

		Raises:
			PortnoxApiError: if entity_id is empty, or on any HTTP error
			               (400/401/403/500).
		"""
		# Validate the identifier locally so we fail fast with a descriptive
		# error instead of relying on the server's generic 400 response.
		if not isinstance(entity_id, str) or not entity_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'entity_id' must be a non-empty string."
			)

		# Build the minimal payload required by the account unblock endpoint.
		payload = {"EntityId": entity_id.strip()}

		# Use the dedicated account unblock endpoint so Portnox restores the
		# account-level block state rather than the device-level one.
		endpoint = f"{self._config.base_url}/api/account/unblock"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		# The API returns HTTP 200 with no body when the account is unblocked.
		if response.status_code == 200:
			return None

		# Map documented error codes to clear, consistent messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def unblock_device(self, entity_id: str) -> None:
		"""Restore network access for a previously blocked device.

		Sends POST /api/device/unblock.  The reason for the original block is
		cleared by Portnox when the device is unblocked.

		Args:
			entity_id: The unique device identifier to unblock.

		Raises:
			PortnoxApiError: on any HTTP error.
		"""
		endpoint = f"{self._config.base_url}/api/device/unblock"

		# Only the EntityId is required; no reason field for unblock.
		payload = {"EntityId": entity_id}

		try:
			response = self._session.post(
				endpoint,
				data=json.dumps(payload),
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			return

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def delete_account(self, account_id: str) -> None:
		"""Permanently delete a Portnox account.

		Sends DELETE /api/account with a JSON payload containing AccountId.
		This removes the specified account from Portnox.  Unlike blocking, which
		preserves the account and only suspends access, deletion is intended for
		accounts that should no longer exist in the system.

		Important operational context:
		  - Deletion is a stronger action than blocking because it removes the
		    account rather than temporarily suspending it.
		  - Use this for decommissioned cloud/contractor accounts, cleanup of
		    mistaken account creation, or lifecycle termination workflows.
		  - Because the API uses DELETE with a JSON body rather than a path
		    parameter, we must explicitly send the AccountId in the request body.

		Common use cases:
		  - Offboarding cleanup: permanently remove a contractor or cloud account
		    after the engagement ends.
		  - Duplicate account cleanup: delete an accidentally-created duplicate
		    account after migrating the user to the correct identity.
		  - Test data cleanup: remove temporary accounts created during validation
		    or integration testing.

		Args:
			account_id: The account identifier to delete.  The API expects this in
			            the AccountId field and it must be non-empty.

		Returns:
			None.  HTTP 200 indicates the account was successfully deleted.

		Raises:
			PortnoxApiError: if account_id is empty, or on any HTTP error
			               (400/401/403/500).
		"""
		# Validate locally so obviously malformed requests fail immediately with
		# a precise message rather than a generic server-side 400 response.
		if not isinstance(account_id, str) or not account_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_id' must be a non-empty string."
			)

		# Build the exact JSON body required by this DELETE endpoint.
		payload = {"AccountId": account_id.strip()}

		# Use the dedicated account deletion endpoint so Portnox performs a true
		# account removal rather than a reversible block or group reassignment.
		endpoint = f"{self._config.base_url}/api/account"

		try:
			response = self._session.delete(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		# The API returns HTTP 200 with no body when the account is deleted.
		if response.status_code == 200:
			return None

		# Map documented error codes to clear, consistent messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def delete_device(self, device_id: str) -> None:
		"""Permanently remove a device record from Portnox CLEAR.

		Sends DELETE /api/device/{deviceId}.  Unlike blocking, deletion removes
		the device's history from the system and cannot be undone.  Use this
		when a device has been decommissioned or reassigned and its history
		should no longer appear in reports.

		Args:
			device_id: The unique device identifier (DeviceId / EntityId).

		Raises:
			PortnoxApiError: if device_id is empty, or on any HTTP error.
		"""
		# Validate locally before making the network call; this avoids sending a
		# DELETE to "/api/device/" with an empty path segment which would likely
		# hit an unintended endpoint or return an unhelpful error.
		if not isinstance(device_id, str) or not device_id.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'device_id' must be a non-empty string.")

		# Embed the device ID as a URL path parameter as documented by the API.
		endpoint = f"{self._config.base_url}/api/device/{device_id.strip()}"

		try:
			response = self._session.delete(
				endpoint,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		# 200 with no body confirms successful deletion.
		if response.status_code == 200:
			return

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def search_mac_based_accounts(
		self, mac_addresses: List[Dict[str, Any]]
	) -> Dict[str, Any]:
		"""Search for MAB (MAC-based Authentication) accounts by whitelisted MAC.

		MAC-based Authentication (MAB) is a network access control mechanism that
		authenticates and authorizes network devices based on their MAC (Media
		Access Control) address rather than user credentials.  Portnox maintains
		a whitelist of MAC addresses for each MAB-enabled account, allowing
		unmanaged or agentless devices to connect to the network.

		This method searches the Portnox database for all accounts that have been
		configured with whitelisted MAC addresses, and returns two lists:
		  1. "Accounts": MAB accounts that were successfully matched/upserted.
		  2. "UnupsertedAccounts": MAB accounts that exist but had no match this
		     search (may be needed for correlation or cleanup purposes).

		The POST body contains a MacWhiteList array, where each entry has:
		  - Mac: The MAC address to search for (e.g., "00:11:22:33:44:55").
		  - Description: Optional description of the device or purpose.
		  - Expiration: ISO 8601 timestamp indicating when this MAC whitelist
		    entry expires (e.g., temporary device, BYOD, contractor device).

		Each account returned contains extensive nested configuration including:
		  - AgentlessOptions: MAC whitelist, vendor whitelist, secure MAB settings.
		  - RadiusOptions: Voice VLAN configuration if device is VoIP phone.
		  - Certificates: All certificates associated with this account.
		  - Status fields: Whether account is blocked, creation time, etc.

		Args:
			mac_addresses: A list of dict objects, each with:
			               - "Mac": (required, str) MAC address to search.
			               - "Description": (optional, str) Device description.
			               - "Expiration": (optional, str) ISO 8601 timestamp.
			               Example: [
			                   {
			                     "Mac": "00:11:22:33:44:55",
			                     "Description": "Printer",
			                     "Expiration": "2026-12-31T23:59:59Z"
			                   }
			               ]

		Returns:
			A dict with keys:
			  - "Accounts": list of Account objects (with full MAB config) that
			    matched the search criteria.
			  - "UnupsertedAccounts": list of Account objects that are not yet
			    associated with these MAC addresses.
			  - "IsSuccess": boolean indicating overall operation status.
			    associated with these MAC addresses.
			  - "IsSuccess": boolean indicating overall operation status.

		Raises:
			PortnoxApiError: if mac_addresses is empty or not a list, or if the
			               API returns a non-200 status or unexpected response shape.
		"""
		# Validate the input is a non-empty list.  We must have at least one MAC
		# address to search for; an empty list makes no sense.
		if not isinstance(mac_addresses, list) or len(mac_addresses) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a non-empty list."
			)

		# Validate that each entry in the list has at least a "Mac" field.  Per
		# the API schema, Mac is required; Description and Expiration are optional.
		for idx, mac_entry in enumerate(mac_addresses):
			if not isinstance(mac_entry, dict):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must be a dict, got {type(mac_entry).__name__}"
				)
			if "Mac" not in mac_entry or not isinstance(mac_entry.get("Mac"), str):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must have a 'Mac' field (str)."
				)
			if not mac_entry["Mac"].strip():
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: 'Mac' cannot be empty."
				)

		# Construct the request payload.  The API expects a JSON object with a
		# single top-level key "MacWhiteList" containing our list.
		payload = {"MacWhiteList": mac_addresses}

		# Construct the endpoint URL.  This is a POST to the MAC-based accounts
		# search namespace.
		endpoint = f"{self._config.base_url}/api/mac-based-accounts/search"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict containing Accounts, UnupsertedAccounts,
			# and IsSuccess fields.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			return body

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			detail = self._extract_error_detail_from_response(response)
			detail_lower = detail.lower()

			if (
				"not found" in detail_lower and "domain" in detail_lower
			) or "user not found" in detail_lower or "account not found" in detail_lower:
				message = (
					"LDAP account creation failed: user was not found in the specified directory domain (HTTP 400)."
				)
			elif (
				"already exist" in detail_lower
				or "already exists" in detail_lower
				or "duplicate" in detail_lower
			):
				message = (
					"LDAP account creation failed: the account already exists in the directory/domain (HTTP 400)."
				)
			else:
				message = "LDAP account creation failed due to a bad request (HTTP 400)."

			if detail:
				message = f"{message} API detail: {detail}"

			raise PortnoxApiError(message)
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def delete_mac_from_whitelist(
		self,
		account_name: str,
		mac_addresses: List[Dict[str, Any]],
		max_whitelist_length: Optional[int] = None,
	) -> None:
		"""Remove MAC addresses from a MAB account's whitelist.

		MAC-based Authentication (MAB) accounts maintain a whitelist of approved
		MAC addresses that are allowed to connect to the network.  This method
		removes specified MAC addresses from the whitelist.

		IMPORTANT: This method has dual behavior:
		  - If mac_addresses is a non-empty list: removes only those specific
		    MAC addresses from the whitelist (partial removal).
		  - If mac_addresses is an empty list: removes the ENTIRE whitelist,
		    effectively disabling MAB for that account (full removal).

		This dual behavior allows callers to:
		  - Clean up individual expired/revoked MAC entries without affecting
		    other whitelisted devices (e.g., remove a contractor's MAC).
		  - Disable MAB entirely for an account (e.g., convert to EAP-only
		    authentication, or decommission the account).

		The request body contains:
		  - AccountName: Required. The MAB account to modify.
		  - MacWhiteList: List of MAC entries to remove (empty = remove all).
		  - MaxMacWhiteListLength: Optional capacity limit for the whitelist
		    (informational; used to validate consistency).

		Args:
			account_name: The MAB account name (e.g., email, AD account name, or
			             device identifier) to modify.  Must be non-empty.
			mac_addresses: List of MAC address objects to remove.  Each object
			              should have:
			              - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			              - "Description" (optional, str): Device description.
			              - "Expiration" (optional, str): ISO 8601 expiry datetime.
			              If this list is empty, the ENTIRE whitelist is removed.
			max_whitelist_length: Optional integer specifying the maximum allowed
			                     whitelist size.  Portnox validates that the
			                     resulting whitelist does not exceed this limit.

		Returns:
			None. Returns successfully if the removal operation completes without
			error. Returns nothing on HTTP 200.

		Raises:
			PortnoxApiError: if account_name is empty, mac_addresses is not a
			               list, or on any HTTP error (400/401/403/500).
		"""
		# Validate that account_name is a non-empty string.  The API requires an
		# account to modify; we cannot modify an undefined account.
		if not isinstance(account_name, str) or not account_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_name' must be a non-empty string."
			)

		# Validate that mac_addresses is a list (though it may be empty).  An
		# empty list is valid and means "remove entire whitelist".
		if not isinstance(mac_addresses, list):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a list."
			)

		# Validate each entry in the list (if non-empty).  Per the API schema,
		# Mac is required; Description and Expiration are optional.
		for idx, mac_entry in enumerate(mac_addresses):
			if not isinstance(mac_entry, dict):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must be a dict, got {type(mac_entry).__name__}"
				)
			if "Mac" not in mac_entry or not isinstance(mac_entry.get("Mac"), str):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must have a 'Mac' field (str)."
				)
			if not mac_entry["Mac"].strip():
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: 'Mac' cannot be empty."
				)

		# Construct the request payload.  The API expects:
		#   - AccountName: the target MAB account
		#   - MacWhiteList: the list of MACs to remove (empty = remove all)
		#   - MaxMacWhiteListLength: optional capacity constraint
		payload = {
			"AccountName": account_name.strip(),
			"MacWhiteList": mac_addresses,
		}

		# Only include MaxMacWhiteListLength if explicitly provided (to avoid
		# sending null/0 values that might be misinterpreted by the API).
		if max_whitelist_length is not None:
			payload["MaxMacWhiteListLenght"] = max_whitelist_length

		# Construct the endpoint URL.  This is a DELETE request to the MAC
		# whitelist removal namespace.
		endpoint = f"{self._config.base_url}/api/mac-based-accounts/mac-whitelist-remove"

		try:
			response = self._session.delete(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			# HTTP 200 means the removal succeeded.  The API does not return a
			# body on success, so we return None to the caller.
			return None

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			detail = self._extract_error_detail_from_response(response)
			detail_lower = detail.lower()

			if (
				"already exist" in detail_lower
				or "already exists" in detail_lower
				or "duplicate" in detail_lower
			):
				message = (
					"Cloud account creation failed: the account already exists (HTTP 400)."
				)
			else:
				message = "Cloud account creation failed due to a bad request (HTTP 400)."

			if detail:
				message = f"{message} API detail: {detail}"

			raise PortnoxApiError(message)
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def add_mac_to_whitelist(
		self,
		account_name: str,
		mac_addresses: List[Dict[str, Any]],
		max_whitelist_length: Optional[int] = None,
	) -> None:
		"""Add MAC addresses to a MAB account's whitelist.

		MAC-based Authentication (MAB) accounts maintain a whitelist of approved
		MAC addresses that are allowed to connect to the network.  This method
		adds new MAC addresses to an existing account's whitelist, growing the
		set of authorized devices.

		Common use cases:
		  - Onboarding new devices: add a printer, VoIP phone, or IoT device to
		    an existing MAB account without disrupting current whitelisted devices.
		  - Contractor/guest access: add a contractor's laptop MAC for temporary
		    network access.
		  - Device replacement: add a new MAC for a replacement device while the
		    old MAC remains until decommissioned.
		  - Multi-device accounts: build up a whitelist of multiple devices owned
		    by or associated with the same account (e.g., user's laptop + phone).

		The request body contains:
		  - AccountName: Required. The target MAB account to modify.
		  - MacWhiteList: Non-empty list of MAC entries to add.
		  - MaxMacWhiteListLength: Optional capacity limit for the whitelist
		    (informational; validates that the whitelist won't exceed limits).

		Args:
			account_name: The MAB account name (e.g., email, AD account name, or
			             device identifier) to modify.  Must be non-empty.
			mac_addresses: Non-empty list of MAC address objects to add.  Each
			              object should have:
			              - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			              - "Description" (optional, str): Device description
			                (e.g., "Printer in Building A").
			              - "Expiration" (optional, str): ISO 8601 expiry datetime.
			                Useful for temporary access (contractors, guests).
			max_whitelist_length: Optional integer specifying the maximum allowed
			                     whitelist size.  Portnox validates that after adding
			                     the new MACs, the total whitelist does not exceed
			                     this limit (if specified).

		Returns:
			None. Returns successfully if the add operation completes without
			error. Returns nothing on HTTP 200.

		Raises:
			PortnoxApiError: if account_name is empty, mac_addresses is empty
			               or malformed, or on any HTTP error (400/401/403/500).
		"""
		# Validate that account_name is a non-empty string.  The API requires an
		# account to modify; we cannot modify an undefined account.
		if not isinstance(account_name, str) or not account_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_name' must be a non-empty string."
			)

		# Validate that mac_addresses is a non-empty list.  Unlike the delete
		# operation (which allows empty list to mean "remove all"), the add
		# operation requires at least one MAC address.  There's no sensible
		# interpretation of "add nothing".
		if not isinstance(mac_addresses, list) or len(mac_addresses) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a non-empty list."
			)

		# Validate each entry in the list.  Per the API schema, Mac is required;
		# Description and Expiration are optional.
		for idx, mac_entry in enumerate(mac_addresses):
			if not isinstance(mac_entry, dict):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must be a dict, got {type(mac_entry).__name__}"
				)
			if "Mac" not in mac_entry or not isinstance(mac_entry.get("Mac"), str):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must have a 'Mac' field (str)."
				)
			if not mac_entry["Mac"].strip():
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: 'Mac' cannot be empty."
				)

		# Construct the request payload.  The API expects:
		#   - AccountName: the target MAB account
		#   - MacWhiteList: the list of MACs to add (must be non-empty)
		#   - MaxMacWhiteListLength: optional capacity constraint
		payload = {
			"AccountName": account_name.strip(),
			"MacWhiteList": mac_addresses,
		}

		# Only include MaxMacWhiteListLenght if explicitly provided (to avoid
		# sending null/0 values that might be misinterpreted by the API).
		if max_whitelist_length is not None:
			payload["MaxMacWhiteListLenght"] = max_whitelist_length

		# Construct the endpoint URL.  This is a POST request to the MAC
		# whitelist add namespace.
		endpoint = f"{self._config.base_url}/api/mac-based-accounts/mac-whitelist-add"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			# HTTP 200 means the add succeeded.  The API does not return a body
			# on success, so we return None to the caller.
			return None

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def move_mac_between_accounts(
		self,
		current_account_name: str,
		target_account_name: str,
		mac_addresses: List[Dict[str, Any]],
		max_whitelist_length: Optional[int] = None,
	) -> None:
		"""Move MAC addresses from one MAB account's whitelist to another.

		MAC-based Authentication (MAB) accounts maintain whitelists of approved
		MAC addresses.  This method moves specified MAC addresses from one account's
		whitelist to another account's whitelist, transferring ownership/association
		of those devices in a single operation.

		IMPORTANT: This method has dual behavior:
		  - If mac_addresses is a non-empty list: moves only those specific MAC
		    addresses from the source account to the target account (partial move).
		  - If mac_addresses is an empty list: moves the ENTIRE whitelist from
		    source to target, effectively disabling MAB on the source account and
		    consolidating all whitelisted devices under the target account (full move).

		This dual behavior enables:
		  - Device reassignment: move a user's printer MAC to a new account when
		    the device is reassigned to a different department.
		  - Contractor handoff: move a contractor's whitelisted MAC entries to
		    another account when the contractor role transfers to a colleague.
		  - Account consolidation: merge all devices from one MAB account into
		    another (full move).
		  - Partial transfer: move specific devices while keeping others in the
		    original account.

		The request body contains:
		  - CurrentAccountName: Required. The source MAB account (remove from).
		  - TargetAccountName: Required. The destination MAB account (add to).
		  - MacWhiteList: List of MACs to move (empty = move entire whitelist).
		  - MaxMacWhiteListLength: Optional capacity limit for the target account.

		Args:
			current_account_name: Source MAB account name (e.g., email, AD account).
			                      Must be non-empty.
			target_account_name: Destination MAB account name.  Must be non-empty
			                     and different from current_account_name.
			mac_addresses: List of MAC address objects to move.  Each object
			              should have:
			              - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			              - "Description" (optional, str): Device description.
			              - "Expiration" (optional, str): ISO 8601 expiry datetime.
			              If this list is empty, the ENTIRE whitelist moves.
			max_whitelist_length: Optional integer specifying the maximum allowed
			                     whitelist size for the target account.  Portnox
			                     validates that after adding the moved MACs, the
			                     target account's whitelist does not exceed this limit.

		Returns:
			None. Returns successfully if the move operation completes without
			error. Returns nothing on HTTP 200.

		Raises:
			PortnoxApiError: if either account name is empty, they are identical,
			               mac_addresses is not a list, or on any HTTP error
			               (400/401/403/500).
		"""
		# Validate that current_account_name is a non-empty string.
		if not isinstance(current_account_name, str) or not current_account_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'current_account_name' must be a non-empty string."
			)

		# Validate that target_account_name is a non-empty string.
		if not isinstance(target_account_name, str) or not target_account_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'target_account_name' must be a non-empty string."
			)

		current_name = current_account_name.strip()
		target_name = target_account_name.strip()

		# Prevent nonsensical self-moves; moving from an account to itself has no
		# effect and is likely a caller error.
		if current_name == target_name:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'current_account_name' and 'target_account_name' must be different."
			)

		# Validate that mac_addresses is a list (though it may be empty).  An
		# empty list is valid and means "move entire whitelist".
		if not isinstance(mac_addresses, list):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a list."
			)

		# Validate each entry in the list (if non-empty).  Per the API schema,
		# Mac is required; Description and Expiration are optional.
		for idx, mac_entry in enumerate(mac_addresses):
			if not isinstance(mac_entry, dict):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must be a dict, got {type(mac_entry).__name__}"
				)
			if "Mac" not in mac_entry or not isinstance(mac_entry.get("Mac"), str):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must have a 'Mac' field (str)."
				)
			if not mac_entry["Mac"].strip():
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: 'Mac' cannot be empty."
				)

		# Construct the request payload.  The API expects:
		#   - CurrentAccountName: the source MAB account
		#   - TargetAccountName: the destination MAB account
		#   - MacWhiteList: the list of MACs to move (empty = move all)
		#   - MaxMacWhiteListLength: optional capacity constraint
		payload = {
			"CurrentAccountName": current_name,
			"TargetAccountName": target_name,
			"MacWhiteList": mac_addresses,
		}

		# Only include MaxMacWhiteListLenght if explicitly provided (to avoid
		# sending null/0 values that might be misinterpreted by the API).
		if max_whitelist_length is not None:
			payload["MaxMacWhiteListLenght"] = max_whitelist_length

		# Construct the endpoint URL.  This is a POST request to the MAC
		# whitelist move namespace.
		endpoint = f"{self._config.base_url}/api/mac-based-accounts/mac-whitelist-move"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			# HTTP 200 means the move succeeded.  The API does not return a
			# body on success, so we return None to the caller.
			return None

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def change_mac_expiration(
		self,
		account_name: str,
		mac_addresses: List[Dict[str, Any]],
	) -> None:
		"""Change the expiration time for one or multiple MAC addresses in a whitelist.

		MAC-based Authentication (MAB) accounts maintain whitelists of approved
		MAC addresses, often with expiration dates to enforce temporary access.
		This method updates the expiration timestamp for specified MAC addresses
		without changing other whitelist properties (MAC address itself, description,
		etc.).

		Common use cases:
		  - Extend contractor/guest access: a contractor's device MAC is expiring
		    soon; extend the expiration by weeks or months rather than removing
		    and re-adding the MAC.
		  - Batch expiration updates: update multiple device MACs at once (e.g.,
		    all devices in a project that is being extended).
		  - Refresh temporary access: a temporary lab device needs continued access;
		    bump its expiration without full re-enrollment.
		  - Enforce access controls: set all MACs to expire at a fixed date (e.g.,
		    end of fiscal year) without re-entering other MAC details.

		The request body contains:
		  - AccountName: Required. The target MAB account.
		  - MacWhiteList: Non-empty list of MAC entries to update.  Note that in
		    this operation, each entry only needs "Mac" and "Expiration"; the
		    "Description" field is ignored (included for consistency with other
		    MAC operations but not used by the server).

		Importantly, this operation modifies ONLY the expiration timestamp; the MAC
		address itself and all other whitelist properties remain unchanged.

		Args:
			account_name: The MAB account name (e.g., email, AD account name, or
			             device identifier) to modify.  Must be non-empty.
			mac_addresses: Non-empty list of MAC address objects to update.  Each
			              object should have:
			              - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			              - "Expiration" (required, str): New ISO 8601 expiry datetime
			                (e.g., "2026-12-31T23:59:59Z").
			              - "Description" (optional, str): Ignored by this operation;
			                included for API schema consistency but has no effect.
			              Example: [
			                {
			                  "Mac": "00:11:22:33:44:55",
			                  "Expiration": "2026-12-31T23:59:59Z"
			                }
			              ]

		Returns:
			None. Returns successfully if the update operation completes without
			error. Returns nothing on HTTP 200.

		Raises:
			PortnoxApiError: if account_name is empty, mac_addresses is empty or
			               malformed, or on any HTTP error (400/401/403/500).
		"""
		# Validate that account_name is a non-empty string.  The API requires an
		# account to modify; we cannot modify an undefined account.
		if not isinstance(account_name, str) or not account_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_name' must be a non-empty string."
			)

		# Validate that mac_addresses is a non-empty list.  Unlike delete/move
		# operations, this change-expiration operation always requires at least
		# one MAC.  There's no sensible interpretation of "update expiration for
		# nothing".
		if not isinstance(mac_addresses, list) or len(mac_addresses) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a non-empty list."
			)

		# Validate each entry in the list.  Per the API schema for this operation,
		# both Mac and Expiration are required; Description is optional.
		for idx, mac_entry in enumerate(mac_addresses):
			if not isinstance(mac_entry, dict):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must be a dict, got {type(mac_entry).__name__}"
				)
			if "Mac" not in mac_entry or not isinstance(mac_entry.get("Mac"), str):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must have a 'Mac' field (str)."
				)
			if not mac_entry["Mac"].strip():
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: 'Mac' cannot be empty."
				)
			# For change-expiration, Expiration is also required.  We validate that
			# it exists and is a string; we don't validate the date format itself
			# as that would be fragile (the server is authoritative on date parsing).
			if "Expiration" not in mac_entry or not isinstance(mac_entry.get("Expiration"), str):
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: must have an 'Expiration' field (str, ISO 8601 datetime)."
				)
			if not mac_entry["Expiration"].strip():
				raise PortnoxApiError(
					f"Invalid MAC entry at index {idx}: 'Expiration' cannot be empty."
				)

		# Construct the request payload.  The API expects:
		#   - AccountName: the target MAB account
		#   - MacWhiteList: the list of MACs with new expiration times
		payload = {
			"AccountName": account_name.strip(),
			"MacWhiteList": mac_addresses,
		}

		# Construct the endpoint URL.  This is a POST request to the MAC
		# expiration change namespace.
		endpoint = f"{self._config.base_url}/api/mac-based-accounts/change-expiration"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			# HTTP 200 means the expiration change succeeded.  The API does not
			# return a body on success, so we return None to the caller.
			return None

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def get_mac_based_account(self, account_id: str) -> Dict[str, Any]:
		"""Retrieve comprehensive details for a single MAB account by its unique ID.

		Sends GET /api/mac-based-accounts/{accountId}.  The response contains an
		extremely rich set of MAB account configuration and state information,
		including:
		  - Account metadata (OrgId, AccountId, AccountName, Description, GroupId)
		  - Creation and audit information (CreatedAt, CreationType, LastUpdatedBy)
		  - Agentless (MAB) options:
		    - MAC whitelist entries (each with MAC address, description, expiration)
		    - Vendor whitelist entries (approved MAC vendors by prefix)
		    - Secure MAB settings (optional enhanced security for MAB)
		    - Account expiration timestamp
		  - RADIUS options (e.g., Voice VLAN for VoIP phones)
		  - Admin block status and reason (if account is disabled)
		  - Identity type classification (user account, shared device, etc.)

		This is a single GET request with no pagination; it returns the complete
		account record in one response.

		Common use cases:
		  - Audit MAB configuration: review exactly which MACs are whitelisted,
		    their descriptions, and expiration dates for compliance/security review.
		  - Pre-flight checks: before adding/removing/moving MACs, fetch the account
		    to verify it exists, is not blocked, and understand current whitelist state.
		  - Account migration: export full account config including all MAB settings,
		    vendor restrictions, and RADIUS options before transferring to new system.
		  - Troubleshooting: when a device cannot authenticate via MAB, fetch the
		    account to verify the MAC is whitelisted and not expired.
		  - Compliance reporting: generate reports on all active MAB accounts,
		    their MAC whitelists, and expiration dates.

		Args:
			account_id: Unique account identifier (AccountId as returned by search,
			           list, or previous get_mac_based_account calls).

		Returns:
			A comprehensive dict containing all MAB account configuration, state,
			and whitelist data.  The structure includes:
			  - Top-level fields: OrgId, AccountId, AccountName, Description, etc.
			  - Nested AgentlessOptions: MAC whitelist, vendor whitelist, etc.
			  - Nested RadiusOptions: Voice VLAN configuration.
			  - Admin block status: IsBlockByAdmin, BlockReason.

		Raises:
			PortnoxApiError: if account_id is empty, or on HTTP errors (including
			               404 if account not found) or unexpected response shapes.
		"""
		# Validate that account_id is a non-empty string.  An empty ID is not a
		# valid request; we catch this locally to avoid making a network call that
		# would return a 400 with a generic error message.
		if not isinstance(account_id, str) or not account_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_id' must be a non-empty string."
			)

		target_id = account_id.strip()

		# Construct the endpoint URL with the account ID as a path parameter.
		endpoint = f"{self._config.base_url}/api/mac-based-accounts/{target_id}"

		try:
			response = self._session.get(
				endpoint,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict containing the account record.  The API
			# returns an unwrapped dict at the top level (similar to get_device).
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			return body

		# Map HTTP status codes to human-readable error messages.  Note that 404
		# is unique to this endpoint — a missing account (rather than a malformed
		# request) surfaces as HTTP 404.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 404:
			raise PortnoxApiError(f"MAB account with ID '{target_id}' was not found (HTTP 404).")
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def create_mac_based_accounts(
		self,
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Create one or more new MAB (MAC-based Authentication) accounts.

		MAC-based Authentication (MAB) allows unmanaged/agentless network devices
		(printers, IP phones, IoT devices, etc.) to connect to the network by
		registering their MAC addresses with the Portnox platform.  This method
		creates new MAB accounts and populates them with initial configuration:
		MAC whitelists, vendor restrictions, RADIUS options, etc.

		Common use cases:
		  - Onboard new managed printer: create a MAB account for the printer's
		    MAC address, set Voice VLAN for SIP phone, add vendor whitelist for
		    known printer OUIs.
		  - Enable contractor IoT device: create a MAB account for a contractor's
		    sensor device, set MAC expiration date for temporary access.
		  - Batch device provisioning: create multiple MAB accounts in a single
		    operation (one POST) for all devices in a lab, data center, or site.
		  - Device onboarding workflow: create a MAB account as part of new device
		    enrollment, then incrementally add more MACs or settings later.
		  - VoIP phone deployment: create MAB accounts for all new IP phones,
		    configure Voice VLAN so phones get proper network segmentation.

		The request body contains a "MacBasedAccounts" array, where each account
		object specifies:
		  - AccountName: Required. Unique identifier for the account (often device
		    name, department, or use case identifier).
		  - Description: Optional. Human-readable description of the account or device.
		  - MacWhiteList: Optional. Array of MAC addresses to authorize immediately
		    (each with Mac, optional Description, optional Expiration timestamp).
		  - VendorsWhiteList: Optional. Array of approved MAC vendors by prefix
		    (each with VendorName and array of VendorPrefixes like "AA:BB:CC").
		  - AllowAgentlessDevices: Optional boolean. Enable/disable MAB for the
		    account (default true).
		  - PutDevicesIntoVoiceVlan: Optional boolean. If true, assign Voice VLAN
		    (useful for IP phones and VoIP devices).
		  - CredentialsExpirationDate: Optional. Set an expiration for the entire
		    account (all MACs and credentials expire on this date).
		  - IdentityPreSharedKey: Optional. Pre-shared key for secure MAB (if
		    SecureMabOptions is enabled on the account).
		  - MaxMacWhiteListLenght: Optional. Maximum number of MACs allowed (typo
		    "Lenght" matches Portnox API schema).
		  - MaxVendorsWhiteListsLenght: Optional. Maximum vendor whitelist entries.

		The response includes:
		  - "Accounts": Array of successfully created account objects. Each includes
		    AccountId (generated by API), full AgentlessOptions, RadiusOptions,
		    certificate info, etc.
		  - "UnupsertedAccounts": Array of accounts that could not be created (e.g.,
		    duplicate AccountName, validation failure). Inspect this to diagnose
		    partial failures.
		  - "IsSuccess": Boolean indicating overall operation success.

		Args:
			accounts: Non-empty list of MAB account objects to create.  Each account
			         should have:
			         - "AccountName" (required, str): Unique account identifier.
			           Must be non-empty and not already exist.
			         - "Description" (optional, str): Account description.
			         - "MacWhiteList" (optional, list): Initial MAC addresses to
			           whitelist. Each entry: {"Mac": "...", "Description": "...",
			           "Expiration": "..."}.
			         - "VendorsWhiteList" (optional, list): MAC vendors to allow.
			         - "AllowAgentlessDevices" (optional, bool): Enable MAB.
			         - "PutDevicesIntoVoiceVlan" (optional, bool): Assign Voice VLAN.
			         - "CredentialsExpirationDate" (optional, str): ISO 8601 datetime.
			         - "IdentityPreSharedKey" (optional, str): Pre-shared key.
			         - "MaxMacWhiteListLenght" (optional, int): Max MAC whitelist size.
			         - "MaxVendorsWhiteListsLenght" (optional, int): Max vendor list size.
			         Example: [
			           {
			             "AccountName": "printer-5th-floor",
			             "Description": "Xerox printer in building 5",
			             "MacWhiteList": [
			               {"Mac": "AA:BB:CC:DD:EE:FF", "Description": "Primary MAC"}
			             ],
			             "AllowAgentlessDevices": true,
			             "PutDevicesIntoVoiceVlan": false
			           }
			         ]

		Returns:
			A dict with keys:
			  - "Accounts": List of successfully created Account objects (each with
			    generated AccountId and full config).
			  - "UnupsertedAccounts": List of accounts that failed to create
			    (inspect for details on why creation failed).
			  - "IsSuccess": Boolean indicating success (true if all accounts created).

		Raises:
			PortnoxApiError: if accounts list is empty, contains malformed entries,
			               or on any HTTP error (400/401/403/500).
		"""
		# Validate that accounts is a non-empty list.  Creating zero accounts
		# makes no sense; we catch this locally for better error messaging.
		if not isinstance(accounts, list) or len(accounts) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'accounts' must be a non-empty list."
			)

		# Validate each account object in the list.  Per the API schema, AccountName
		# is required; all other fields are optional.
		for idx, account_obj in enumerate(accounts):
			if not isinstance(account_obj, dict):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must be a dict, got {type(account_obj).__name__}"
				)
			if "AccountName" not in account_obj or not isinstance(account_obj.get("AccountName"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have an 'AccountName' field (str)."
				)
			if not account_obj["AccountName"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'AccountName' cannot be empty."
				)

		# Construct the request payload.  The API expects a JSON object with a
		# single top-level key "MacBasedAccounts" containing our list.
		payload = {"MacBasedAccounts": accounts}

		# Construct the endpoint URL.  This is a POST to the MAC-based accounts
		# creation namespace.
		endpoint = f"{self._config.base_url}/api/mac-based-accounts"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict containing Accounts, UnupsertedAccounts,
			# and IsSuccess fields.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			return body

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def list_mac_based_accounts(
		self,
		page_number: int = 1,
		page_size: int = 50,
	) -> Dict[str, Any]:
		"""Retrieve a paginated list of all MAB (MAC-based Authentication) accounts.

		Sends GET /api/list-mac-based-accounts/{pageNumber}.  The API uses query
		string parameters to control pagination; page numbers are 1-indexed and
		page size is fixed at 50 accounts per page.

		This method retrieves all MAB accounts configured in the Portnox
		deployment, including:
		  - Account metadata (ID, name, description, group, creation info)
		  - Agentless options (MAC whitelist with expiration dates, vendor whitelist,
		    secure MAB settings)
		  - RADIUS options (Voice VLAN for VoIP phones)
		  - Admin block status (if account is disabled and reason why)

		Common use cases:
		  - Compliance audits: Review all MAB accounts in the deployment to verify
		    proper configuration, no expired MACs, and authorized device lists.
		  - Capacity planning: Count total MAB accounts, average whitelist sizes,
		    and identify over-subscribed accounts.
		  - Bulk operations: Retrieve all accounts, filter by criteria (e.g., all
		    voice VLANs, all with vendor restrictions), then perform batch updates.
		  - Monitoring and troubleshooting: Export all account configurations to
		    diagnose missing or misconfigured MAB settings.
		  - Device inventory: Correlate all whitelisted MACs with known devices to
		    identify unauthorized or stale MAC entries.
		  - Migration and backup: Export complete account list before system upgrade
		    or platform migration.

		Pagination:
		  - Page numbers start at 1 (not 0).
		  - Page size is fixed at 50 accounts per page.
		  - Use page_number to iterate through pages; increment until you receive
		    fewer than 50 accounts (indicating you've reached the last page).

		Args:
			page_number: 1-based page index (first page = 1, second page = 2, etc.).
			            Must be >= 1.  Default is 1 (first page).
			page_size:   Fixed page size for this endpoint.  The Portnox API
			            currently supports only 50 accounts per page.  Provided as
			            a parameter for clarity and potential future expansion, but
			            values other than 50 may be rejected or ignored.

		Returns:
			A dict with key:
			  - "MabAccounts": List of MAB account objects for this page. Each
			    account contains full configuration (AgentlessOptions, RadiusOptions,
			    block status, etc.). If this page is the last page, the list may
			    contain fewer than 50 accounts (or be empty if page_number is
			    beyond the last page).

		Raises:
			PortnoxApiError: if page_number < 1, or on any HTTP error
			               (400/401/403/500).
		"""
		# Validate pagination inputs before sending a request that would fail
		# with an opaque 400 error from the server.
		if page_number < 1:
			raise PortnoxApiError("Missing or malformed parameter: 'page_number' must be >= 1.")

		# Construct the endpoint URL with the page number as a path parameter.
		# The API embeds the page number directly in the URL path.
		endpoint = f"{self._config.base_url}/api/list-mac-based-accounts/{page_number}"

		try:
			response = self._session.get(
				endpoint,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict containing a MabAccounts array.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			# Validate that MabAccounts is a list if present.  A non-list result
			# indicates an undocumented API change we should surface loudly.
			mab_accounts = body.get("MabAccounts")
			if mab_accounts is not None and not isinstance(mab_accounts, list):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			# Return the full response dict so callers can inspect the MabAccounts
			# array directly.
			return body

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def create_ldap_accounts(
		self,
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Create one or more new LDAP (Active Directory) accounts in Portnox.

		LDAP accounts represent users and computers synchronized from an Active
		Directory (AD) domain or LDAP directory service.  This method creates new
		LDAP-backed accounts in Portnox, enabling network access control and device
		management for corporate users and managed machines.

		Common use cases:
		  - New user onboarding: create LDAP accounts for newly hired employees so
		    they can authenticate and enroll managed/unmanaged devices.
		  - Bulk AD sync: after a directory restructuring (e.g., domain migration,
		    OU consolidation), bulk-create new LDAP accounts for affected users.
		  - Lab or contract user setup: create LDAP accounts for temporary staff,
		    contractors, or lab users with limited lifespans (CredentialsExpirationDate).
		  - Device-bound accounts: create LDAP accounts for managed computers or
		    service accounts that need agentless/MAB network access.
		  - Pilot group provisioning: create accounts for a pilot group to test
		    new Portnox policies before rolling out to the entire organization.

		The request body contains an "LdapAccounts" array, where each account
		object specifies:
		  - AccountName: Required. The user or computer name from AD (e.g., email
		    address, sAMAccountName, or UPN like user@company.com).
		  - DirectoryDomain: Required. The LDAP directory domain (e.g.,
		    "company.com", "DC=company,DC=com", or a configured directory service ID).
		  - Description: Optional. Human-readable description of the account or user.
		  - AllowAgentlessDevices: Optional boolean. Enable MAB (MAC-based auth) for
		    this account so unmanaged devices can connect using MAC whitelisting.
		  - CredentialsExpirationDate: Optional. ISO 8601 timestamp for account
		    expiration. Useful for contractors, guests, or temporary staff whose
		    access should automatically expire on a fixed date.

		The response includes:
		  - "Accounts": Array of successfully created account objects. Each includes
		    the generated AccountId, full AgentlessOptions (if enabled), certificate
		    info, LDAP integration data, and other metadata.
		  - "UnupsertedAccounts": Array of accounts that could not be created (e.g.,
		    duplicate AccountName in domain, user not found in AD, directory not
		    configured). Inspect this to diagnose partial failures.
		  - "IsSuccess": Boolean indicating overall operation success.

		Args:
			accounts: Non-empty list of LDAP account objects to create.  Each account
			         should have:
			         - "AccountName" (required, str): User or computer identifier
			           from AD (e.g., "john.doe@company.com" or "computer-name").
			         - "DirectoryDomain" (required, str): Directory domain identifier
			           (e.g., "company.com" or a configured LDAP directory ID).
			         - "Description" (optional, str): Account description.
			         - "AllowAgentlessDevices" (optional, bool): Enable MAB.
			         - "CredentialsExpirationDate" (optional, str): ISO 8601 timestamp
			           for account expiration (e.g., "2026-12-31T23:59:59Z").
			         Example: [
			           {
			             "AccountName": "john.doe@company.com",
			             "DirectoryDomain": "company.com",
			             "Description": "Marketing department user",
			             "AllowAgentlessDevices": true,
			             "CredentialsExpirationDate": "2026-12-31T23:59:59Z"
			           }
			         ]

		Returns:
			A dict with keys:
			  - "Accounts": List of successfully created Account objects (each with
			    generated AccountId, certificate info, AgentlessOptions, etc.).
			  - "UnupsertedAccounts": List of accounts that failed to create
			    (inspect for details on why creation failed).
			  - "IsSuccess": Boolean indicating success (true if all accounts created).

		Raises:
			PortnoxApiError: if accounts list is empty, contains malformed entries,
			               or on any HTTP error (400/401/403/500).
		"""
		# Validate that accounts is a non-empty list.  Creating zero accounts
		# makes no sense; we catch this locally for better error messaging.
		if not isinstance(accounts, list) or len(accounts) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'accounts' must be a non-empty list."
			)

		# Validate each account object in the list.  Per the API schema, AccountName
		# and DirectoryDomain are required; other fields are optional.
		for idx, account_obj in enumerate(accounts):
			if not isinstance(account_obj, dict):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must be a dict, got {type(account_obj).__name__}"
				)
			if "AccountName" not in account_obj or not isinstance(account_obj.get("AccountName"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have an 'AccountName' field (str)."
				)
			if not account_obj["AccountName"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'AccountName' cannot be empty."
				)
			if "DirectoryDomain" not in account_obj or not isinstance(account_obj.get("DirectoryDomain"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have a 'DirectoryDomain' field (str)."
				)
			if not account_obj["DirectoryDomain"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'DirectoryDomain' cannot be empty."
				)

		# Construct the request payload.  The API expects a JSON object with a
		# single top-level key "LdapAccounts" containing our list.
		payload = {"LdapAccounts": accounts}

		# Construct the endpoint URL.  This is a POST to the LDAP accounts
		# creation namespace.
		endpoint = f"{self._config.base_url}/api/ldap-accounts"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict containing Accounts, UnupsertedAccounts,
			# and IsSuccess fields.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			return body

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def create_contractor_accounts(
		self,
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Create one or more new contractor accounts in Portnox.

		Contractor accounts are a lightweight account type designed for temporary
		external workers (contractors, consultants, vendors) who need limited-time
		network access.  Unlike LDAP accounts (which are bound to a directory service)
		or MAB accounts (which authenticate by MAC address), contractor accounts use
		Portnox-managed credentials and can be given a hard expiration date to
		enforce the end of the engagement.

		Common use cases:
		  - Short-term consultants: create an account for an external consultant,
		    set CredentialsExpirationDate to the contract end date so access auto-
		    expires without manual intervention.
		  - Vendor technicians: create accounts for vendor engineers performing
		    on-site work, with AllowAgentlessDevices if they bring unmanaged
		    equipment.
		  - Temporary project staff: create accounts for all members of a
		    fixed-term project in a single batch call, all sharing the same
		    expiration date aligned with the project timeline.
		  - Auditors: create an auditor account with a short expiration that
		    covers only the audit window.
		  - Seasonal workers: batch-create accounts for seasonal staff, with
		    expiration dates matching the seasonal period.

		The request body contains a "ContractorAccounts" array, where each object
		specifies:
		  - AccountName: Required. Unique identifier for the contractor account
		    (e.g., email address, username, badge ID).
		  - Description: Optional. Human-readable description of the contractor
		    or engagement purpose.
		  - CredentialsExpirationDate: Optional ISO 8601 timestamp.  When set,
		    all credentials for this account expire at the specified time,
		    automatically revoking network access with no further action needed.
		  - AllowAgentlessDevices: Optional boolean. Enable MAB (MAC-based auth)
		    for this account so the contractor's unmanaged devices can connect
		    via MAC whitelisting.

		The response includes:
		  - "Accounts": Array of successfully created account objects. Each includes
		    the generated AccountId, AgentlessOptions (if enabled), and certificate
		    info for use in subsequent operations.
		  - "UnupsertedAccounts": Array of accounts that could not be created (e.g.,
		    duplicate AccountName, validation failure).  Inspect this to diagnose
		    partial failures in batch operations.
		  - "IsSuccess": Boolean indicating overall operation success.

		Args:
			accounts: Non-empty list of contractor account objects to create.  Each
			         account should have:
			         - "AccountName" (required, str): Unique contractor identifier
			           (e.g., "jane.smith@vendorcorp.com" or "contractor-badge-42").
			         - "Description" (optional, str): Account description.
			         - "CredentialsExpirationDate" (optional, str): ISO 8601 datetime
			           at which the account expires (e.g., "2026-09-30T23:59:59Z").
			         - "AllowAgentlessDevices" (optional, bool): Enable MAB.
			         Example: [
			           {
			             "AccountName": "jane.smith@vendorcorp.com",
			             "Description": "Network audit consultant",
			             "CredentialsExpirationDate": "2026-09-30T23:59:59Z",
			             "AllowAgentlessDevices": false
			           }
			         ]

		Returns:
			A dict with keys:
			  - "Accounts": List of successfully created Account objects (each with
			    generated AccountId and full configuration).
			  - "UnupsertedAccounts": List of accounts that failed to create.
			  - "IsSuccess": Boolean indicating success (true if all accounts created).

		Raises:
			PortnoxApiError: if accounts list is empty, contains malformed entries,
			               or on any HTTP error (400/401/403/500).
		"""
		# Validate that accounts is a non-empty list.  Creating zero accounts makes
		# no sense; we catch this locally for a clear error message.
		if not isinstance(accounts, list) or len(accounts) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'accounts' must be a non-empty list."
			)

		# Validate each account object.  Per the API schema, AccountName is required;
		# Description, CredentialsExpirationDate, and AllowAgentlessDevices are optional.
		for idx, account_obj in enumerate(accounts):
			if not isinstance(account_obj, dict):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must be a dict, got {type(account_obj).__name__}"
				)
			if "AccountName" not in account_obj or not isinstance(account_obj.get("AccountName"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have an 'AccountName' field (str)."
				)
			if not account_obj["AccountName"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'AccountName' cannot be empty."
				)

		# Construct the request payload.  The API expects a JSON object with a
		# single top-level key "ContractorAccounts" containing our list.
		payload = {"ContractorAccounts": accounts}

		# Construct the endpoint URL.  This is a POST to the contractor accounts
		# creation namespace.
		endpoint = f"{self._config.base_url}/api/contractor-accounts"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict containing Accounts, UnupsertedAccounts,
			# and IsSuccess fields.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			return body

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def create_cloud_accounts(
		self,
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Create one or more new Portnox Cloud (CLEAR) accounts.

		Cloud accounts are Portnox-managed accounts hosted entirely in the Portnox
		Cloud platform, independent of any directory service (unlike LDAP) or fixed
		device authentication (unlike MAB).  Cloud accounts support flexible credential
		management and are ideal for cloud-based teams, distributed users, and
		orchestrated identity provisioning.

		Common use cases:
		  - Cloud-first organizations: manage user accounts for distributed workforces
		    that don't rely on on-premises Active Directory.
		  - MSP/SaaS deployments: create multi-tenant cloud accounts for managed
		    service provider customers without complex directory integration.
		  - Hybrid identities: provision cloud accounts alongside LDAP/AD for users
		    that aren't in directory, or for cloud-only services.
		  - Identity provisioning workflows: batch-create accounts from cloud identity
		    platforms (Okta, Azure AD sync, Workspace, etc.).
		  - Automated user onboarding: call from HR/provisioning systems to create
		    accounts and set auto-expiry for temporary or contract workers.

		The request body contains a "ClearAccounts" array, where each account
		object specifies:
		  - AccountName: Required. Unique identifier for the cloud account
		    (e.g., email address, username, employee ID).
		  - Description: Optional. Human-readable description of the account
		    or user role.
		  - CredentialsExpirationDate: Optional ISO 8601 timestamp. When set,
		    all credentials for this account expire at the specified time,
		    automatically revoking access with no further action needed.
		  - AllowAgentlessDevices: Optional boolean. Enable MAB (MAC-based auth)
		    for this account so unmanaged devices can connect via MAC whitelisting.

		The response includes:
		  - "Accounts": Array of successfully created account objects. Each includes
		    the generated AccountId, AgentlessOptions (if enabled), and certificate
		    info for use in subsequent operations.
		  - "UnupsertedAccounts": Array of accounts that could not be created (e.g.,
		    duplicate AccountName, validation failure). Inspect this to diagnose
		    partial failures in batch operations.
		  - "IsSuccess": Boolean indicating overall operation success.

		Args:
			accounts: Non-empty list of cloud account objects to create.  Each account
			         should have:
			         - "AccountName" (required, str): Unique account identifier
			           (e.g., "user@mycompany.com" or "emp-12345").
			         - "Description" (optional, str): Account description.
			         - "CredentialsExpirationDate" (optional, str): ISO 8601 datetime
			           at which the account expires (e.g., "2027-12-31T23:59:59Z").
			         - "AllowAgentlessDevices" (optional, bool): Enable MAB.
			         Example: [
			           {
			             "AccountName": "alice@mycompany.com",
			             "Description": "Cloud operations engineer",
			             "CredentialsExpirationDate": null,
			             "AllowAgentlessDevices": true
			           }
			         ]

		Returns:
			A dict with keys:
			  - "Accounts": List of successfully created Account objects (each with
			    generated AccountId and full config).
			  - "UnupsertedAccounts": List of accounts that failed to create.
			  - "IsSuccess": Boolean indicating success (true if all accounts created).

		Raises:
			PortnoxApiError: if accounts list is empty, contains malformed entries,
			               or on any HTTP error (400/401/403/500).
		"""
		# Validate that accounts is a non-empty list.  Creating zero accounts makes
		# no sense; we catch this locally for a clear error message.
		if not isinstance(accounts, list) or len(accounts) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'accounts' must be a non-empty list."
			)

		# Validate each account object.  Per the API schema, AccountName is required;
		# Description, CredentialsExpirationDate, and AllowAgentlessDevices are optional.
		for idx, account_obj in enumerate(accounts):
			if not isinstance(account_obj, dict):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must be a dict, got {type(account_obj).__name__}"
				)
			if "AccountName" not in account_obj or not isinstance(account_obj.get("AccountName"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have an 'AccountName' field (str)."
				)
			if not account_obj["AccountName"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'AccountName' cannot be empty."
				)

		# Construct the request payload.  The API expects a JSON object with a
		# single top-level key "ClearAccounts" containing our list.  Note the
		# internal API naming: "Clear" refers to the Portnox CLEAR cloud platform.
		payload = {"ClearAccounts": accounts}

		# Construct the endpoint URL.  This is a POST to the cloud accounts
		# creation namespace.
		endpoint = f"{self._config.base_url}/api/cloud-accounts"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict containing Accounts, UnupsertedAccounts,
			# and IsSuccess fields.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			return body

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def move_account_to_group(self, group_name: str, account_id: str) -> None:
		"""Move a non-LDAP account to a different Portnox group.

		Sends POST /api/account/move-to-group with a payload containing GroupName
		and AccountId.  This operation is intended for non-LDAP identities,
		especially Portnox Cloud accounts and Contractor accounts.

		Important behavioral context:
		  - LDAP accounts are typically assigned by LDAP mapping policy and are
		    not meant to be manually moved with this endpoint.
		  - When an account is moved, Portnox recalculates the risk score for all
		    devices associated with that account using the destination group's policy.

		Common use cases:
		  - Role change: move a contractor from a broad onboarding group to a
		    restricted production group after vetting.
		  - Offboarding prep: move an account into a quarantine/limited-access
		    group before disabling credentials.
		  - Policy correction: reassign an account that was accidentally created
		    in the wrong group.
		  - Temporary elevation: move to a privileged support group for a short
		    maintenance window, then move back.

		Args:
			group_name: Destination Portnox group name (must be non-empty).
			account_id: Account identifier to move (must be non-empty).  This is
			           typically the Portnox AccountId or account identifier used by
			           your integration, depending on deployment conventions.

		Returns:
			None.  HTTP 200 indicates the group assignment update succeeded.

		Raises:
			PortnoxApiError: if group_name/account_id are empty, or on any HTTP error
			               (400/401/403/500).
		"""
		# Validate destination group name locally so callers get a deterministic,
		# descriptive error without a network round-trip.
		if not isinstance(group_name, str) or not group_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'group_name' must be a non-empty string."
			)

		# Validate account identifier locally for the same reason as above.
		if not isinstance(account_id, str) or not account_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_id' must be a non-empty string."
			)

		# Construct the request payload exactly as required by the endpoint schema.
		payload = {
			"GroupName": group_name.strip(),
			"AccountId": account_id.strip(),
		}

		# Construct the endpoint URL for account group reassignment.
		endpoint = f"{self._config.base_url}/api/account/move-to-group"

		try:
			response = self._session.post(
				endpoint,
				json=payload,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		# HTTP 200 indicates successful group reassignment; API returns no body.
		if response.status_code == 200:
			return None

		# Map HTTP status codes to human-readable error messages.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def find_devices_by_account_name(
		self, account_name: str, search_field: int = 1, max_pages: int = 10
	) -> List[Dict[str, Any]]:
		"""Search for all devices owned by a specific user account.

		Portnox organises devices under user accounts (typically identified by
		email address).  This method iterates through pages of search results,
		collecting all matching device entries, up to max_pages pages.

		The raw API returns entries grouped by account (each entry has an
		Account sub-object and a Devices list).  This method returns the raw
		page entries rather than flattening them, to preserve the account context.

		Args:
			account_name:  The email address or account name to search for.
			search_field:  Integer field selector.  Default 1 = email/account.
			               0 = all fields (slower but more comprehensive).
			max_pages:     Safety limit to prevent runaway pagination.

		Returns:
			A flat list of the raw page-entry objects (each containing Account
			and Devices keys) across all matching pages.

		Raises:
			PortnoxApiError: if account_name is empty or on any API error.
		"""
		if not isinstance(account_name, str) or not account_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_name' must be a non-empty string."
			)

		all_devices = []

		# Iterate page by page.  We use a large page_size (100) to minimise the
		# number of round trips while staying within typical API limits.
		for page_num in range(1, max_pages + 1):
			response = self.list_devices(
				page_number=page_num,
				page_size=100,
				search_value=account_name.strip(),
				search_field=search_field,
				include_account_without_devices=False,
			)

			result = response.get("Result") if isinstance(response, dict) else None
			if result and isinstance(result, list):
				all_devices.extend(result)

			# Stop early once we have retrieved all available pages rather than
			# making unnecessary extra requests up to max_pages.
			total_pages = response.get("TotalPages") if isinstance(response, dict) else None
			if total_pages is not None and page_num >= total_pages:
				break

		return all_devices

	def get_device(self, device_id: str) -> Dict[str, Any]:
		"""Retrieve comprehensive details for a single device by its unique ID.

		Sends GET /api/device/{deviceId}.  The response contains an extremely
		rich set of device telemetry including:
		  - Mobile device data (GSM, WiFi, MDM enrollment status, installed apps)
		  - Computer data (OS, network interfaces, security software, users)
		  - Validation history (authentication attempts, NAS connections, ACLs)
		  - Risk assessment (compliance score, policy violations, grace periods)
		  - Certificate information (enrollment, machine, and user certificates)
		  - Azure / Intune integration data
		  - Third-party MDM integration (Jamf, CrowdStrike, SentinelOne)
		  - Location information (geolocation data, coordinates)

		This is a single GET request with no pagination; it returns the complete
		device record in one response.

		Args:
			device_id: Unique device identifier (DeviceId / EntityId).

		Returns:
			A comprehensive dict containing all device telemetry, validation
			history, risk assessment, and integration data.  The structure is
			highly nested with many optional sub-objects (e.g., MobileDeviceData,
			ComputerData, ValidationStatuses array).

		Raises:
			PortnoxApiError: if device_id is empty, or on HTTP errors or
			                 unexpected response shapes.
		"""
		if not isinstance(device_id, str) or not device_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'device_id' must be a non-empty string."
			)

		target_id = device_id.strip()

		# Construct the endpoint URL with the device ID as a path parameter.
		endpoint = f"{self._config.base_url}/api/device/{target_id}"

		try:
			response = self._session.get(
				endpoint,
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The response should be a dict containing the device record.  Unlike
			# some list endpoints, the device detail endpoint returns an unwrapped
			# dict at the top level.
			if not isinstance(body, dict):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")

			return body

		# Map HTTP status codes to human-readable error messages.  Note that 404
		# is unique to this endpoint — a missing device (rather than a malformed
		# request) surfaces as HTTP 404.
		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 404:
			raise PortnoxApiError(f"Device with ID '{target_id}' was not found (HTTP 404).")
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def get_nases(self, mode: int = DEFAULT_MODE, info: int = DEFAULT_INFO) -> List[Dict[str, Any]]:
		"""Retrieve the full list of NAS (Network Access Switch) devices.

		Sends POST /api/nases with Mode and Info control fields.  The response
		is a JSON array where each element represents a single NAS device.

		Args:
			mode: Controls which NAS records are returned.  0 = all active NASes.
			      Other values select subsets; consult Portnox documentation.
			info: Bitmask controlling additional data fields in each NAS object.
			      0 = minimal data.  Higher bits add connection history, stats, etc.

		Returns:
			A list of NAS device objects.

		Raises:
			PortnoxApiError: on HTTP errors or unexpected response shapes.
		"""
		endpoint = f"{self._config.base_url}/api/nases"

		# The endpoint takes a POST body even though this is a read operation;
		# the Portnox API uses POST for queries that accept control parameters.
		payload = {"Mode": mode, "Info": info}

		try:
			response = self._session.post(
				endpoint,
				data=json.dumps(payload),
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# Unlike the sites endpoint, the NAS list is returned as a bare JSON
			# array (not wrapped in a dict), so we validate that shape here.
			if not isinstance(body, list):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")
			return body

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)

	def update_nases(self, nases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
		"""Batch-update NAS device records via PUT /api/nases.

		Sends the complete updated NAS objects in a `Nases` wrapper.
		Each NAS object must contain its NasId so the server knows which record
		to update.  Fields not included in the object are not preserved — the
		caller is responsible for fetching the current state first and merging
		changes into the full object before calling this method.

		Args:
			nases: List of NAS objects to update.  Each must include NasId.

		Returns:
			The list of updated NAS objects as returned by the API.

		Raises:
			PortnoxApiError: on HTTP errors or unexpected response shapes.
		"""
		endpoint = f"{self._config.base_url}/api/nases"

		# Wrap the list in the `Nases` key that the API expects.
		payload = {"Nases": nases}

		try:
			response = self._session.put(
				endpoint,
				data=json.dumps(payload),
				timeout=self._config.timeout_seconds,
				verify=self._config.verify_tls,
			)
		except requests.RequestException as exc:
			raise PortnoxApiError(f"Portnox API request failed: {exc}") from exc

		if response.status_code == 200:
			try:
				body = response.json()
			except ValueError as exc:
				raise PortnoxApiError("Portnox API returned invalid JSON.") from exc

			# The API returns the updated NAS list as a bare JSON array.
			if not isinstance(body, list):
				raise PortnoxApiError("Portnox API returned unexpected response shape.")
			return body

		if response.status_code == 400:
			raise PortnoxApiError("Missing or malformed parameter (HTTP 400).")
		if response.status_code == 401:
			raise PortnoxApiError(
				"Provided organizational credentials are not valid (HTTP 401)."
			)
		if response.status_code == 403:
			raise PortnoxApiError(
				"Access denied due to the license restrictions (HTTP 403)."
			)
		if response.status_code == 500:
			raise PortnoxApiError("Internal server error from Portnox API (HTTP 500).")

		raise PortnoxApiError(
			f"Unexpected Portnox API response HTTP {response.status_code}: {response.text[:500]}"
		)


def build_server(client: PortnoxClient) -> FastMCP:
	"""Construct and return a FastMCP server pre-loaded with all Portnox tools.

	All MCP tool functions are defined as inner functions (closures) here so
	they automatically capture the `client` instance without needing it passed
	as an argument on every call.  The `@mcp.tool()` decorator registers each
	function as a named tool that MCP clients can discover and invoke.

	Naming convention: Every tool has a primary name (e.g. `list_devices`) and
	an alias prefixed with `portnox_` (e.g. `list_portnox_devices`).  The
	aliases exist so that AI assistants that have multiple MCP servers loaded
	can unambiguously target Portnox operations when the context is ambiguous.

	Args:
		client: An already-initialised PortnoxClient.

	Returns:
		A configured FastMCP instance ready to be run.
	"""
	# Create the MCP server instance.  The name identifies the server to
	# clients that connect to it.
	mcp = FastMCP("portnox-mcp-server")

	@mcp.tool()
	def list_nas_devices(mode: int = DEFAULT_MODE, info: int = DEFAULT_INFO) -> Dict[str, Any]:
		"""Get NAS devices from Portnox Cloud.

		Args:
			mode: Portnox request field `Mode`.  0 = all active NASes.
			info: Portnox request field `Info`.  0 = minimal NAS data.

		Returns:
			A JSON-serializable object containing NAS list and count.
		"""
		devices = client.get_nases(mode=mode, info=info)

		# Wrap in a consistent envelope so callers always get `count` + `items`.
		return {"count": len(devices), "items": devices}

	@mcp.tool()
	def list_nas_sites() -> Dict[str, Any]:
		"""List Portnox sites where a NAS could be deployed.

		This calls GET /api/nases/sites and returns the Sites array along with
		a count of how many sites were found.
		"""
		sites = client.get_sites()
		return {"count": len(sites), "items": sites}

	@mcp.tool()
	def list_portnox_nas_sites() -> Dict[str, Any]:
		"""Alias of list_nas_sites with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return list_nas_sites()

	# ---------------------------------------------------------------------------
	# Internal helper functions (not exposed as MCP tools)
	# ---------------------------------------------------------------------------

	def _get_string_field(obj: Dict[str, Any], keys: List[str]) -> Optional[str]:
		"""Return the first non-empty string value found among the given keys.

		Portnox API responses use inconsistent casing for some fields across
		different deployment versions (e.g. "IP" vs "Ip" vs "IpAddress").
		This helper probes multiple candidate key names in order and returns
		the first non-empty string found, avoiding per-call key-guessing.

		Args:
			obj:  Dict to search.
			keys: Ordered list of candidate key names to try.

		Returns:
			Stripped string value, or None if no matching key is found.
		"""
		for key in keys:
			value = obj.get(key)
			if isinstance(value, str) and value.strip():
				return value.strip()
		return None

	def _find_nas_by_ip(devices: List[Dict[str, Any]], ip_address: str) -> List[Dict[str, Any]]:
		"""Filter a list of NAS device dicts to those matching a given IP.

		Checks multiple candidate field names for the IP address because
		different Portnox deployments use different property names.

		Args:
			devices:    List of NAS device objects from get_nases().
			ip_address: IP address string to match exactly (no wildcards).

		Returns:
			Subset of `devices` whose IP field equals `ip_address`.
		"""
		matches: List[Dict[str, Any]] = []
		for item in devices:
			# Probe the common IP field name variants in priority order.
			item_ip = _get_string_field(item, ["IP", "Ip", "IpAddress", "NASIP", "NasIp", "Address"])
			if item_ip == ip_address:
				matches.append(item)
		return matches

	def _summarize_bulk_create_result(
		requested_count: int,
		result: Dict[str, Any],
		strict_mode: bool,
		account_type: str,
	) -> Dict[str, Any]:
		"""Normalize a native Portnox batch-create response into a consistent envelope.

		The account creation endpoints already support batch submission natively and
		return three key fields:
		  - Accounts: successfully created accounts
		  - UnupsertedAccounts: accounts the server did not create
		  - IsSuccess: server-level overall success indicator

		This helper keeps the raw payload available while also adding normalized
		counts and optional strict-mode enforcement so all bulk create wrappers
		behave consistently.

		Important strict-mode caveat:
		  These Portnox endpoints are batch-native, so by the time the response is
		  returned, the server has already attempted the whole batch.  strict_mode
		  cannot prevent partial creation on the server; it only changes whether we
		  return a summarized partial-success result or raise an error.

		Args:
			requested_count: Number of account objects submitted by the caller.
			result: Raw response dict returned by the corresponding create tool.
			strict_mode: Whether to raise if any accounts were not created.
			account_type: Human-readable label used in strict-mode error messages.

		Returns:
			A normalized dict containing counts plus the raw Portnox response fields.

		Raises:
			PortnoxApiError: if result shape is invalid, strict_mode is not boolean,
			               or strict_mode=True and the server reports any failures.
		"""
		if not isinstance(strict_mode, bool):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'strict_mode' must be a boolean."
			)

		if not isinstance(result, dict):
			raise PortnoxApiError("Portnox API returned unexpected response shape.")

		created_accounts = result.get("Accounts", [])
		failed_accounts = result.get("UnupsertedAccounts", [])
		is_success = result.get("IsSuccess")

		if not isinstance(created_accounts, list) or not isinstance(failed_accounts, list):
			raise PortnoxApiError("Portnox API returned unexpected response shape.")

		created_count = len(created_accounts)
		failed_count = len(failed_accounts)

		# In strict mode we surface a hard failure when the server reports any
		# accounts that could not be created, even though some earlier entries may
		# already have succeeded on the server side.
		if strict_mode and failed_count > 0:
			raise PortnoxApiError(
				f"Bulk {account_type} creation completed with partial failure: {failed_count} of {requested_count} account(s) were not created."
			)

		return {
			"status": "completed",
			"account_type": account_type,
			"requested_count": requested_count,
			"created_count": created_count,
			"failed_count": failed_count,
			"is_success": bool(is_success),
			"accounts": created_accounts,
			"unupserted_accounts": failed_accounts,
			"raw_response": result,
		}

	@mcp.tool()
	def update_nas_display_name_by_ip(
		ip_address: str,
		display_name: str,
		mode: int = DEFAULT_MODE,
		info: int = DEFAULT_INFO,
	) -> Dict[str, Any]:
		"""Update one Portnox NAS display name by IP address.

		This is a convenience tool for prompts like:
		- "update the display name for Portnox NAS '10.1.1.1' to 'USG'"

		The workflow is: fetch all NASes → find the one matching `ip_address`
		→ update its DisplayName in-place → push the full updated object back
		via PUT /api/nases.

		Args:
			ip_address:   NAS IP address to locate in Portnox.
			display_name: New display name value.
			mode:         Portnox request field `Mode` for the lookup call.
			info:         Portnox request field `Info` for the lookup call.

		Returns:
			Object describing the matched NAS and update status, including
			the previous and new display names for confirmation.
		"""
		# Validate inputs before making any API calls to give the caller a
		# clear error message rather than a confusing API response.
		if not isinstance(ip_address, str) or not ip_address.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'ip_address' must be a non-empty string.")

		if not isinstance(display_name, str) or not display_name.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'display_name' must be a non-empty string.")

		target_ip = ip_address.strip()
		new_name = display_name.strip()

		# Fetch the live NAS list so we are working with the current server state.
		devices = client.get_nases(mode=mode, info=info)
		matches = _find_nas_by_ip(devices, target_ip)

		if len(matches) == 0:
			raise PortnoxApiError(f"No NAS found with IP '{target_ip}'.")

		# Refuse to update if multiple NASes share the same IP (misconfiguration).
		# The caller must use a NasId-based tool to disambiguate.
		if len(matches) > 1:
			nas_ids = [str(item.get("NasId", "")) for item in matches]
			raise PortnoxApiError(
				f"Multiple NAS entries found with IP '{target_ip}'. Refine request by NasId. Matches: {nas_ids}"
			)

		# Take a shallow copy to avoid mutating the list element in-place.
		current = dict(matches[0])
		nas_id = _get_string_field(current, ["NasId"]) or ""
		if not nas_id:
			raise PortnoxApiError("Matched NAS is missing required 'NasId'; cannot update.")

		# Save the old name for the audit response before overwriting it.
		previous_name = _get_string_field(current, ["DisplayName", "Name", "NasName"])

		# Apply the change to the full NAS object.  We send the complete object
		# (not just the changed field) because the PUT endpoint replaces the
		# entire resource.
		current["DisplayName"] = new_name

		updated_items = client.update_nases(nases=[current])

		# Extract the new name from the API's response for confirmation.
		result_name = None
		if updated_items:
			result_name = _get_string_field(updated_items[0], ["DisplayName", "Name", "NasName"])

		return {
			"status": "updated",
			"ip_address": target_ip,
			"nas_id": nas_id,
			"previous_display_name": previous_name,
			"requested_display_name": new_name,
			"result_display_name": result_name,
			"updated_count": len(updated_items),
			"items": updated_items,
		}

	@mcp.tool()
	def update_portnox_nas_display_name(
		ip_address: str,
		display_name: str,
		mode: int = DEFAULT_MODE,
		info: int = DEFAULT_INFO,
	) -> Dict[str, Any]:
		"""Alias of update_nas_display_name_by_ip with explicit Portnox naming."""
		return update_nas_display_name_by_ip(
			ip_address=ip_address,
			display_name=display_name,
			mode=mode,
			info=info,
		)

	@mcp.tool()
	def update_nas_devices(nases: List[Dict[str, Any]]) -> Dict[str, Any]:
		"""Batch update NAS devices in Portnox Cloud.

		Accepts a list of full NAS objects (each must include its NasId) and
		sends them all to the API in a single PUT request.

		Safety rules enforced before the API request is made:
		- Maximum 250 NAS objects per request (prevents oversized payloads).
		- Duplicate NasId values in the input are rejected to prevent the same
		  device being unintentionally updated twice in one call.

		Fields set to null inside a NAS object are forwarded as-is.  Portnox
		typically preserves null fields on the server, but the caller should
		prefer fetching the current state first and merging changes.
		"""
		if not isinstance(nases, list) or len(nases) == 0:
			raise PortnoxApiError("Missing or malformed parameter: 'nases' must be a non-empty list.")

		if len(nases) > 250:
			raise PortnoxApiError("Batch update limit exceeded: maximum 250 NASes per request.")

		# Validate each NAS object and collect NasIds for duplicate detection.
		nas_ids: List[str] = []
		for idx, item in enumerate(nases):
			if not isinstance(item, dict):
				raise PortnoxApiError(
					f"Missing or malformed parameter: nases[{idx}] must be an object."
				)

			nas_id = item.get("NasId")
			if not isinstance(nas_id, str) or not nas_id.strip():
				raise PortnoxApiError(
					f"Missing or malformed parameter: nases[{idx}].NasId must be a non-empty string."
				)
			nas_ids.append(nas_id.strip())

		# If the set of IDs is smaller than the list, at least one ID appears
		# more than once.  Reject the request to prevent silent data corruption.
		if len(nas_ids) != len(set(nas_ids)):
			raise PortnoxApiError(
				"Rejected request: duplicate NasId values detected; request declined as malicious."
			)

		updated = client.update_nases(nases=nases)
		return {"count": len(updated), "items": updated}

	@mcp.tool()
	def create_or_update_site(
		name: str,
		description: Optional[str] = None,
		parent_id: Optional[str] = None,
		rules: Optional[List[Dict[str, Any]]] = None,
	) -> Dict[str, Any]:
		"""Create or update a Portnox site with name, description, parent, and IP rules.

		This tool sends a PUT request to /api/nases/sites with site configuration.
		If a site with the given name already exists, it will be updated with the
		provided fields while preserving any fields not explicitly supplied.
		If no site with that name exists, a new site will be created.

		The lookup is case-insensitive.  If multiple sites share the same name,
		the tool refuses to proceed and returns their IDs so the caller can use
		the more precise `update_site_by_id` tool instead.

		Args:
			name:        Site display name (required).
			description: Site description.
			parent_id:   Parent site ID (optional; null if not specified).
			rules:       List of rule objects with Type, From, To, Mask fields.
			               - Type 1: CIDR (From=IP, Mask=prefix_length, To=null)
			               - Type 2: Range (From=start_ip, To=end_ip, Mask=null)

		Returns:
			The created/updated site object from Portnox API, plus an operation
			status string ("created" or "updated") and the previous site data.
		"""
		if not isinstance(name, str) or not name.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'name' must be a non-empty string.")

		target_name = name.strip()

		# Fetch the current site list to determine whether we are creating or
		# updating, and to retrieve the existing site data for merge.
		existing_sites = client.get_sites()
		name_matches: List[Dict[str, Any]] = []
		for site in existing_sites:
			site_name = site.get("Name")
			# Case-insensitive comparison so "Main" and "main" are treated as the
			# same site, matching typical user expectations.
			if isinstance(site_name, str) and site_name.strip().casefold() == target_name.casefold():
				name_matches.append(site)

		# Refuse to modify ambiguous sites; surface the IDs to the caller.
		if len(name_matches) > 1:
			match_ids = [str(s.get("Id", "")) for s in name_matches]
			raise PortnoxApiError(
				f"Multiple sites found with name '{target_name}'. Use update_site_by_id with one of: {match_ids}"
			)

		matching_site = name_matches[0] if name_matches else None

		site_data: Dict[str, Any] = {}

		if matching_site:
			# ---- UPDATE PATH ----
			# Start from the existing site so all unspecified fields are preserved.
			site_data = dict(matching_site)
			site_data["Name"] = target_name
			expected_id = _get_string_field(matching_site, ["Id"])

			# Only overwrite fields that the caller explicitly provided.
			if description is not None:
				if not isinstance(description, str):
					raise PortnoxApiError("Missing or malformed parameter: 'description' must be a string or null.")
				site_data["Description"] = description.strip()

			if parent_id is not None:
				if not isinstance(parent_id, str) or not parent_id.strip():
					raise PortnoxApiError("Missing or malformed parameter: 'parent_id' must be a non-empty string or null.")
				site_data["ParentId"] = parent_id.strip()

			if rules is not None:
				if not isinstance(rules, list):
					raise PortnoxApiError("Missing or malformed parameter: 'rules' must be a list.")
				site_data["Rules"] = rules

			operation = "updated"
		else:
			# ---- CREATE PATH ----
			# Build a fresh site object with sensible defaults for omitted fields.
			site_data = {
				"Name": target_name,
				"Description": description.strip() if isinstance(description, str) else "",
			}

			if parent_id is not None:
				if not isinstance(parent_id, str) or not parent_id.strip():
					raise PortnoxApiError("Missing or malformed parameter: 'parent_id' must be a non-empty string or null.")
				site_data["ParentId"] = parent_id.strip()
			else:
				# Explicitly pass null so the API creates a root-level site.
				site_data["ParentId"] = None

			if rules is not None:
				if not isinstance(rules, list):
					raise PortnoxApiError("Missing or malformed parameter: 'rules' must be a list.")
				site_data["Rules"] = rules
			else:
				# An empty Rules list is safer than omitting the key entirely.
				site_data["Rules"] = []

			operation = "created"
			expected_id = None

		result = client.create_or_update_site(site_data)

		# ---- POST-WRITE VERIFICATION (update path only) ----
		# The Portnox PUT endpoint can silently create a *new* site instead of
		# updating an existing one on some versions.  We defend against this by
		# re-fetching the site list and confirming the expected ID still exists.
		if operation == "updated":
			result_id = _get_string_field(result, ["Id"])
			if expected_id and result_id and result_id != expected_id:
				raise PortnoxApiError(
					"Portnox API returned success but created/returned a different site ID. "
					f"Expected Id={expected_id}, got Id={result_id}. Refusing to report success."
				)

			latest_sites = client.get_sites()
			latest_match = None
			for site in latest_sites:
				sid = _get_string_field(site, ["Id"])
				if sid == expected_id:
					latest_match = site
					break

			if latest_match is None:
				raise PortnoxApiError(
					"Portnox API reported success but target site ID was not found afterward. "
					"This endpoint may be creating new sites instead of updating existing ones."
				)

		return {
			"status": operation,
			"site_name": target_name,
			# Include the previous state for change-tracking and audit purposes.
			"previous_data": dict(matching_site) if matching_site else None,
			"site": result,
		}

	@mcp.tool()
	def update_portnox_site(
		name: str,
		description: Optional[str] = None,
		parent_id: Optional[str] = None,
		rules: Optional[List[Dict[str, Any]]] = None,
	) -> Dict[str, Any]:
		"""Alias of create_or_update_site with explicit Portnox naming."""
		return create_or_update_site(
			name=name,
			description=description,
			parent_id=parent_id,
			rules=rules,
		)

	@mcp.tool()
	def update_site_by_id(
		site_id: str,
		name: Optional[str] = None,
		description: Optional[str] = None,
		parent_id: Optional[str] = None,
		rules: Optional[List[Dict[str, Any]]] = None,
	) -> Dict[str, Any]:
		"""Update an existing Portnox site by its unique ID, preserving unchanged fields.

		Prefer this tool over `create_or_update_site` when you know the site's
		Id, because it is immune to name-collision ambiguity.

		The tool fetches the current site first, merges only the provided fields,
		then writes the complete updated object back via the PUT endpoint.  After
		writing, it re-reads the site list to confirm the update took effect.

		Args:
			site_id:     The unique ID of the site to update (required).
			name:        New display name (kept unchanged if not provided).
			description: New description (kept unchanged if not provided).
			parent_id:   New parent site ID (kept unchanged if not provided).
			rules:       New rules array (kept unchanged if not provided).

		Returns:
			Object with status, the previous site data, and the updated site.
		"""
		if not isinstance(site_id, str) or not site_id.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'site_id' must be a non-empty string.")

		target_id = site_id.strip()

		# Fetch all sites and find the matching one by ID.
		# We need the full current object so we can merge changes into it.
		existing_sites = client.get_sites()
		matching_site = None
		for site in existing_sites:
			if isinstance(site.get("Id"), str) and site.get("Id").strip() == target_id:
				matching_site = site
				break

		# If the site does not exist, fail fast rather than sending a PUT that
		# would silently create a new site (a known Portnox API behaviour).
		if not matching_site:
			raise PortnoxApiError(f"No site found with ID '{target_id}'.")

		# Start with the full existing site data and overwrite only what changed.
		site_data = dict(matching_site)

		if name is not None:
			if not isinstance(name, str) or not name.strip():
				raise PortnoxApiError("Missing or malformed parameter: 'name' must be a non-empty string or null.")
			site_data["Name"] = name.strip()

		if description is not None:
			if not isinstance(description, str):
				raise PortnoxApiError("Missing or malformed parameter: 'description' must be a string.")
			site_data["Description"] = description.strip()

		if parent_id is not None:
			if not isinstance(parent_id, str) or not parent_id.strip():
				raise PortnoxApiError("Missing or malformed parameter: 'parent_id' must be a non-empty string or null.")
			site_data["ParentId"] = parent_id.strip()

		if rules is not None:
			if not isinstance(rules, list):
				raise PortnoxApiError("Missing or malformed parameter: 'rules' must be a list.")
			site_data["Rules"] = rules

		# Preserve the original state so we can include it in the response.
		previous_data = dict(matching_site)
		result = client.create_or_update_site(site_data)

		# Safety check: ensure the API updated the same site and did not create
		# a new one under a different ID.
		result_id = _get_string_field(result, ["Id"])
		if result_id and result_id != target_id:
			raise PortnoxApiError(
				"Portnox API returned success but created/returned a different site ID. "
				f"Expected Id={target_id}, got Id={result_id}. Refusing to report success."
			)

		# Re-read the site list to get the authoritative post-update state.
		latest_sites = client.get_sites()
		latest_match = None
		for site in latest_sites:
			sid = _get_string_field(site, ["Id"])
			if sid == target_id:
				latest_match = site
				break

		if latest_match is None:
			raise PortnoxApiError(
				"Portnox API reported success but target site ID was not found afterward. "
				"This endpoint may be creating new sites instead of updating existing ones."
			)

		return {
			"status": "updated",
			"site_id": target_id,
			"previous_data": previous_data,
			"site": latest_match,
		}

	@mcp.tool()
	def update_portnox_site_by_id(
		site_id: str,
		name: Optional[str] = None,
		description: Optional[str] = None,
		parent_id: Optional[str] = None,
		rules: Optional[List[Dict[str, Any]]] = None,
	) -> Dict[str, Any]:
		"""Alias of update_site_by_id with explicit Portnox naming."""
		return update_site_by_id(
			site_id=site_id,
			name=name,
			description=description,
			parent_id=parent_id,
			rules=rules,
		)

	@mcp.tool()
	def delete_site_by_id(site_id: str) -> Dict[str, Any]:
		"""Delete a Portnox site by its unique site ID.

		The tool captures the site's current details before deletion so the
		response includes what was deleted — useful for audit logs and confirming
		the correct site was targeted.

		After calling the API, it re-reads the site list to confirm the site is
		truly gone, guarding against API versions that return 200 but do not
		actually delete the record.

		Args:
			site_id: The unique site ID to delete.

		Returns:
			Object with status "deleted", the site_id, its former name, and the
			full site object as it existed immediately before deletion.
		"""
		if not isinstance(site_id, str) or not site_id.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'site_id' must be a non-empty string.")

		target_id = site_id.strip()

		# Capture site details before delete so the response is informative.
		sites_before = client.get_sites()
		matching_site = None
		for site in sites_before:
			if _get_string_field(site, ["Id"]) == target_id:
				matching_site = dict(site)
				break

		# Verify existence before attempting delete to give a clearer error than
		# the API's generic 400/404 response.
		if matching_site is None:
			raise PortnoxApiError(f"No site found with ID '{target_id}'.")

		client.delete_site(target_id)

		# Post-delete verification: re-fetch all sites and confirm the target is gone.
		sites_after = client.get_sites()
		for site in sites_after:
			if _get_string_field(site, ["Id"]) == target_id:
				raise PortnoxApiError(
					f"Delete call returned success but site ID '{target_id}' still exists."
				)

		return {
			"status": "deleted",
			"site_id": target_id,
			"site_name": _get_string_field(matching_site, ["Name"]),
			"deleted_site": matching_site,
		}

	@mcp.tool()
	def delete_portnox_site_by_id(site_id: str) -> Dict[str, Any]:
		"""Alias of delete_site_by_id with explicit Portnox naming."""
		return delete_site_by_id(site_id=site_id)

	@mcp.tool()
	def delete_site_by_name(name: str) -> Dict[str, Any]:
		"""Delete a Portnox site identified by its display name.

		Uses a case-insensitive name lookup.  If the name matches exactly one
		site, that site is deleted.  If multiple sites share the name, the tool
		refuses to proceed and returns their IDs so the caller can use
		`delete_site_by_id` to target the correct one unambiguously.

		Args:
			name: Display name of the site to delete.

		Returns:
			Same response shape as delete_site_by_id.
		"""
		if not isinstance(name, str) or not name.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'name' must be a non-empty string.")

		target_name = name.strip()
		sites = client.get_sites()

		# Collect all sites whose name matches (case-insensitively).
		matches: List[Dict[str, Any]] = []
		for site in sites:
			site_name = _get_string_field(site, ["Name"])
			if site_name and site_name.casefold() == target_name.casefold():
				matches.append(site)

		if len(matches) == 0:
			raise PortnoxApiError(f"No site found with name '{target_name}'.")

		# Ambiguous — do not guess which site to delete.
		if len(matches) > 1:
			match_ids = [_get_string_field(s, ["Id"]) for s in matches]
			raise PortnoxApiError(
				f"Multiple sites found with name '{target_name}'. Use delete_site_by_id with one of: {match_ids}"
			)

		# Exactly one match — resolve to ID and delegate to delete_site_by_id.
		target_id = _get_string_field(matches[0], ["Id"])
		if not target_id:
			raise PortnoxApiError(
				f"Site '{target_name}' is missing Id and cannot be deleted by name."
			)

		return delete_site_by_id(site_id=target_id)

	@mcp.tool()
	def delete_portnox_site(name: str) -> Dict[str, Any]:
		"""Alias of delete_site_by_name with explicit Portnox naming."""
		return delete_site_by_name(name=name)

	@mcp.tool()
	def update_site_rules_by_id(site_id: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
		"""Replace all membership rules for a Portnox site identified by its ID.

		Rules define which IP addresses or subnets belong to the site.
		This is a full replacement — any existing rules not present in the new
		list will be removed.

		Rules format:
		  - Type 1: CIDR / subnet rule.  Set From = network address,
		            Mask = prefix length (e.g. "24"), To = null.
		  - Type 2: IP range rule.  Set From = first IP, To = last IP,
		            Mask = null.

		Before sending the update, the tool verifies the site exists and
		confirms the returned updated site has the expected ID.

		Args:
			site_id: Unique site identifier.
			rules:   Non-empty list of rule objects.

		Returns:
			Object with status, site name, rule count, and the updated site.
		"""
		if not isinstance(site_id, str) or not site_id.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'site_id' must be a non-empty string.")
		if not isinstance(rules, list) or len(rules) == 0:
			raise PortnoxApiError("Missing or malformed parameter: 'rules' must be a non-empty list.")

		target_id = site_id.strip()

		# Verify the site exists before attempting the update.  This gives a
		# human-readable error rather than a raw API error if the ID is wrong.
		sites_before = client.get_sites()
		matching_site = None
		for site in sites_before:
			if _get_string_field(site, ["Id"]) == target_id:
				matching_site = site
				break

		if matching_site is None:
			raise PortnoxApiError(f"No site found with ID '{target_id}'.")

		updated_site = client.update_site_rules(site_id=target_id, rules=rules)

		# Confirm the API returned the same site ID we targeted.
		updated_id = _get_string_field(updated_site, ["Id"])
		if updated_id and updated_id != target_id:
			raise PortnoxApiError(
				"Portnox API returned success but returned a different site ID for rules update. "
				f"Expected Id={target_id}, got Id={updated_id}."
			)

		return {
			"status": "updated",
			"site_id": target_id,
			"site_name": _get_string_field(matching_site, ["Name"]),
			"rules_count": len(rules),
			"site": updated_site,
		}

	@mcp.tool()
	def update_portnox_site_rules_by_id(site_id: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
		"""Alias of update_site_rules_by_id with explicit Portnox naming."""
		return update_site_rules_by_id(site_id=site_id, rules=rules)

	@mcp.tool()
	def update_site_rules_by_name(name: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
		"""Replace membership rules for a Portnox site identified by name.

		Uses a case-insensitive name lookup.  Fails if multiple sites share
		the same name; use `update_site_rules_by_id` in that case.

		Args:
			name:  Display name of the site to update.
			rules: Non-empty list of rule objects (same format as update_site_rules_by_id).

		Returns:
			Same response shape as update_site_rules_by_id.
		"""
		if not isinstance(name, str) or not name.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'name' must be a non-empty string.")
		if not isinstance(rules, list) or len(rules) == 0:
			raise PortnoxApiError("Missing or malformed parameter: 'rules' must be a non-empty list.")

		target_name = name.strip()
		sites = client.get_sites()

		# Collect sites whose name matches case-insensitively.
		matches: List[Dict[str, Any]] = []
		for site in sites:
			site_name = _get_string_field(site, ["Name"])
			if site_name and site_name.casefold() == target_name.casefold():
				matches.append(site)

		if len(matches) == 0:
			raise PortnoxApiError(f"No site found with name '{target_name}'.")

		if len(matches) > 1:
			match_ids = [_get_string_field(s, ["Id"]) for s in matches]
			raise PortnoxApiError(
				f"Multiple sites found with name '{target_name}'. Use update_site_rules_by_id with one of: {match_ids}"
			)

		# Resolve the name to a unique ID and delegate to the ID-based tool.
		target_id = _get_string_field(matches[0], ["Id"])
		if not target_id:
			raise PortnoxApiError(
				f"Site '{target_name}' is missing Id and cannot be updated by name."
			)

		return update_site_rules_by_id(site_id=target_id, rules=rules)

	@mcp.tool()
	def update_portnox_site_rules(name: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
		"""Alias of update_site_rules_by_name with explicit Portnox naming."""
		return update_site_rules_by_name(name=name, rules=rules)

	@mcp.tool()
	def list_devices(
		page_number: int = 1,
		page_size: int = 10,
		search_value: Optional[str] = None,
		search_field: Optional[int] = None,
		include_account_without_devices: bool = False,
		client_time_offset: int = 0,
	) -> Dict[str, Any]:
		"""List a single page of Portnox endpoint devices with optional search.

		The Portnox device list endpoint is paginated.  This tool returns one
		page at a time along with total count and page metadata so callers can
		iterate through pages manually if needed.

		For retrieving all devices at once, use `list_all_devices` instead.

		Args:
			page_number:                   1-based page index (default 1).
			page_size:                     Devices per page (default 10).
			search_value:                  Optional text to filter devices.
			search_field:                  Field selector for the search.
			                               0 = all fields, 1 = email/account.
			include_account_without_devices: Include accounts with no devices.
			client_time_offset:            UTC offset in minutes for time filters.

		Returns:
			Object containing page metadata and the `items` list of device
			entries for the requested page.
		"""
		response = client.list_devices(
			page_number=page_number,
			page_size=page_size,
			search_value=search_value,
			search_field=search_field,
			include_account_without_devices=include_account_without_devices,
			client_time_offset=client_time_offset,
		)

		# Extract pagination fields from the raw response for the envelope.
		items = response.get("Result") if isinstance(response, dict) else None
		total_devices = response.get("TotalDevices") if isinstance(response, dict) else None
		total_pages = response.get("TotalPages") if isinstance(response, dict) else None

		return {
			"page_number": page_number,
			"page_size": page_size,
			"count": len(items) if isinstance(items, list) else 0,
			"total_devices": total_devices,
			"total_pages": total_pages,
			"items": items if isinstance(items, list) else [],
			# Include the raw response so callers can inspect any extra fields
			# not explicitly surfaced by this envelope.
			"raw": response,
		}

	@mcp.tool()
	def list_portnox_devices(
		page_number: int = 1,
		page_size: int = 10,
		search_value: Optional[str] = None,
		search_field: Optional[int] = None,
		include_account_without_devices: bool = False,
		client_time_offset: int = 0,
	) -> Dict[str, Any]:
		"""Alias of list_devices with explicit Portnox naming."""
		return list_devices(
			page_number=page_number,
			page_size=page_size,
			search_value=search_value,
			search_field=search_field,
			include_account_without_devices=include_account_without_devices,
			client_time_offset=client_time_offset,
		)

	@mcp.tool()
	def list_all_devices(
		page_size: int = 10,
		search_value: Optional[str] = None,
		search_field: Optional[int] = None,
		include_account_without_devices: bool = False,
		client_time_offset: int = 0,
		max_pages: int = 1000,
	) -> Dict[str, Any]:
		"""Fetch every page of /api/device/list and return a flat list of device rows.

		The Portnox device list nests device objects inside account entries.
		This tool:
		  1. Fetches the first page to discover TotalPages.
		  2. Fetches all remaining pages (up to max_pages).
		  3. Flattens the nested structure so each output row is
		     {"account": {...}, "device": {...}}.

		This makes it easy for callers to iterate devices without dealing with
		pagination or the nested account/device schema themselves.

		Args:
			page_size:                     Devices per page (default 10).
			search_value:                  Optional text filter.
			search_field:                  Field selector (0=all, 1=email).
			include_account_without_devices: Include deviceless account rows.
			client_time_offset:            UTC offset in minutes.
			max_pages:                     Hard cap on pages fetched, as a
			                               safety net for very large deployments.

		Returns:
			Object with pages_fetched, total counts from the first page, a
			flattened_count of individual device rows, and the `items` list.
		"""
		if page_size < 1:
			raise PortnoxApiError("Missing or malformed parameter: 'page_size' must be >= 1.")
		if max_pages < 1:
			raise PortnoxApiError("Missing or malformed parameter: 'max_pages' must be >= 1.")

		# Fetch page 1 first to learn how many total pages exist.
		first_page = client.list_devices(
			page_number=1,
			page_size=page_size,
			search_value=search_value,
			search_field=search_field,
			include_account_without_devices=include_account_without_devices,
			client_time_offset=client_time_offset,
		)

		first_items = first_page.get("Result") if isinstance(first_page, dict) else None
		if not isinstance(first_items, list):
			first_items = []

		# Parse TotalPages defensively; fall back to 1 if missing or invalid.
		total_pages_raw = first_page.get("TotalPages") if isinstance(first_page, dict) else None
		try:
			total_pages = int(total_pages_raw) if total_pages_raw is not None else 1
		except (TypeError, ValueError):
			total_pages = 1

		if total_pages < 1:
			total_pages = 1

		# Respect the caller's max_pages cap to avoid unbounded API usage.
		if total_pages > max_pages:
			total_pages = max_pages

		# Collect all page responses, starting with the already-fetched first page.
		page_results: List[Dict[str, Any]] = [first_page]

		for page_number in range(2, total_pages + 1):
			page = client.list_devices(
				page_number=page_number,
				page_size=page_size,
				search_value=search_value,
				search_field=search_field,
				include_account_without_devices=include_account_without_devices,
				client_time_offset=client_time_offset,
			)
			page_results.append(page)

		# Flatten the nested account→devices structure into a simple list.
		# Each Portnox page entry has an Account and a Devices array;
		# we emit one row per device so consumers get a 1D list to iterate.
		flattened: List[Dict[str, Any]] = []
		for page in page_results:
			page_items = page.get("Result") if isinstance(page, dict) else None
			if not isinstance(page_items, list):
				continue

			for entry in page_items:
				if not isinstance(entry, dict):
					continue

				account = entry.get("Account")
				devices = entry.get("Devices")

				if isinstance(devices, list) and len(devices) > 0:
					# Emit one row per device, each paired with its account.
					for device in devices:
						flattened.append({
							"account": account if isinstance(account, dict) else None,
							"device": device if isinstance(device, dict) else device,
						})
				elif include_account_without_devices:
					# Emit the account row with a null device when requested.
					flattened.append({
						"account": account if isinstance(account, dict) else None,
						"device": None,
					})

		return {
			"status": "ok",
			"pages_fetched": len(page_results),
			"page_size": page_size,
			# Report the server's own totals so callers can detect truncation
			# caused by the max_pages limit.
			"total_pages_reported": first_page.get("TotalPages") if isinstance(first_page, dict) else None,
			"total_devices_reported": first_page.get("TotalDevices") if isinstance(first_page, dict) else None,
			"flattened_count": len(flattened),
			"items": flattened,
		}

	@mcp.tool()
	def list_all_portnox_devices(
		page_size: int = 10,
		search_value: Optional[str] = None,
		search_field: Optional[int] = None,
		include_account_without_devices: bool = False,
		client_time_offset: int = 0,
		max_pages: int = 1000,
	) -> Dict[str, Any]:
		"""Alias of list_all_devices with explicit Portnox naming."""
		return list_all_devices(
			page_size=page_size,
			search_value=search_value,
			search_field=search_field,
			include_account_without_devices=include_account_without_devices,
			client_time_offset=client_time_offset,
			max_pages=max_pages,
		)

	@mcp.tool()
	def block_device(entity_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
		"""Quarantine a device so it cannot access the network.

		Blocks the device identified by `entity_id` (also called DeviceId).
		If no reason is provided, a default reason is used so the Portnox
		audit log is never left with an empty reason field.

		Args:
			entity_id: Unique device identifier (DeviceId / EntityId).
			reason:    Optional human-readable reason for the block action.

		Returns:
			Object confirming the block with the entity_id and reason recorded.
		"""
		if not isinstance(entity_id, str) or not entity_id.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'entity_id' must be a non-empty string.")

		# Provide a sensible default reason if the caller omits one, because
		# Portnox requires a non-empty reason for the block API call.
		final_reason = (
			reason.strip()
			if isinstance(reason, str) and reason.strip()
			else "Device blocked by the Portnox MCP server"
		)

		client.block_device(entity_id=entity_id.strip(), reason=final_reason)

		return {
			"status": "blocked",
			"entity_id": entity_id.strip(),
			"reason": final_reason,
		}

	@mcp.tool()
	def block_portnox_device(entity_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
		"""Alias of block_device with explicit Portnox naming."""
		return block_device(entity_id=entity_id, reason=reason)

	@mcp.tool()
	def unblock_device(entity_id: str) -> Dict[str, Any]:
		"""Restore network access for a previously blocked device.

		Args:
			entity_id: Unique device identifier (DeviceId / EntityId).

		Returns:
			Object confirming the unblock with the entity_id.
		"""
		if not isinstance(entity_id, str) or not entity_id.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'entity_id' must be a non-empty string.")

		client.unblock_device(entity_id=entity_id.strip())

		return {
			"status": "unblocked",
			"entity_id": entity_id.strip(),
		}

	@mcp.tool()
	def unblock_portnox_device(entity_id: str) -> Dict[str, Any]:
		"""Alias of unblock_device with explicit Portnox naming."""
		return unblock_device(entity_id=entity_id)

	@mcp.tool()
	def delete_device(device_id: str) -> Dict[str, Any]:
		"""Permanently remove a device record from Portnox CLEAR.

		Sends DELETE /api/device/{deviceId}.  Unlike blocking, deletion removes
		the device's history from the system entirely and cannot be undone.
		Use this only when a device has been decommissioned or should no longer
		appear in any Portnox report.

		Args:
			device_id: Unique device identifier (DeviceId / EntityId).

		Returns:
			Object confirming deletion with the device_id that was deleted.
		"""
		if not isinstance(device_id, str) or not device_id.strip():
			raise PortnoxApiError("Missing or malformed parameter: 'device_id' must be a non-empty string.")

		# Delegate to the client method which handles URL construction and
		# HTTP status code mapping.
		client.delete_device(device_id=device_id.strip())

		return {
			"status": "deleted",
			"device_id": device_id.strip(),
		}

	@mcp.tool()
	def delete_portnox_device(device_id: str) -> Dict[str, Any]:
		"""Alias of delete_device with explicit Portnox naming."""
		return delete_device(device_id=device_id)

	@mcp.tool()
	def find_devices_by_account_name(
		account_name: str, search_field: int = 1
	) -> Dict[str, Any]:
		"""Search for all devices associated with a user account name or email.

		Queries the Portnox device list using the account name as the search
		term and iterates all result pages.  Default search_field=1 targets
		the email / account identifier field.

		Returns device details including EntityId values that can be passed
		directly to block_device, unblock_device, or delete_device.

		Args:
			account_name:  Email address or account name to search for.
			search_field:  Integer field selector (default 1 = email/account).

		Returns:
			Object with the account name searched, a `matches` list of device
			summary objects, and a count.
		"""
		if not isinstance(account_name, str) or not account_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_name' must be a non-empty string."
			)

		devices = client.find_devices_by_account_name(
			account_name=account_name.strip(), search_field=search_field
		)

		# Return a consistent envelope even when no devices are found so callers
		# do not need to guard against missing keys.
		if not devices:
			return {
				"account_name": account_name.strip(),
				"search_field": search_field,
				"matches": [],
				"count": 0,
			}

		# Project each raw result entry to a flat, predictable summary object.
		# The raw entries are account-level objects with a Devices sub-list;
		# we flatten them here for convenience.
		device_list = []
		for dev in devices:
			device_list.append(
				{
					"entity_id": dev.get("EntityId"),
					"device_name": dev.get("DeviceName"),
					"device_type": dev.get("DeviceType"),
					"mac_address": dev.get("MacAddress"),
					"ip_address": dev.get("IPAddress"),
					"status": dev.get("Status"),
				}
			)

		return {
			"account_name": account_name.strip(),
			"search_field": search_field,
			"matches": device_list,
			"count": len(device_list),
		}

	@mcp.tool()
	def find_portnox_devices_by_account_name(
		account_name: str, search_field: int = 1
	) -> Dict[str, Any]:
		"""Alias of find_devices_by_account_name with explicit Portnox naming."""
		return find_devices_by_account_name(
			account_name=account_name, search_field=search_field
		)

	@mcp.tool()
	def block_device_by_account_name(
		account_name: str, reason: Optional[str] = None
	) -> Dict[str, Any]:
		"""Find every device belonging to an account and block them all.

		This is a convenience tool for scenarios like "block all devices for
		user@example.com" — it combines a device search (search_field=1 for
		email) with a batch block operation.

		Each device is blocked individually; if one block fails it is recorded
		in the response with an `error` key rather than aborting the whole batch.

		Args:
			account_name: Email address or account name whose devices to block.
			reason:       Optional reason; a default is used if not provided.

		Returns:
			Object with the account name, reason, a `blocked` list detailing
			each device's outcome, and a count of successfully blocked devices.
		"""
		if not isinstance(account_name, str) or not account_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_name' must be a non-empty string."
			)

		# search_field=1 targets the email/account identifier.
		devices = client.find_devices_by_account_name(
			account_name=account_name.strip(), search_field=1
		)

		if not devices:
			return {
				"account_name": account_name.strip(),
				"blocked": [],
				"blocked_count": 0,
				"message": f"No devices found for account '{account_name.strip()}'",
			}

		final_reason = (
			reason.strip() if isinstance(reason, str) and reason.strip() else "Device blocked by the Portnox MCP server"
		)

		blocked_devices = []
		for dev in devices:
			entity_id = dev.get("EntityId")

			# Skip entries that are missing an EntityId; they cannot be blocked.
			if not entity_id:
				continue

			try:
				client.block_device(entity_id=str(entity_id), reason=final_reason)
				# Record success.
				blocked_devices.append(
					{
						"entity_id": str(entity_id),
						"device_name": dev.get("DeviceName"),
						"reason": final_reason,
					}
				)
			except PortnoxApiError as e:
				# Record failure without aborting the rest of the batch.
				blocked_devices.append(
					{
						"entity_id": str(entity_id),
						"device_name": dev.get("DeviceName"),
						"error": str(e),
					}
				)

		return {
			"account_name": account_name.strip(),
			"reason": final_reason,
			"blocked": blocked_devices,
			# Count only entries that succeeded (i.e. have no "error" key).
			"blocked_count": len([d for d in blocked_devices if "error" not in d]),
		}

	@mcp.tool()
	def block_portnox_device_by_account_name(
		account_name: str, reason: Optional[str] = None
	) -> Dict[str, Any]:
		"""Alias of block_device_by_account_name with explicit Portnox naming."""
		return block_device_by_account_name(
			account_name=account_name, reason=reason
		)

	@mcp.tool()
	def get_device_details(device_id: str) -> Dict[str, Any]:
		"""Retrieve comprehensive telemetry and configuration for a single device.

		Fetches all available information about a device identified by its unique
		ID (DeviceId / EntityId).  This includes a very rich set of nested data
		structures covering multiple device types and integration points.

		Data returned includes (where available):
		  - Mobile device profile: GSM/cellular settings, WiFi configuration,
		    MDM enrollment status, installed applications, certificates.
		  - Computer profile: Windows/macOS/Linux OS details, installed software,
		    security software status, network interfaces, users and groups,
		    domain membership, BitLocker/FileVault status.
		  - Authentication history: Every validation attempt (successful or failed),
		    which NAS device the device connected through, ACL assignments, VLAN
		    assignments, RADIUS attributes.
		  - Risk assessment: Compliance score, policy violations with grace periods,
		    scoring details.
		  - Integration data: Azure AD/Entra ID registration, Intune compliance,
		    Jamf enrollment, CrowdStrike integration, SentinelOne integration.
		  - Location data: Geolocation if available (latitude, longitude, city,
		    country, postal code).
		  - Certificates: Enrollment certificate, machine certificate, user
		    certificates from installed accounts.

		Because the response is extremely nested and heterogeneous, many fields
		may be null or absent depending on:
		  - Device type (mobile vs desktop vs server).
		  - Installed agents and enrollment status.
		  - How long the device has been in Portnox's database.
		  - Third-party integrations enabled at your organization.

		The caller is expected to handle optional fields gracefully rather than
		assuming a fixed response schema.

		Args:
			device_id: Unique device identifier (DeviceId / EntityId).

		Returns:
			A comprehensive device object with all available telemetry, validation
			history, risk assessment, and integration data.  The object is
			extremely nested; consult the Portnox API documentation for the
			complete schema.

		Raises:
			PortnoxApiError: if device_id is empty, the device is not found
			               (HTTP 404), or on any other API error.
		"""
		if not isinstance(device_id, str) or not device_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'device_id' must be a non-empty string."
			)

		# Delegate to the client method, which handles URL construction, HTTP
		# status codes, and JSON parsing.
		device_data = client.get_device(device_id=device_id.strip())

		# Wrap the response in a consistent envelope so callers always get a
		# status field.  The bulk of the response is under "device".
		return {
			"status": "fetched",
			"device_id": device_id.strip(),
			"device": device_data,
		}

	@mcp.tool()
	def get_portnox_device_details(device_id: str) -> Dict[str, Any]:
		"""Alias of get_device_details with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return get_device_details(device_id=device_id)

	@mcp.tool()
	def search_mac_based_accounts(
		mac_addresses: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Search for MAB accounts by whitelisted MAC addresses.

		MAC-based Authentication (MAB) enables network access control for devices
		that either cannot run an enrollment agent (e.g., printers, VoIP phones,
		IoT devices) or where users prefer agentless onboarding.  Each MAB account
		is configured with a whitelist of approved MAC addresses.  This method
		searches for all accounts that match the supplied MAC addresses.

		Typical use cases:
		  - Onboarding a new IP phone: search for its MAC to find/create the MAB
		    account and get the VLAN assignment.
		  - Auditing: find all accounts that have whitelisted a specific MAC
		    (e.g., detect if a contractor device is still whitelisted).
		  - Cleanup: get the list of all configured MAB accounts to identify
		    obsolete or expired whitelist entries.

		The search returns two lists:
		  1. Accounts (matched): MAB accounts with whitelisted MAC addresses that
		     matched the input.
		  2. UnupsertedAccounts (unmatched): Other configured MAB accounts that
		     did not match but are returned for reference/reconciliation.

		Each account in the response includes:
		  - AgentlessOptions: MAC/vendor whitelists, secure MAB settings.
		  - RadiusOptions: Voice VLAN config (for VoIP devices).
		  - Certificates: All enrolled certificates.
		  - Status: Block status, creation date, last update.

		Args:
			mac_addresses: Non-empty list of MAC address objects.  Each object
			               should have:
			               - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			               - "Description" (optional, str): Device description.
			               - "Expiration" (optional, str): ISO 8601 expiry datetime.

		Returns:
			A dict with:
			  - "Accounts": List of matched Account objects (full MAB config).
			  - "UnupsertedAccounts": List of other Account objects.
			  - "IsSuccess": Boolean success indicator.

		Raises:
			PortnoxApiError: if mac_addresses is empty, malformed, or on any API
			               error (400/401/403/500).
		"""
		if not isinstance(mac_addresses, list) or len(mac_addresses) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a non-empty list."
			)

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (MacWhiteList wrapper)
		#   - HTTP status code mapping
		#   - JSON parsing and response shape validation
		search_results = client.search_mac_based_accounts(
			mac_addresses=mac_addresses
		)

		# The response is already a dict with Accounts, UnupsertedAccounts, and
		# IsSuccess.  Wrap it in a consistent envelope for MCP callers.
		return {
			"status": "searched",
			"input_mac_count": len(mac_addresses),
			"result": search_results,
		}

	@mcp.tool()
	def search_portnox_mac_based_accounts(
		mac_addresses: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Alias of search_mac_based_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return search_mac_based_accounts(mac_addresses=mac_addresses)

	@mcp.tool()
	def delete_mac_from_whitelist(
		account_name: str,
		mac_addresses: List[Dict[str, Any]] = None,
		max_whitelist_length: Optional[int] = None,
	) -> Dict[str, Any]:
		"""Remove MAC addresses from a MAB account's whitelist.

		MAC-based Authentication (MAB) accounts maintain a whitelist of MAC
		addresses that are allowed to connect to the network.  This tool removes
		specified MAC addresses from an account's whitelist.

		CRITICAL BEHAVIOR — This tool has dual purposes:
		  1. Partial removal: If mac_addresses contains one or more MAC entries,
		     those specific addresses are removed from the whitelist while
		     preserving all other whitelisted devices.  Example: remove a
		     contractor's iPhone after project ends.
		  2. Full removal: If mac_addresses is an empty list (or None/omitted),
		     the ENTIRE whitelist is deleted, effectively disabling MAB for
		     that account.  Example: convert account from MAB-only to EAP auth.

		Use case examples:
		  - Remove a specific IP phone's MAC after decommissioning (partial).
		  - Revoke all whitelisted devices for a user account (full).
		  - Clean up expired MAC entries before reusing the account (partial).
		  - Disable agentless access for a contractor upon project completion (full).

		The removal is sent via HTTP DELETE with a JSON body containing:
		  - AccountName: The target MAB account to modify.
		  - MacWhiteList: List of MACs to remove (empty list = remove all).
		  - MaxMacWhiteListLength: Optional capacity limit (informational).

		Args:
			account_name: The MAB account name (e.g., email, AD account name).
			              Must be non-empty.  Example: "printer@company.com"
			mac_addresses: List of MAC address objects to remove.  Each object
			              should have:
			              - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			              - "Description" (optional, str): Device description.
			              - "Expiration" (optional, str): ISO 8601 expiry datetime.
			              If omitted or empty, the ENTIRE whitelist is removed.
			max_whitelist_length: Optional integer.  Portnox validates that the
			                     resulting whitelist (after removal) does not
			                     exceed this limit.

		Returns:
			A dict with:
			  - "status": "deleted"
			  - "account_name": The account that was modified.
			  - "mac_count": Number of specific MACs removed (0 for full removal).
			  - "action": Either "partial_removal" or "full_removal" depending
			    on whether mac_addresses was empty.

		Raises:
			PortnoxApiError: if account_name is empty, mac_addresses is malformed,
			               or on any HTTP error (400/401/403/500).
		"""
		# If mac_addresses is None, treat it as an empty list (full removal).
		if mac_addresses is None:
			mac_addresses = []

		if not isinstance(mac_addresses, list):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a list or None."
			)

		# Determine the action type based on whether the list is empty.  This is
		# important to communicate to the caller what happened.
		action = "full_removal" if len(mac_addresses) == 0 else "partial_removal"

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (AccountName, MacWhiteList, MaxMacWhiteListLength)
		#   - HTTP DELETE with JSON body
		#   - HTTP status code mapping
		#   - Response parsing
		client.delete_mac_from_whitelist(
			account_name=account_name,
			mac_addresses=mac_addresses,
			max_whitelist_length=max_whitelist_length,
		)

		# Return a consistent envelope indicating success.  The actual API
		# returns HTTP 200 with no body, so we construct our own response.
		return {
			"status": "deleted",
			"account_name": account_name.strip(),
			"mac_count": len(mac_addresses),
			"action": action,
			"message": (
				"Entire MAC whitelist removed for account"
				if action == "full_removal"
				else f"{len(mac_addresses)} MAC address(es) removed from whitelist"
			),
		}

	@mcp.tool()
	def delete_portnox_mac_from_whitelist(
		account_name: str,
		mac_addresses: List[Dict[str, Any]] = None,
		max_whitelist_length: Optional[int] = None,
	) -> Dict[str, Any]:
		"""Alias of delete_mac_from_whitelist with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return delete_mac_from_whitelist(
			account_name=account_name,
			mac_addresses=mac_addresses,
			max_whitelist_length=max_whitelist_length,
		)

	@mcp.tool()
	def add_mac_to_whitelist(
		account_name: str,
		mac_addresses: List[Dict[str, Any]],
		max_whitelist_length: Optional[int] = None,
	) -> Dict[str, Any]:
		"""Add MAC addresses to a MAB account's whitelist.

		MAC-based Authentication (MAB) enables network access for agentless or
		unmanaged devices (printers, VoIP phones, IoT devices, etc.).  Each MAB
		account maintains a whitelist of approved MAC addresses that are allowed
		to connect.  This tool adds new MAC addresses to an existing account's
		whitelist, growing the set of authorized devices without disrupting
		existing whitelisted devices.

		Common use cases:
		  - Onboarding: add a new printer or VoIP phone to an existing MAB account.
		  - Contractor/guest access: temporarily whitelist a contractor's laptop
		    by MAC address for a project.
		  - Device replacement: add a replacement device's MAC before removing the
		    old MAC (allows for staged transition without service disruption).
		  - Multi-device accounts: build up a whitelist of multiple devices for
		    the same account (e.g., user's laptop + cell phone + tablet).
		  - Capacity planning: add devices up to (but not exceeding) the max
		    whitelist capacity specified by max_whitelist_length.

		The add is sent via HTTP POST with a JSON body containing:
		  - AccountName: The target MAB account to modify.
		  - MacWhiteList: Non-empty list of MACs to add.
		  - MaxMacWhiteListLength: Optional capacity limit (informational).

		Args:
			account_name: The MAB account name (e.g., email, AD account name, or
			             device identifier).  Must be non-empty.  Example:
			             "printer@company.com" or "conference-room-phone"
			mac_addresses: Non-empty list of MAC address objects to add.  Each
			              object should have:
			              - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			              - "Description" (optional, str): Device description
			                (e.g., "Printer in Building A" or "Contractor Laptop").
			              - "Expiration" (optional, str): ISO 8601 expiry datetime
			                (useful for temporary access, e.g., contractors, guests).
			              Example: [
			                {
			                  "Mac": "00:11:22:33:44:55",
			                  "Description": "HP Color Printer",
			                  "Expiration": "2026-12-31T23:59:59Z"
			                }
			              ]
			max_whitelist_length: Optional integer.  Portnox validates that after
			                     adding the new MACs, the total whitelist size
			                     does not exceed this limit.

		Returns:
			A dict with:
			  - "status": "added"
			  - "account_name": The account that was modified.
			  - "mac_count": Number of MAC addresses added.
			  - "message": Human-readable summary.

		Raises:
			PortnoxApiError: if account_name is empty, mac_addresses is empty or
			               malformed, or on any HTTP error (400/401/403/500).
		"""
		if not isinstance(mac_addresses, list) or len(mac_addresses) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a non-empty list."
			)

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (AccountName, MacWhiteList, MaxMacWhiteListLength)
		#   - HTTP POST with JSON body
		#   - HTTP status code mapping
		#   - Response parsing
		client.add_mac_to_whitelist(
			account_name=account_name,
			mac_addresses=mac_addresses,
			max_whitelist_length=max_whitelist_length,
		)

		# Return a consistent envelope indicating success.  The actual API
		# returns HTTP 200 with no body, so we construct our own response.
		return {
			"status": "added",
			"account_name": account_name.strip(),
			"mac_count": len(mac_addresses),
			"message": f"{len(mac_addresses)} MAC address(es) added to whitelist",
		}

	@mcp.tool()
	def add_portnox_mac_to_whitelist(
		account_name: str,
		mac_addresses: List[Dict[str, Any]],
		max_whitelist_length: Optional[int] = None,
	) -> Dict[str, Any]:
		"""Alias of add_mac_to_whitelist with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return add_mac_to_whitelist(
			account_name=account_name,
			mac_addresses=mac_addresses,
			max_whitelist_length=max_whitelist_length,
		)

	@mcp.tool()
	def move_mac_between_accounts(
		current_account_name: str,
		target_account_name: str,
		mac_addresses: List[Dict[str, Any]] = None,
		max_whitelist_length: Optional[int] = None,
	) -> Dict[str, Any]:
		"""Move MAC addresses with corresponding devices between MAB accounts.

		MAC-based Authentication (MAB) devices are associated with specific MAB
		accounts.  When a device needs to be reassigned to a different account
		(e.g., user changes departments, device transferred to new owner), this
		tool moves the MAC address(es) from the source account's whitelist to
		the destination account's whitelist.

		The move operation transfers device association atomically: the MAC(s)
		are removed from the source account and added to the target account
		in a single operation, ensuring no gap in network access for the device.

		CRITICAL BEHAVIOR — This tool has dual purposes:
		  1. Partial move: If mac_addresses contains one or more MAC entries,
		     only those specific addresses are moved while other whitelisted
		     devices remain in the source account.  Example: move a user's
		     printer MAC to their new department's account.
		  2. Full move: If mac_addresses is an empty list (or None/omitted),
		     the ENTIRE whitelist moves from source to target account,
		     consolidating all whitelisted devices under one account.  Example:
		     merge two account's device inventories when accounts are combined.

		Use case examples:
		  - Department transfer: move an employee's assigned IP phone MAC when
		    the employee changes departments (partial).
		  - Account consolidation: move all whitelisted devices from a
		    contractor's account to the account that's taking over their work
		    (full).
		  - Device reassignment: move specific devices while others stay with
		    the original owner (partial).
		  - Merger/acquisition: consolidate all agentless device MACs from
		    multiple accounts into a single unified account (full moves).

		The move is sent via HTTP POST with a JSON body containing:
		  - CurrentAccountName: Source MAB account to remove MACs from.
		  - TargetAccountName: Destination MAB account to add MACs to.
		  - MacWhiteList: List of MACs to move (empty list = move all).
		  - MaxMacWhiteListLength: Optional capacity limit for target account.

		Args:
			current_account_name: Source MAB account (e.g., email, AD name).
			                      Must be non-empty and different from target.
			target_account_name: Destination MAB account.  Must be non-empty
			                    and different from current.
			mac_addresses: List of MAC address objects to move.  Each should have:
			              - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			              - "Description" (optional, str): Device description.
			              - "Expiration" (optional, str): ISO 8601 expiry datetime.
			              If omitted or empty, the ENTIRE whitelist is moved.
			max_whitelist_length: Optional integer.  Portnox validates that after
			                     moving the MACs into the target account, the
			                     target's whitelist size does not exceed this limit.

		Returns:
			A dict with:
			  - "status": "moved"
			  - "current_account_name": Source account that was emptied (or partially reduced).
			  - "target_account_name": Destination account that received the MACs.
			  - "mac_count": Number of specific MACs moved (0 for full move).
			  - "action": Either "partial_move" or "full_move".
			  - "message": Human-readable summary.

		Raises:
			PortnoxApiError: if either account name is empty, they are identical,
			               mac_addresses is malformed, or on any HTTP error
			               (400/401/403/500).
		"""
		# If mac_addresses is None, treat it as an empty list (full move).
		if mac_addresses is None:
			mac_addresses = []

		if not isinstance(mac_addresses, list):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a list or None."
			)

		# Determine the action type based on whether the list is empty.  This is
		# important to communicate to the caller what happened.
		action = "full_move" if len(mac_addresses) == 0 else "partial_move"

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (CurrentAccountName, TargetAccountName, MacWhiteList, MaxMacWhiteListLength)
		#   - HTTP POST with JSON body
		#   - Account name validation (non-empty and different)
		#   - HTTP status code mapping
		#   - Response parsing
		client.move_mac_between_accounts(
			current_account_name=current_account_name,
			target_account_name=target_account_name,
			mac_addresses=mac_addresses,
			max_whitelist_length=max_whitelist_length,
		)

		# Return a consistent envelope indicating success.  The actual API
		# returns HTTP 200 with no body, so we construct our own response.
		return {
			"status": "moved",
			"current_account_name": current_account_name.strip(),
			"target_account_name": target_account_name.strip(),
			"mac_count": len(mac_addresses),
			"action": action,
			"message": (
				f"Entire MAB whitelist moved from '{current_account_name.strip()}' to '{target_account_name.strip()}'"
				if action == "full_move"
				else f"{len(mac_addresses)} MAC address(es) moved from '{current_account_name.strip()}' to '{target_account_name.strip()}'"
			),
		}

	@mcp.tool()
	def move_portnox_mac_between_accounts(
		current_account_name: str,
		target_account_name: str,
		mac_addresses: List[Dict[str, Any]] = None,
		max_whitelist_length: Optional[int] = None,
	) -> Dict[str, Any]:
		"""Alias of move_mac_between_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return move_mac_between_accounts(
			current_account_name=current_account_name,
			target_account_name=target_account_name,
			mac_addresses=mac_addresses,
			max_whitelist_length=max_whitelist_length,
		)

	@mcp.tool()
	def change_mac_expiration(
		account_name: str,
		mac_addresses: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Change the expiration time for one or multiple MAC addresses in a whitelist.

		MAC-based Authentication (MAB) devices are often granted temporary network
		access via MAC whitelisting with expiration dates.  Rather than removing
		and re-adding a MAC address to extend access, this tool updates the
		expiration timestamp directly, preserving all other whitelist properties.

		This operation is useful for:
		  - Extending contractor/guest access: a contractor's device MAC is
		    expiring; extend the deadline without re-enrollment ceremony.
		  - Batch updates: refresh multiple device expirations at once (e.g.,
		    all devices in a project extended by 6 months).
		  - Temporary lab devices: a device needs continued lab access; bump
		    its expiration without full re-provisioning.
		  - Enforcing uniform cutoff dates: set all MACs in an account to
		    expire on the same future date (e.g., end of fiscal year).
		  - Remediation: reset an accidentally-expired MAC to a valid future
		    date without losing the device's history.

		Important: This operation changes ONLY the expiration timestamp.  The
		MAC address itself and all other whitelist properties (description, etc.)
		remain unchanged.  If you need to modify description or other fields,
		use a remove + add sequence instead.

		The expiration change is sent via HTTP POST with a JSON body containing:
		  - AccountName: The target MAB account to modify.
		  - MacWhiteList: Non-empty list of MACs with new expiration times.

		Args:
			account_name: The MAB account name (e.g., email, AD account name).
			             Must be non-empty.
			mac_addresses: Non-empty list of MAC address objects to update.  Each
			              object should have:
			              - "Mac" (required, str): MAC address (e.g., "00:11:22:33:44:55").
			              - "Expiration" (required, str): New ISO 8601 expiry datetime
			                (e.g., "2026-12-31T23:59:59Z").
			              - "Description" (optional, str): Ignored by this operation;
			                included for schema consistency.
			              Example: [
			                {
			                  "Mac": "00:11:22:33:44:55",
			                  "Expiration": "2026-12-31T23:59:59Z"
			                }
			              ]

		Returns:
			A dict with:
			  - "status": "updated"
			  - "account_name": The account that was modified.
			  - "mac_count": Number of MAC expirations updated.
			  - "message": Human-readable summary.

		Raises:
			PortnoxApiError: if account_name is empty, mac_addresses is empty or
			               malformed, or on any HTTP error (400/401/403/500).
		"""
		if not isinstance(mac_addresses, list) or len(mac_addresses) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'mac_addresses' must be a non-empty list."
			)

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (AccountName, MacWhiteList)
		#   - HTTP POST with JSON body
		#   - Input validation (account name, MAC entries, Expiration field)
		#   - HTTP status code mapping
		#   - Response parsing
		client.change_mac_expiration(
			account_name=account_name,
			mac_addresses=mac_addresses,
		)

		# Return a consistent envelope indicating success.  The actual API
		# returns HTTP 200 with no body, so we construct our own response.
		return {
			"status": "updated",
			"account_name": account_name.strip(),
			"mac_count": len(mac_addresses),
			"message": f"Expiration time updated for {len(mac_addresses)} MAC address(es)",
		}

	@mcp.tool()
	def change_portnox_mac_expiration(
		account_name: str,
		mac_addresses: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Alias of change_mac_expiration with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return change_mac_expiration(
			account_name=account_name,
			mac_addresses=mac_addresses,
		)

	@mcp.tool()
	def get_mac_based_account(
		account_id: str,
	) -> Dict[str, Any]:
		"""Retrieve comprehensive configuration and state for a MAB account by ID.

		MAB (MAC-based Authentication) accounts maintain all the configuration
		and state needed to authenticate and authorize unmanaged/agentless
		network devices based on their MAC address.  This tool fetches the
		complete account record, including:
		  - Account metadata (ID, name, description, group, creation info)
		  - Agentless options (MAC whitelist entries with expiration dates,
		    vendor whitelist, secure MAB settings)
		  - RADIUS options (Voice VLAN for VoIP phones)
		  - Admin block status (if account is disabled and reason why)

		This operation is useful for:
		  - Compliance audits: Review which MACs are whitelisted, their descriptions,
		    and expiration dates to ensure only authorized devices are configured.
		  - Pre-flight checks: Before adding/removing/moving MACs, verify the
		    account exists, is not blocked, and understand current whitelist state.
		  - Troubleshooting: When a device cannot authenticate via MAB, retrieve
		    the account to verify the MAC is whitelisted, not expired, and the
		    account is not blocked.
		  - Account migration: Export full account configuration (including vendor
		    restrictions, RADIUS settings, and all whitelist entries) for backup
		    or transfer to a new system.
		  - Security review: Identify MAC entries nearing expiration to plan
		    renewal or decommissioning of temporary devices (contractors, guests).
		  - Capacity planning: Inspect how many MAC slots are used vs the account's
		    configured limits.

		The response is HTTP 200 with a complete account object containing:
		  - OrgId, AccountId, AccountName, Description, GroupId
		  - CreatedAt, CreationType, LastUpdatedBy, IdentityType
		  - AgentlessOptions with MacWhiteList (each entry has Mac, Description, Expiration)
		  - AgentlessOptions with VendorsWhiteList (approved MAC vendor prefixes)
		  - AgentlessOptions with SecureMabOptions (enhanced security configuration)
		  - RadiusOptions (Voice VLAN settings if configured)
		  - IsBlockByAdmin and BlockReason (if account is disabled)

		Args:
			account_id: The unique MAB account identifier (AccountId as returned by
			           search_mac_based_accounts or previous get_mac_based_account calls).
			           Must be non-empty.

		Returns:
			A dict containing the complete MAB account object with all nested
			configuration sections (AgentlessOptions, RadiusOptions, etc.).

		Raises:
			PortnoxApiError: if account_id is empty, API returns 404 (account not
			               found), or on any HTTP error (400/401/403/500).
		"""
		if not isinstance(account_id, str) or not account_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_id' must be a non-empty string."
			)

		# Delegate to the client method, which handles:
		#   - URL construction with account ID path parameter
		#   - HTTP GET request
		#   - Input validation (non-empty account_id)
		#   - HTTP status code mapping (200, 400, 401, 403, 404, 500)
		#   - Response parsing and shape validation
		account = client.get_mac_based_account(
			account_id=account_id,
		)

		# Return the account object directly (already a dict).  The API response
		# is structured, so we return it as-is without additional wrapping.
		# This preserves all nested data (whitelists, options, etc.) for the caller.
		return account

	@mcp.tool()
	def get_portnox_mac_based_account(
		account_id: str,
	) -> Dict[str, Any]:
		"""Alias of get_mac_based_account with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return get_mac_based_account(
			account_id=account_id,
		)

	@mcp.tool()
	def create_mac_based_accounts(
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Create one or more new MAB (MAC-based Authentication) accounts.

		MAB accounts enable unmanaged/agentless network devices (printers, IP phones,
		IoT sensors, etc.) to connect to the network by registering their MAC
		addresses.  This tool creates new MAB accounts with initial configuration
		including MAC whitelists, vendor restrictions, RADIUS settings, and
		credential expiration.

		This operation is useful for:
		  - Onboarding managed printers: create an account for a printer's MAC,
		    configure Voice VLAN if needed, restrict to known printer vendors.
		  - VoIP phone deployment: batch-create MAB accounts for all new IP phones
		    with Voice VLAN enabled for proper network segmentation.
		  - Contractor IoT devices: create a MAB account for a contractor's sensor
		    or device, set expiration date to enforce temporary access limits.
		  - Lab device provisioning: create multiple MAB accounts in one operation
		    for all devices in a testing lab or data center.
		  - Device onboarding workflow: create a MAB account as the first step of
		    new device enrollment, then incrementally add more details later.

		Each account in the request specifies:
		  - AccountName: Required unique identifier for the account (device name,
		    department, use case, etc.).
		  - Description: Optional description of the account/device.
		  - MacWhiteList: Optional list of MAC addresses to authorize immediately.
		  - VendorsWhiteList: Optional list of approved MAC vendors by prefix.
		  - AllowAgentlessDevices: Optional boolean to enable/disable MAB.
		  - PutDevicesIntoVoiceVlan: Optional boolean to assign Voice VLAN (IP phones).
		  - CredentialsExpirationDate: Optional ISO 8601 timestamp for account
		    expiration (enforces temporary access).
		  - IdentityPreSharedKey: Optional pre-shared key for secure MAB.
		  - MaxMacWhiteListLenght: Optional limit on MAC whitelist size.
		  - MaxVendorsWhiteListsLenght: Optional limit on vendor list size.

		The response includes both created accounts and any that failed:
		  - "Accounts": Successfully created accounts (each with generated AccountId).
		  - "UnupsertedAccounts": Accounts that failed to create (inspect for reasons,
		    e.g., duplicate AccountName, validation failure).
		  - "IsSuccess": Overall operation success indicator.

		Args:
			accounts: Non-empty list of MAB account definition objects.  Each should have:
			         - "AccountName" (required, str): Unique account identifier.
			         - "Description" (optional, str): Human-readable description.
			         - "MacWhiteList" (optional, list): Initial MACs to authorize.
			           Each entry: {"Mac": "...", "Description": "...", "Expiration": "..."}.
			         - "VendorsWhiteList" (optional, list): Approved MAC vendors.
			         - "AllowAgentlessDevices" (optional, bool): Enable MAB.
			         - "PutDevicesIntoVoiceVlan" (optional, bool): Enable Voice VLAN.
			         - "CredentialsExpirationDate" (optional, str): ISO 8601 timestamp.
			         - "IdentityPreSharedKey" (optional, str): Pre-shared key.
			         - "MaxMacWhiteListLenght" (optional, int): Max MAC whitelist entries.
			         - "MaxVendorsWhiteListsLenght" (optional, int): Max vendor entries.
			         Example: [
			           {
			             "AccountName": "printer-5th-floor",
			             "Description": "Xerox printer in building 5",
			             "MacWhiteList": [
			               {"Mac": "AA:BB:CC:DD:EE:FF", "Description": "Primary"}
			             ],
			             "AllowAgentlessDevices": true,
			             "PutDevicesIntoVoiceVlan": false
			           }
			         ]

		Returns:
			A dict with:
			  - "Accounts": List of successfully created Account objects (each with
			    generated AccountId and full configuration).
			  - "UnupsertedAccounts": List of accounts that failed to create.
			  - "IsSuccess": Boolean indicating overall success.

		Raises:
			PortnoxApiError: if accounts list is empty or malformed, or on any
			               HTTP error (400/401/403/500).
		"""
		if not isinstance(accounts, list) or len(accounts) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'accounts' must be a non-empty list."
			)

		# Validate that each account has at least an AccountName field.  This catches
		# obvious mistakes before delegating to the API.
		for idx, account_obj in enumerate(accounts):
			if not isinstance(account_obj, dict):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must be a dict, got {type(account_obj).__name__}"
				)
			if "AccountName" not in account_obj or not isinstance(account_obj.get("AccountName"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have an 'AccountName' field (str)."
				)
			if not account_obj["AccountName"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'AccountName' cannot be empty."
				)

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (MacBasedAccounts wrapper)
		#   - HTTP POST with JSON body
		#   - Input validation (accounts list, AccountName field)
		#   - HTTP status code mapping
		#   - Response parsing
		result = client.create_mac_based_accounts(
			accounts=accounts,
		)

		# Return the response envelope directly.  The API returns both successfully
		# created accounts and any that failed (UnupsertedAccounts), so return the
		# full response so the caller can inspect both lists.
		return result

	@mcp.tool()
	def create_portnox_mac_based_accounts(
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Alias of create_mac_based_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return create_mac_based_accounts(
			accounts=accounts,
		)

	@mcp.tool()
	def list_mac_based_accounts(
		page_number: int = 1,
		page_size: int = 50,
	) -> Dict[str, Any]:
		"""Retrieve a paginated list of all MAB (MAC-based Authentication) accounts.

		Retrieve all MAB accounts configured in the Portnox deployment. The API
		uses pagination with 1-indexed page numbers and fixed page size of 50
		accounts per page.  Each account includes comprehensive configuration:
		MAC whitelist entries (with expiration dates), vendor whitelist (approved
		MAC vendors), RADIUS options (Voice VLAN), and admin block status.

		This tool is useful for:
		  - Compliance audits: Review all MAB accounts to verify proper config,
		    no expired MACs, and authorized device lists.
		  - Capacity planning: Count total MAB accounts, average whitelist sizes,
		    and identify over-subscribed accounts that may need consolidation.
		  - Bulk operations: Retrieve all accounts, filter by criteria (e.g., all
		    accounts with Voice VLAN, all with vendor restrictions), then perform
		    batch updates to multiple accounts.
		  - Monitoring and troubleshooting: Export account configurations to diagnose
		    missing or misconfigured MAB settings (e.g., accounts with no whitelists).
		  - Device inventory: Correlate all whitelisted MACs with known inventory to
		    identify unauthorized or stale MAC entries that should be removed.
		  - Migration and backup: Export complete account list before system upgrade
		    or migration to new identity management platform.

		Pagination behavior:
		  - Page numbers are 1-indexed (first page = 1, not 0).
		  - Page size is fixed at 50 accounts per page on the Portnox API.
		  - Iterate through pages by incrementing page_number until you receive
		    fewer than 50 accounts (indicating the last page) or empty list.

		The response includes a "MabAccounts" array where each account contains:
		  - Account metadata (ID, name, description, group, creation timestamp)
		  - Agentless options (MAC whitelist, vendor whitelist, secure MAB settings)
		  - RADIUS options (Voice VLAN configuration for VoIP phones)
		  - Admin block status (if account is disabled and the reason)

		Args:
			page_number: 1-based page index (first page = 1). Must be >= 1.
			            Default is 1 (fetch first page).
			page_size:   Fixed page size for this endpoint. The Portnox API
			            currently enforces 50 accounts per page; this parameter
			            is provided for clarity and potential future expansion.

		Returns:
			A dict with key:
			  - "MabAccounts": List of MAB account objects on this page. If this
			    is the last page, the list may contain fewer than 50 accounts
			    (or be empty if page_number exceeds total pages).

		Raises:
			PortnoxApiError: if page_number < 1, or on any HTTP error
			               (400/401/403/500).
		"""
		if page_number < 1:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'page_number' must be >= 1."
			)

		# Delegate to the client method, which handles:
		#   - URL construction with page number path parameter
		#   - HTTP GET request
		#   - Input validation (page_number >= 1)
		#   - HTTP status code mapping (200, 400, 401, 403, 500)
		#   - Response parsing and shape validation
		result = client.list_mac_based_accounts(
			page_number=page_number,
			page_size=page_size,
		)

		# Return the response directly.  The API returns a MabAccounts array,
		# which is the core data the caller wants, so we return the full dict
		# so the caller can inspect the MabAccounts list and any other metadata.
		return result

	@mcp.tool()
	def list_portnox_mac_based_accounts(
		page_number: int = 1,
		page_size: int = 50,
	) -> Dict[str, Any]:
		"""Alias of list_mac_based_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return list_mac_based_accounts(
			page_number=page_number,
			page_size=page_size,
		)

	@mcp.tool()
	def create_ldap_accounts(
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Create one or more new LDAP (Active Directory) accounts in Portnox.

		LDAP accounts represent users and computers managed by an Active Directory
		(AD) domain or LDAP directory service, enabling Portnox network access
		control and device management for corporate users and managed machines.

		This tool is useful for:
		  - New user onboarding: create LDAP accounts for new hires so they can
		    authenticate and enroll managed/unmanaged devices immediately.
		  - Bulk AD integration: after directory restructuring (domain migration,
		    OU consolidation), bulk-create new accounts for affected users/machines.
		  - Temporary staff provisioning: create LDAP accounts for contractors or
		    lab users with a CredentialsExpirationDate to auto-expire access.
		  - Device management: create accounts for managed computers or service
		    accounts that need agentless network access or certificate enrollment.
		  - Pilot deployments: create accounts for a pilot user group to test
		    Portnox policies before full organization rollout.

		Each account in the request specifies:
		  - AccountName: Required unique identifier from AD (user email, sAMAccountName,
		    computer name, UPN, etc.).
		  - DirectoryDomain: Required LDAP directory domain (e.g., "company.com",
		    "DC=company,DC=com", or configured directory ID).
		  - Description: Optional human-readable description.
		  - AllowAgentlessDevices: Optional boolean to enable MAB (MAC-based auth)
		    for unmanaged devices using MAC whitelisting.
		  - CredentialsExpirationDate: Optional ISO 8601 timestamp for account
		    expiration (useful for contractors, guests, temporary staff).

		The response includes both created accounts and those that failed:
		  - "Accounts": Successfully created accounts (each with generated AccountId,
		    certificate info, AgentlessOptions if enabled).
		  - "UnupsertedAccounts": Accounts that failed to create (e.g., duplicate
		    AccountName in domain, user not found in AD, directory misconfiguration).
		  - "IsSuccess": Overall operation success indicator.

		Args:
			accounts: Non-empty list of LDAP account definition objects.  Each should have:
			         - "AccountName" (required, str): AD user or computer identifier
			           (e.g., "john.doe@company.com", "computer-name", UPN, etc.).
			         - "DirectoryDomain" (required, str): LDAP directory domain
			           (e.g., "company.com" or configured directory service ID).
			         - "Description" (optional, str): Account description.
			         - "AllowAgentlessDevices" (optional, bool): Enable MAB.
			         - "CredentialsExpirationDate" (optional, str): ISO 8601 timestamp
			           for account expiration (e.g., "2026-12-31T23:59:59Z").
			         Example: [
			           {
			             "AccountName": "john.doe@company.com",
			             "DirectoryDomain": "company.com",
			             "Description": "Marketing department user",
			             "AllowAgentlessDevices": true,
			             "CredentialsExpirationDate": "2026-12-31T23:59:59Z"
			           }
			         ]

		Returns:
			A dict with:
			  - "Accounts": List of successfully created Account objects (each with
			    generated AccountId, certificate info, and configuration).
			  - "UnupsertedAccounts": List of accounts that failed to create.
			  - "IsSuccess": Boolean indicating overall success.

		Raises:
			PortnoxApiError: if accounts list is empty or malformed, or on any
			               HTTP error (400/401/403/500).
		"""
		if not isinstance(accounts, list) or len(accounts) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'accounts' must be a non-empty list."
			)

		# Validate that each account has required AccountName and DirectoryDomain fields.
		# This catches obvious mistakes before delegating to the API.
		for idx, account_obj in enumerate(accounts):
			if not isinstance(account_obj, dict):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must be a dict, got {type(account_obj).__name__}"
				)
			if "AccountName" not in account_obj or not isinstance(account_obj.get("AccountName"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have an 'AccountName' field (str)."
				)
			if not account_obj["AccountName"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'AccountName' cannot be empty."
				)
			if "DirectoryDomain" not in account_obj or not isinstance(account_obj.get("DirectoryDomain"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have a 'DirectoryDomain' field (str)."
				)
			if not account_obj["DirectoryDomain"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'DirectoryDomain' cannot be empty."
				)

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (LdapAccounts wrapper)
		#   - HTTP POST with JSON body
		#   - Input validation (accounts list, required fields)
		#   - HTTP status code mapping
		#   - Response parsing
		result = client.create_ldap_accounts(
			accounts=accounts,
		)

		# Return the response envelope directly.  The API returns both successfully
		# created accounts and any that failed (UnupsertedAccounts), so return the
		# full response so the caller can inspect both lists.
		return result

	@mcp.tool()
	def create_portnox_ldap_accounts(
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Alias of create_ldap_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return create_ldap_accounts(
			accounts=accounts,
		)

	@mcp.tool()
	def create_contractor_accounts(
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Create one or more new contractor accounts in Portnox.

		Contractor accounts are a lightweight account type designed for temporary
		external workers (contractors, consultants, vendors) who need limited-time
		network access managed entirely by Portnox rather than a directory service.

		This tool is useful for:
		  - Short-term consultants: create an account with CredentialsExpirationDate
		    set to the contract end date so access auto-expires with no manual cleanup.
		  - Vendor technicians: create accounts for on-site vendor engineers,
		    optionally enabling AllowAgentlessDevices if they bring unmanaged equipment.
		  - Project staff: batch-create accounts for all members of a fixed-term
		    project in a single call, all sharing the same expiration date.
		  - Auditors: create a short-lived account that covers only the audit window.
		  - Seasonal workers: batch-create accounts with a shared seasonal expiry date.

		Each account in the request specifies:
		  - AccountName: Required unique identifier (e.g., email, username, badge ID).
		  - Description: Optional description of the contractor or engagement.
		  - CredentialsExpirationDate: Optional ISO 8601 timestamp; when set, access
		    is automatically revoked at expiry with no further action needed.
		  - AllowAgentlessDevices: Optional boolean to enable MAC-based (MAB) auth for
		    the contractor's unmanaged devices via MAC whitelisting.

		The response includes both created accounts and any that failed:
		  - "Accounts": Successfully created accounts (each with generated AccountId).
		  - "UnupsertedAccounts": Accounts that failed to create (e.g., duplicate
		    AccountName). Inspect this to diagnose partial failures in batch calls.
		  - "IsSuccess": Overall operation success indicator.

		Args:
			accounts: Non-empty list of contractor account definition objects.  Each should have:
			         - "AccountName" (required, str): Unique contractor identifier
			           (e.g., "jane.smith@vendorcorp.com" or "contractor-badge-42").
			         - "Description" (optional, str): Account description.
			         - "CredentialsExpirationDate" (optional, str): ISO 8601 expiry datetime
			           (e.g., "2026-09-30T23:59:59Z").
			         - "AllowAgentlessDevices" (optional, bool): Enable MAB for unmanaged devices.
			         Example: [
			           {
			             "AccountName": "jane.smith@vendorcorp.com",
			             "Description": "Network audit consultant",
			             "CredentialsExpirationDate": "2026-09-30T23:59:59Z",
			             "AllowAgentlessDevices": false
			           }
			         ]

		Returns:
			A dict with:
			  - "Accounts": List of successfully created Account objects (each with
			    generated AccountId and full configuration).
			  - "UnupsertedAccounts": List of accounts that failed to create.
			  - "IsSuccess": Boolean indicating overall success.

		Raises:
			PortnoxApiError: if accounts list is empty or malformed, or on any
			               HTTP error (400/401/403/500).
		"""
		if not isinstance(accounts, list) or len(accounts) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'accounts' must be a non-empty list."
			)

		# Validate that each account has at least an AccountName field before
		# delegating to the API, providing clear diagnostics on malformed input.
		for idx, account_obj in enumerate(accounts):
			if not isinstance(account_obj, dict):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must be a dict, got {type(account_obj).__name__}"
				)
			if "AccountName" not in account_obj or not isinstance(account_obj.get("AccountName"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have an 'AccountName' field (str)."
				)
			if not account_obj["AccountName"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'AccountName' cannot be empty."
				)

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (ContractorAccounts wrapper)
		#   - HTTP POST with JSON body
		#   - HTTP status code mapping
		#   - Response parsing
		result = client.create_contractor_accounts(
			accounts=accounts,
		)

		# Return the full response so the caller can inspect both Accounts
		# (created) and UnupsertedAccounts (failed) in a single result.
		return result

	@mcp.tool()
	def create_portnox_contractor_accounts(
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Alias of create_contractor_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return create_contractor_accounts(
			accounts=accounts,
		)

	@mcp.tool()
	def create_cloud_accounts(
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Create one or more new Portnox Cloud (CLEAR) accounts.

		Cloud accounts are Portnox-managed accounts hosted in the cloud platform,
		independent of directory services (AD/LDAP) or MAC-based authentication.
		They support flexible credential management and are ideal for cloud-based
		teams, distributed workforces, and provisioning workflows.

		This tool is useful for:
		  - Cloud-first organizations: manage user accounts for teams without
		    on-premises Active Directory.
		  - MSP/SaaS: create multi-tenant accounts for managed service customers
		    without directory integration overhead.
		  - Hybrid identities: provision cloud accounts for users not in corporate
		    directory or for cloud-only services.
		  - Identity provisioning: batch-create accounts from cloud identity
		    platforms (Okta, Azure AD, Google Workspace).
		  - Automated onboarding: call from HR/HRIS systems to create accounts
		    with auto-expiry for temporary or contract workers.

		Each account in the request specifies:
		  - AccountName: Required unique identifier (email, username, employee ID).
		  - Description: Optional description or user role.
		  - CredentialsExpirationDate: Optional ISO 8601 timestamp for auto-expiry.
		  - AllowAgentlessDevices: Optional boolean to enable MAB for unmanaged devices.

		The response includes both created accounts and those that failed:
		  - "Accounts": Successfully created accounts (each with generated AccountId).
		  - "UnupsertedAccounts": Accounts that failed to create (e.g., duplicate
		    AccountName). Inspect this to diagnose partial failures in batch calls.
		  - "IsSuccess": Overall operation success indicator.

		Args:
			accounts: Non-empty list of cloud account definition objects.  Each should have:
			         - "AccountName" (required, str): Unique cloud account identifier
			           (e.g., "user@mycompany.com" or "emp-12345").
			         - "Description" (optional, str): Account description.
			         - "CredentialsExpirationDate" (optional, str): ISO 8601 expiry datetime
			           (e.g., "2027-12-31T23:59:59Z").
			         - "AllowAgentlessDevices" (optional, bool): Enable MAB for unmanaged devices.
			         Example: [
			           {
			             "AccountName": "alice@mycompany.com",
			             "Description": "Cloud operations engineer",
			             "CredentialsExpirationDate": null,
			             "AllowAgentlessDevices": true
			           }
			         ]

		Returns:
			A dict with:
			  - "Accounts": List of successfully created Account objects (each with
			    generated AccountId and full configuration).
			  - "UnupsertedAccounts": List of accounts that failed to create.
			  - "IsSuccess": Boolean indicating overall success.

		Raises:
			PortnoxApiError: if accounts list is empty or malformed, or on any
			               HTTP error (400/401/403/500).
		"""
		if not isinstance(accounts, list) or len(accounts) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'accounts' must be a non-empty list."
			)

		# Validate that each account has at least an AccountName field before
		# delegating to the API, providing clear diagnostics on malformed input.
		for idx, account_obj in enumerate(accounts):
			if not isinstance(account_obj, dict):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must be a dict, got {type(account_obj).__name__}"
				)
			if "AccountName" not in account_obj or not isinstance(account_obj.get("AccountName"), str):
				raise PortnoxApiError(
					f"Invalid account at index {idx}: must have an 'AccountName' field (str)."
				)
			if not account_obj["AccountName"].strip():
				raise PortnoxApiError(
					f"Invalid account at index {idx}: 'AccountName' cannot be empty."
				)

		# Delegate to the client method, which handles:
		#   - URL construction
		#   - Payload assembly (ClearAccounts wrapper)
		#   - HTTP POST with JSON body
		#   - HTTP status code mapping
		#   - Response parsing
		result = client.create_cloud_accounts(
			accounts=accounts,
		)

		# Return the full response so the caller can inspect both Accounts
		# (created) and UnupsertedAccounts (failed) in a single result.
		return result

	@mcp.tool()
	def create_portnox_cloud_accounts(
		accounts: List[Dict[str, Any]],
	) -> Dict[str, Any]:
		"""Alias of create_cloud_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return create_cloud_accounts(
			accounts=accounts,
		)

	@mcp.tool()
	def bulk_create_mac_based_accounts(
		accounts: List[Dict[str, Any]],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Create multiple MAB accounts and return normalized batch summary data.

		This wrapper reuses the existing batch-capable MAB create endpoint, then
		normalizes the Portnox response into consistent count fields so it matches
		the lifecycle-oriented bulk tools added elsewhere in this server.

		Args:
			accounts: Non-empty list of MAB account definitions.
			strict_mode: If True, raise when Portnox reports any uncreated accounts.

		Returns:
			Normalized batch summary with created_count, failed_count, and raw results.
		"""
		result = create_mac_based_accounts(accounts=accounts)
		return _summarize_bulk_create_result(
			requested_count=len(accounts),
			result=result,
			strict_mode=strict_mode,
			account_type="mac_based_accounts",
		)

	@mcp.tool()
	def bulk_create_portnox_mac_based_accounts(
		accounts: List[Dict[str, Any]],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Alias of bulk_create_mac_based_accounts with explicit Portnox naming."""
		return bulk_create_mac_based_accounts(
			accounts=accounts,
			strict_mode=strict_mode,
		)

	@mcp.tool()
	def bulk_create_ldap_accounts(
		accounts: List[Dict[str, Any]],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Create multiple LDAP accounts and return normalized batch summary data.

		This wrapper preserves the existing LDAP creation validation and API
		behavior while exposing consistent count fields and optional strict-mode
		failure semantics.

		Args:
			accounts: Non-empty list of LDAP account definitions.
			strict_mode: If True, raise when Portnox reports any uncreated accounts.

		Returns:
			Normalized batch summary with created_count, failed_count, and raw results.
		"""
		result = create_ldap_accounts(accounts=accounts)
		return _summarize_bulk_create_result(
			requested_count=len(accounts),
			result=result,
			strict_mode=strict_mode,
			account_type="ldap_accounts",
		)

	@mcp.tool()
	def bulk_create_portnox_ldap_accounts(
		accounts: List[Dict[str, Any]],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Alias of bulk_create_ldap_accounts with explicit Portnox naming."""
		return bulk_create_ldap_accounts(
			accounts=accounts,
			strict_mode=strict_mode,
		)

	@mcp.tool()
	def bulk_create_contractor_accounts(
		accounts: List[Dict[str, Any]],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Create multiple contractor accounts and return normalized batch summary data.

		This wrapper keeps the existing contractor creation semantics intact while
		adding normalized counters and optional strict-mode escalation.

		Args:
			accounts: Non-empty list of contractor account definitions.
			strict_mode: If True, raise when Portnox reports any uncreated accounts.

		Returns:
			Normalized batch summary with created_count, failed_count, and raw results.
		"""
		result = create_contractor_accounts(accounts=accounts)
		return _summarize_bulk_create_result(
			requested_count=len(accounts),
			result=result,
			strict_mode=strict_mode,
			account_type="contractor_accounts",
		)

	@mcp.tool()
	def bulk_create_portnox_contractor_accounts(
		accounts: List[Dict[str, Any]],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Alias of bulk_create_contractor_accounts with explicit Portnox naming."""
		return bulk_create_contractor_accounts(
			accounts=accounts,
			strict_mode=strict_mode,
		)

	@mcp.tool()
	def bulk_create_cloud_accounts(
		accounts: List[Dict[str, Any]],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Create multiple cloud accounts and return normalized batch summary data.

		This wrapper keeps the existing cloud account batch creation behavior and
		adds consistent counters plus strict-mode error escalation.

		Args:
			accounts: Non-empty list of cloud account definitions.
			strict_mode: If True, raise when Portnox reports any uncreated accounts.

		Returns:
			Normalized batch summary with created_count, failed_count, and raw results.
		"""
		result = create_cloud_accounts(accounts=accounts)
		return _summarize_bulk_create_result(
			requested_count=len(accounts),
			result=result,
			strict_mode=strict_mode,
			account_type="cloud_accounts",
		)

	@mcp.tool()
	def bulk_create_portnox_cloud_accounts(
		accounts: List[Dict[str, Any]],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Alias of bulk_create_cloud_accounts with explicit Portnox naming."""
		return bulk_create_cloud_accounts(
			accounts=accounts,
			strict_mode=strict_mode,
		)

	@mcp.tool()
	def move_account_to_group(group_name: str, account_id: str) -> Dict[str, Any]:
		"""Move a non-LDAP account to a different Portnox group.

		Use this operation to reassign Portnox Cloud or Contractor accounts from
		one policy group to another.  This is particularly useful when a user's
		access scope changes (onboarding -> production, support -> restricted, etc.).

		Important operational note:
		  - LDAP accounts are assigned via LDAP mapping and are not intended to be
		    manually moved using this endpoint.
		  - Moving an account triggers risk-score recalculation for all associated
		    devices according to the destination group's policy.

		Args:
			group_name: Destination Portnox group name.
			account_id: Account identifier to move.

		Returns:
			A dict with:
			  - "status": "updated"
			  - "account_id": Identifier that was moved.
			  - "group_name": Destination group applied.
			  - "message": Human-readable action summary.

		Raises:
			PortnoxApiError: if parameters are missing/malformed, or on any HTTP
			               error (400/401/403/500).
		"""
		# Validate required fields before API call to provide deterministic errors.
		if not isinstance(group_name, str) or not group_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'group_name' must be a non-empty string."
			)
		if not isinstance(account_id, str) or not account_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_id' must be a non-empty string."
			)

		# Delegate to the client method, which handles endpoint URL construction,
		# payload serialization, HTTP call execution, and status code mapping.
		client.move_account_to_group(
			group_name=group_name,
			account_id=account_id,
		)

		# Return a consistent MCP response envelope because the API itself returns
		# HTTP 200 with no body on success.
		return {
			"status": "updated",
			"account_id": account_id.strip(),
			"group_name": group_name.strip(),
			"message": f"Account moved to group '{group_name.strip()}'",
		}

	@mcp.tool()
	def move_portnox_account_to_group(group_name: str, account_id: str) -> Dict[str, Any]:
		"""Alias of move_account_to_group with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return move_account_to_group(
			group_name=group_name,
			account_id=account_id,
		)

	@mcp.tool()
	def block_account(entity_id: str, reason: str) -> Dict[str, Any]:
		"""Block a Portnox account so it can no longer access the network.

		Use this for immediate account-level containment, administrative suspension,
		or policy enforcement.  The reason is saved in Portnox for auditability.

		Args:
			entity_id: Account identifier to block.
			reason: Human-readable reason for the block action.

		Returns:
			A dict with:
			  - "status": "updated"
			  - "entity_id": The blocked account identifier.
			  - "message": Human-readable success summary.

		Raises:
			PortnoxApiError: if parameters are missing/malformed, or on any HTTP
			               error (400/401/403/500).
		"""
		# Validate inputs locally to avoid a round-trip for obviously invalid calls.
		if not isinstance(entity_id, str) or not entity_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'entity_id' must be a non-empty string."
			)
		if not isinstance(reason, str) or not reason.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'reason' must be a non-empty string."
			)

		# Delegate to the client method so request construction and status mapping
		# stay centralized in one place.
		client.block_account(entity_id=entity_id, reason=reason)

		# The API returns HTTP 200 with no body, so we synthesize a small response
		# envelope that callers can use for confirmation and logging.
		return {
			"status": "updated",
			"entity_id": entity_id.strip(),
			"message": f"Account '{entity_id.strip()}' was blocked",
		}

	@mcp.tool()
	def block_portnox_account(entity_id: str, reason: str) -> Dict[str, Any]:
		"""Alias of block_account with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return block_account(entity_id=entity_id, reason=reason)

	@mcp.tool()
	def block_multiple_accounts(
		account_ids: List[str],
		reason: str,
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Block multiple Portnox accounts in one batch.

		This is the bulk counterpart to block_account().  It is useful when a
		set of accounts must be suspended together for incident response,
		policy enforcement, or administrative containment.

		Why this tool exists:
		  - Operational efficiency: one MCP call can block many accounts instead of
		    forcing the caller to loop externally.
		  - Consistent audit output: per-account results show exactly which accounts
		    were blocked successfully and which failed.
		  - Controlled failure handling: strict_mode allows all-or-stop workflows
		    when partial success is not acceptable.

		Behavior notes:
		  - The reason is applied to every account in the batch so audit history is
		    consistent across all blocked entries.
		  - strict_mode determines whether processing continues after a failure.
		      - False (default): continue processing remaining accounts.
		      - True: stop on first failure and raise PortnoxApiError.

		Args:
			account_ids: Non-empty list of account identifiers to block.
			reason: Human-readable explanation saved with each block action.
			strict_mode: Whether to stop immediately on first failure.

		Returns:
			A dict with:
			  - "status": "completed"
			  - "requested_count": number of submitted account IDs
			  - "blocked_count": number of successful blocks
			  - "failed_count": number of failed blocks
			  - "results": ordered per-account outcomes with account_id, status,
			    and message

		Raises:
			PortnoxApiError: if parameters are malformed before processing, or when
			               strict_mode=True and any block fails.
		"""
		# Validate the batch inputs up front so malformed calls fail fast with a
		# clear error rather than partway through the operation.
		if not isinstance(account_ids, list) or len(account_ids) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_ids' must be a non-empty list."
			)
		if not isinstance(reason, str) or not reason.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'reason' must be a non-empty string."
			)
		if not isinstance(strict_mode, bool):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'strict_mode' must be a boolean."
			)

		# Validate every account ID before mutating anything so we keep the batch
		# deterministic and avoid partial work caused by bad input.
		for idx, account_id in enumerate(account_ids):
			if not isinstance(account_id, str) or not account_id.strip():
				raise PortnoxApiError(
					f"Invalid account ID at index {idx}: must be a non-empty string."
				)

		results: List[Dict[str, Any]] = []
		blocked_count = 0
		failed_count = 0

		# Process sequentially so the response order mirrors the input order and
		# the caller can correlate each result to its requested account.
		for account_id in account_ids:
			try:
				client.block_account(entity_id=account_id, reason=reason)
				blocked_count += 1
				results.append(
					{
						"account_id": account_id.strip(),
						"status": "updated",
						"message": f"Account '{account_id.strip()}' was blocked",
					}
				)
			except PortnoxApiError as exc:
				# In non-strict mode we keep going so one failure does not stop the
				# rest of the batch from being contained.
				failed_count += 1
				results.append(
					{
						"account_id": account_id.strip(),
						"status": "failed",
						"message": str(exc),
					}
				)

				# In strict mode, abort immediately so callers can enforce a hard
				# all-or-stop containment workflow.
				if strict_mode:
					raise PortnoxApiError(
						f"Failed to block account '{account_id.strip()}': {exc}"
					) from exc

		return {
			"status": "completed",
			"requested_count": len(account_ids),
			"blocked_count": blocked_count,
			"failed_count": failed_count,
			"results": results,
		}

	@mcp.tool()
	def block_portnox_multiple_accounts(
		account_ids: List[str],
		reason: str,
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Alias of block_multiple_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return block_multiple_accounts(
			account_ids=account_ids,
			reason=reason,
			strict_mode=strict_mode,
		)

	@mcp.tool()
	def unblock_account(entity_id: str) -> Dict[str, Any]:
		"""Restore network access for a previously blocked Portnox account.

		Use this when an account has been cleared for use after remediation,
		approval, or investigation.  This is the account-level counterpart to
		`block_account()` and is intentionally separate from device unblock flows.

		Args:
			entity_id: Account identifier to unblock.

		Returns:
			A dict with:
			  - "status": "updated"
			  - "entity_id": The unblocked account identifier.
			  - "message": Human-readable success summary.

		Raises:
			PortnoxApiError: if entity_id is missing/malformed, or on any HTTP
			               error (400/401/403/500).
		"""
		# Validate locally so invalid calls fail before any network request.
		if not isinstance(entity_id, str) or not entity_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'entity_id' must be a non-empty string."
			)

		# Delegate to the client method so request building and status mapping stay
		# centralized in one place.
		client.unblock_account(entity_id=entity_id)

		# The API returns HTTP 200 with no body, so we synthesize a compact success
		# response for callers and audit logs.
		return {
			"status": "updated",
			"entity_id": entity_id.strip(),
			"message": f"Account '{entity_id.strip()}' was unblocked",
		}

	@mcp.tool()
	def unblock_portnox_account(entity_id: str) -> Dict[str, Any]:
		"""Alias of unblock_account with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return unblock_account(entity_id=entity_id)

	@mcp.tool()
	def delete_account(account_id: str) -> Dict[str, Any]:
		"""Permanently delete a Portnox account.

		Use this when an account should be removed from Portnox entirely rather
		than merely blocked.  This is appropriate for final cleanup of temporary
		cloud or contractor accounts, duplicate-account removal, and test-data
		cleanup workflows.

		Args:
			account_id: Account identifier to delete.

		Returns:
			A dict with:
			  - "status": "deleted"
			  - "account_id": The deleted account identifier.
			  - "message": Human-readable success summary.

		Raises:
			PortnoxApiError: if account_id is missing/malformed, or on any HTTP
			               error (400/401/403/500).
		"""
		# Validate locally so invalid calls fail before any network request.
		if not isinstance(account_id, str) or not account_id.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_id' must be a non-empty string."
			)

		# Delegate to the client method so request construction and status mapping
		# stay centralized in one place.
		client.delete_account(account_id=account_id)

		# The API returns HTTP 200 with no body, so we synthesize a compact success
		# envelope for confirmation and logging.
		return {
			"status": "deleted",
			"account_id": account_id.strip(),
			"message": f"Account '{account_id.strip()}' was deleted",
		}

	@mcp.tool()
	def delete_portnox_account(account_id: str) -> Dict[str, Any]:
		"""Alias of delete_account with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return delete_account(account_id=account_id)

	@mcp.tool()
	def delete_multiple_accounts(
		account_ids: List[str],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Permanently delete multiple Portnox accounts in one batch.

		This is the bulk counterpart to delete_account().  It is intended for
		cleanup and lifecycle-termination workflows where many accounts should be
		removed from Portnox entirely rather than merely blocked.

		Why this tool exists:
		  - Operational efficiency: callers can remove many accounts in one MCP
		    call instead of driving an external loop.
		  - Clear audit output: the response includes per-account success/failure
		    records so operators can retry only the failures.
		  - Controlled failure handling: strict_mode supports hard stop behavior
		    when partial completion is not acceptable.

		Behavior notes:
		  - This operation is stronger than blocking because it removes the account
		    instead of preserving it in a suspended state.
		  - strict_mode determines whether processing continues after a failure.
		      - False (default): continue processing remaining accounts.
		      - True: stop on first failure and raise PortnoxApiError.

		Args:
			account_ids: Non-empty list of account identifiers to delete.
			strict_mode: Whether to stop immediately on first failure.

		Returns:
			A dict with:
			  - "status": "completed"
			  - "requested_count": number of submitted account IDs
			  - "deleted_count": number of successful deletions
			  - "failed_count": number of failed deletions
			  - "results": ordered per-account outcomes with account_id, status,
			    and message

		Raises:
			PortnoxApiError: if parameters are malformed before processing, or when
			               strict_mode=True and any delete fails.
		"""
		# Validate the batch inputs up front so malformed requests fail before
		# any destructive action is attempted.
		if not isinstance(account_ids, list) or len(account_ids) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_ids' must be a non-empty list."
			)
		if not isinstance(strict_mode, bool):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'strict_mode' must be a boolean."
			)

		# Validate every account ID before any delete request is sent so the batch
		# starts with a clean, deterministic set of inputs.
		for idx, account_id in enumerate(account_ids):
			if not isinstance(account_id, str) or not account_id.strip():
				raise PortnoxApiError(
					f"Invalid account ID at index {idx}: must be a non-empty string."
				)

		results: List[Dict[str, Any]] = []
		deleted_count = 0
		failed_count = 0

		# Process sequentially so the response order mirrors the input order and
		# operators can match each result directly to the original request item.
		for account_id in account_ids:
			try:
				client.delete_account(account_id=account_id)
				deleted_count += 1
				results.append(
					{
						"account_id": account_id.strip(),
						"status": "deleted",
						"message": f"Account '{account_id.strip()}' was deleted",
					}
				)
			except PortnoxApiError as exc:
				# In non-strict mode we continue so one failed delete does not stop
				# the rest of the lifecycle cleanup batch.
				failed_count += 1
				results.append(
					{
						"account_id": account_id.strip(),
						"status": "failed",
						"message": str(exc),
					}
				)

				# In strict mode, abort immediately so callers can enforce an
				# all-or-stop deletion workflow.
				if strict_mode:
					raise PortnoxApiError(
						f"Failed to delete account '{account_id.strip()}': {exc}"
					) from exc

		return {
			"status": "completed",
			"requested_count": len(account_ids),
			"deleted_count": deleted_count,
			"failed_count": failed_count,
			"results": results,
		}

	@mcp.tool()
	def delete_portnox_multiple_accounts(
		account_ids: List[str],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Alias of delete_multiple_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return delete_multiple_accounts(
			account_ids=account_ids,
			strict_mode=strict_mode,
		)

	@mcp.tool()
	def unblock_multiple_accounts(
		account_ids: List[str],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Restore access for multiple previously blocked Portnox accounts.

		This is the bulk counterpart to unblock_account().  It is intended for
		cases where a set of accounts has already been reviewed and cleared for
		reinstatement, and the operator wants one call to process them all.

		Why this tool exists:
		  - Operational efficiency: the caller can unblock many accounts in a
		    single MCP call instead of looping externally.
		  - Clear audit output: the tool returns per-account success/failure records
		    so operators can see exactly which accounts were restored.
		  - Controlled failure handling: strict_mode allows all-or-stop workflows
		    when partial completion is not acceptable.

		Behavior notes:
		  - This operation only clears the account-level blocked state; it does not
		    delete or recreate accounts.
		  - strict_mode determines whether processing continues after a failure.
		      - False (default): continue processing remaining accounts.
		      - True: stop on first failure and raise PortnoxApiError.

		Args:
			account_ids: Non-empty list of account identifiers to unblock.
			strict_mode: Whether to stop immediately on first failure.

		Returns:
			A dict with:
			  - "status": "completed"
			  - "requested_count": number of submitted account IDs
			  - "unblocked_count": number of successful unblocks
			  - "failed_count": number of failed unblocks
			  - "results": ordered per-account outcomes with account_id, status,
			    and message

		Raises:
			PortnoxApiError: if parameters are malformed before processing, or when
			               strict_mode=True and any account unblock fails.
		"""
		# Validate the account list before starting any mutations so malformed input
		# is rejected with a clear, deterministic error.
		if not isinstance(account_ids, list) or len(account_ids) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_ids' must be a non-empty list."
			)

		# Validate strict_mode explicitly so callers do not rely on truthiness.
		if not isinstance(strict_mode, bool):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'strict_mode' must be a boolean."
			)

		# Validate every account ID up front so the batch starts with a clean and
		# predictable request set.
		for idx, account_id in enumerate(account_ids):
			if not isinstance(account_id, str) or not account_id.strip():
				raise PortnoxApiError(
					f"Invalid account ID at index {idx}: must be a non-empty string."
				)

		results: List[Dict[str, Any]] = []
		unblocked_count = 0
		failed_count = 0

		# Process sequentially so the output order matches the input order and the
		# operator can line up each result with the corresponding account ID.
		for account_id in account_ids:
			try:
				client.unblock_account(entity_id=account_id)
				unblocked_count += 1
				results.append(
					{
						"account_id": account_id.strip(),
						"status": "updated",
						"message": f"Account '{account_id.strip()}' was unblocked",
					}
				)
			except PortnoxApiError as exc:
				# In non-strict mode we keep going so one failed account does not
				# prevent the rest from being restored.
				failed_count += 1
				results.append(
					{
						"account_id": account_id.strip(),
						"status": "failed",
						"message": str(exc),
					}
				)

				# In strict mode, abort immediately so callers can enforce a hard
				# all-or-stop workflow.
				if strict_mode:
					raise PortnoxApiError(
						f"Failed to unblock account '{account_id.strip()}': {exc}"
					) from exc

		return {
			"status": "completed",
			"requested_count": len(account_ids),
			"unblocked_count": unblocked_count,
			"failed_count": failed_count,
			"results": results,
		}

	@mcp.tool()
	def unblock_portnox_multiple_accounts(
		account_ids: List[str],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Alias of unblock_multiple_accounts with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return unblock_multiple_accounts(
			account_ids=account_ids,
			strict_mode=strict_mode,
		)

	@mcp.tool()
	def move_multiple_accounts_to_group(
		group_name: str,
		account_ids: List[str],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Move multiple non-LDAP accounts to the same Portnox group.

		This is a bulk convenience wrapper around move_account_to_group().  It is
		useful when onboarding, remediating, or reorganizing many Portnox Cloud or
		Contractor accounts at once.

		Why this tool exists:
		  - Operational efficiency: callers can submit one MCP call instead of
		    orchestrating a loop of many single-account calls.
		  - Deterministic batch reporting: the tool returns per-account success/failure
		    records so operators can retry only failed items.
		  - Safety for large changes: partial failures are captured explicitly rather
		    than being hidden behind a single exception.

		Behavior notes:
		  - This operation is intended for non-LDAP accounts.  LDAP accounts are
		    assigned by LDAP mapping policy and generally should not be moved manually.
		  - Each successful move causes Portnox to recalculate risk score for the
		    moved account's devices based on the destination group's policy.
		  - Processing is sequential by design to produce clear, ordered, per-account
		    diagnostics and avoid concurrent policy-race side effects.
		  - strict_mode controls failure behavior:
		      - False (default): continue processing and return partial-success report.
		      - True: stop on first failed account and raise PortnoxApiError.

		Args:
			group_name: Destination Portnox group name to apply to each account.
			account_ids: Non-empty list of account identifiers to move.
			strict_mode: Whether to stop immediately on first failure.

		Returns:
			A dict with:
			  - "status": "completed"
			  - "group_name": destination group used
			  - "requested_count": number of submitted account IDs
			  - "moved_count": number of successful moves
			  - "failed_count": number of failed moves
			  - "results": ordered per-account outcomes.  Each entry contains:
			      - account_id
			      - status: "updated" or "failed"
			      - message

		Raises:
			PortnoxApiError: if required parameters are malformed before processing,
			               or when strict_mode=True and any account move fails.
		"""
		# Validate destination group once up front so all accounts share the same,
		# known target and we fail fast on malformed requests.
		if not isinstance(group_name, str) or not group_name.strip():
			raise PortnoxApiError(
				"Missing or malformed parameter: 'group_name' must be a non-empty string."
			)

		# Validate that we received a non-empty list of account IDs.
		if not isinstance(account_ids, list) or len(account_ids) == 0:
			raise PortnoxApiError(
				"Missing or malformed parameter: 'account_ids' must be a non-empty list."
			)

		# Validate strict_mode type explicitly so callers get deterministic input
		# errors instead of Python truthiness surprises.
		if not isinstance(strict_mode, bool):
			raise PortnoxApiError(
				"Missing or malformed parameter: 'strict_mode' must be a boolean."
			)

		# Validate every account ID before starting mutations so the batch either
		# starts with a clean parameter set or fails immediately with a clear error.
		for idx, account_id in enumerate(account_ids):
			if not isinstance(account_id, str) or not account_id.strip():
				raise PortnoxApiError(
					f"Invalid account ID at index {idx}: must be a non-empty string."
				)

		results: List[Dict[str, Any]] = []
		moved_count = 0
		failed_count = 0

		# Process sequentially to preserve deterministic ordering and simplify
		# auditability of per-account outcomes.
		for account_id in account_ids:
			try:
				client.move_account_to_group(
					group_name=group_name,
					account_id=account_id,
				)
				moved_count += 1
				results.append(
					{
						"account_id": account_id.strip(),
						"status": "updated",
						"message": f"Account moved to group '{group_name.strip()}'",
					}
				)
			except PortnoxApiError as exc:
				# Capture failures.  In non-strict mode, continue so one bad account
				# does not prevent movement of remaining valid accounts.
				failed_count += 1
				results.append(
					{
						"account_id": account_id.strip(),
						"status": "failed",
						"message": str(exc),
					}
				)

				# In strict mode, abort immediately at first failure so callers can
				# enforce all-or-stop operational workflows.
				if strict_mode:
					raise PortnoxApiError(
						f"Failed to move account '{account_id.strip()}' to group '{group_name.strip()}': {exc}"
					) from exc

		return {
			"status": "completed",
			"group_name": group_name.strip(),
			"requested_count": len(account_ids),
			"moved_count": moved_count,
			"failed_count": failed_count,
			"results": results,
		}

	@mcp.tool()
	def move_portnox_multiple_accounts_to_group(
		group_name: str,
		account_ids: List[str],
		strict_mode: bool = False,
	) -> Dict[str, Any]:
		"""Alias of move_multiple_accounts_to_group with explicit Portnox naming.

		Use this name when multiple MCP servers are loaded and you need to be
		explicit that you are targeting Portnox rather than another platform.
		"""
		return move_multiple_accounts_to_group(
			group_name=group_name,
			account_ids=account_ids,
			strict_mode=strict_mode,
		)

	# Return the fully-configured MCP server instance to the caller (main).
	return mcp


def daemonize(pid_file: Optional[Path], log_file: Optional[Path]) -> None:
	"""Detach the process from the terminal using the standard Unix double-fork.

	The double-fork technique is the canonical way to create a daemon on
	Linux/Unix.  It guarantees that the resulting process:
	  - Has no controlling terminal (cannot be interrupted by Ctrl-C).
	  - Is not a process-group leader, so it cannot accidentally acquire a
	    controlling terminal in the future.
	  - Is adopted by init/systemd when the parent exits.

	After forking, the process:
	  - Redirects stdin to /dev/null (nothing to read from the terminal).
	  - Redirects stdout/stderr to the log file (or /dev/null if unset).
	  - Writes its PID to pid_file so init scripts and systemd can stop it.

	Args:
		pid_file: Path to write the daemon PID; None to skip.
		log_file: Path to redirect stdout/stderr; None to discard output.
	"""
	# --- First fork ---
	# The parent exits immediately.  This returns control to the shell so the
	# user's terminal prompt comes back while the child continues in the background.
	if os.fork() > 0:
		os._exit(0)

	# Create a new session.  The child becomes the session leader of a new
	# session with no controlling terminal.
	os.setsid()

	# --- Second fork ---
	# The session leader could reacquire a controlling terminal by opening a
	# TTY device.  Forking again makes the grandchild a non-session-leader,
	# which can never reacquire a controlling terminal on Systems V-derived Unix.
	if os.fork() > 0:
		os._exit(0)

	# Change to the root directory so the daemon does not prevent unmounting
	# of the filesystem it was launched from.
	os.chdir("/")

	# Set a restrictive umask so files created by the daemon are not world-readable.
	# 0o027 = owner rw, group r, others nothing.
	os.umask(0o027)

	# Flush any buffered output before redirecting the file descriptors.
	sys.stdout.flush()
	sys.stderr.flush()

	# Redirect stdin to /dev/null — the daemon has nothing to read.
	with open("/dev/null", "r", encoding="utf-8") as null_in:
		os.dup2(null_in.fileno(), sys.stdin.fileno())

	# Redirect stdout and stderr to the log file (or /dev/null if none given).
	if log_file:
		# Ensure the log directory exists before opening the file.
		log_file.parent.mkdir(parents=True, exist_ok=True)
		log_handle = open(log_file, "a", encoding="utf-8")
		os.dup2(log_handle.fileno(), sys.stdout.fileno())
		os.dup2(log_handle.fileno(), sys.stderr.fileno())
	else:
		# Discard all output when no log file is specified.
		with open("/dev/null", "a", encoding="utf-8") as null_out:
			os.dup2(null_out.fileno(), sys.stdout.fileno())
			os.dup2(null_out.fileno(), sys.stderr.fileno())

	# Write the daemon's PID to the pid file so external processes (e.g.
	# systemd, init scripts, or the user) can send signals to it later.
	if pid_file:
		pid_file.parent.mkdir(parents=True, exist_ok=True)
		pid_file.write_text(str(os.getpid()), encoding="utf-8")


def remove_pid_file(pid_file: Optional[Path]) -> None:
	"""Delete the PID file if it exists.

	Called on clean shutdown (SIGTERM, SIGINT, or normal exit) so the PID file
	does not linger after the daemon has stopped.  Uses missing_ok=True to
	silently ignore the case where the file was already removed (e.g. by an
	admin) or was never created.

	Args:
		pid_file: Path to the PID file; None is a no-op.
	"""
	if pid_file and pid_file.exists():
		pid_file.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
	"""Parse and return CLI arguments for the MCP server.

	Supports the following arguments (each has a corresponding environment
	variable fallback so the server can be configured without flags):

	  --transport      : MCP transport protocol (stdio / sse / streamable-http).
	  --host           : IP to bind for network transports.
	  --port           : TCP port for network transports.
	  --allowed-hosts  : Comma-separated allowed Host header values.
	  --force-host-header : Rewrite the incoming Host header (default: localhost:8765).
	  --https          : Enable HTTPS/TLS listener.
	  --tls-cert-file  : Path to PEM/CRT certificate file.
	  --tls-key-file   : Path to PEM private key file.
	  --tls-pfx-file   : Path to PKCS#12 bundle (.pfx/.p12).
	  --tls-pfx-password : Password for PKCS#12 bundle.
	  --tls-cert-dir   : Directory for generated/converted TLS files.
	  --tls-self-signed-cn : CN for auto-generated self-signed cert.
	  --daemon         : Detach and run as a background daemon.
	  --pid-file       : Path for the daemon PID file.
	  --log-file       : Path for daemon log output.
	  --log-level      : Python logging threshold.
	  --token-file     : Path to token file (overrides PORTNOX_TOKEN_FILE).
	  --token          : Long-lived token (overrides PORTNOX_TOKEN).
	  --username       : Local admin username (overrides PORTNOX_USERNAME).
	  --password       : Local admin password (overrides PORTNOX_PASSWORD).
	"""
	parser = argparse.ArgumentParser(description="Portnox MCP server")
	parser.add_argument(
		"--transport",
		choices=["stdio", "sse", "streamable-http"],
		default=os.getenv("MCP_TRANSPORT", "stdio"),
		help="MCP transport to use.",
	)
	parser.add_argument(
		"--host",
		default=os.getenv("MCP_HOST", "0.0.0.0"),
		help="Host/IP to bind for network transports.",
	)
	parser.add_argument(
		"--port",
		type=int,
		default=int(os.getenv("MCP_PORT", "8765")),
		help="Port to bind for network transports.",
	)
	parser.add_argument(
		"--allowed-hosts",
		default=os.getenv("MCP_ALLOWED_HOSTS", "*"),
		help="Comma-separated Host headers to allow for network transports (default: *).",
	)
	parser.add_argument(
		"--force-host-header",
		default=os.getenv("MCP_FORCE_HOST_HEADER", "localhost:8765"),
		help="Override incoming Host header before MCP transport checks (default: localhost:8765).",
	)
	parser.add_argument(
		"--https",
		action="store_true",
		default=_as_bool(os.getenv("MCP_ENABLE_HTTPS", "false")),
		help="Enable HTTPS/TLS for network transports.",
	)
	parser.add_argument(
		"--tls-cert-file",
		default=os.getenv("MCP_TLS_CERT_FILE", ""),
		help="Path to PEM/CRT certificate file (requires --tls-key-file).",
	)
	parser.add_argument(
		"--tls-key-file",
		default=os.getenv("MCP_TLS_KEY_FILE", ""),
		help="Path to PEM private key file (requires --tls-cert-file).",
	)
	parser.add_argument(
		"--tls-pfx-file",
		default=os.getenv("MCP_TLS_PFX_FILE", ""),
		help="Path to PKCS#12 bundle file (.pfx/.p12).",
	)
	parser.add_argument(
		"--tls-pfx-password",
		default=os.getenv("MCP_TLS_PFX_PASSWORD", ""),
		help="Password for PKCS#12 bundle (if required).",
	)
	parser.add_argument(
		"--tls-cert-dir",
		default=os.getenv("MCP_TLS_CERT_DIR", "/tmp/portnox-mcp-tls"),
		help="Directory used for generated/converted TLS files.",
	)
	parser.add_argument(
		"--tls-self-signed-cn",
		default=os.getenv("MCP_TLS_SELF_SIGNED_CN", "localhost"),
		help="Common Name used when generating a self-signed cert.",
	)
	parser.add_argument(
		"--daemon",
		action="store_true",
		help="Run as a Linux/Unix daemon (double-fork).",
	)
	parser.add_argument(
		"--pid-file",
		default="/var/run/portnox-mcp-server.pid",
		help="PID file path when running as daemon.",
	)
	parser.add_argument(
		"--log-file",
		default="/var/log/portnox-mcp-server.log",
		help="Log file path when running as daemon.",
	)
	parser.add_argument(
		"--log-level",
		default="INFO",
		help="Python logging level (DEBUG, INFO, WARNING, ERROR).",
	)
	parser.add_argument(
		"--token-file",
		default=None,
		help="Path to long-lived token file (overrides PORTNOX_TOKEN_FILE).",
	)
	parser.add_argument(
		"--token",
		default=None,
		help="Long-lived API token (overrides PORTNOX_TOKEN).",
	)
	parser.add_argument(
		"--username",
		default=None,
		help="Local Portnox Cloud admin username (overrides PORTNOX_USERNAME).",
	)
	parser.add_argument(
		"--password",
		default=None,
		help="Local Portnox Cloud admin password (overrides PORTNOX_PASSWORD).",
	)
	return parser.parse_args()


def _call_with_supported_kwargs(func: Any, preferred_kwargs: Dict[str, Any]) -> None:
	"""Call `func` passing only the keyword arguments it actually accepts.

	Different versions of the FastMCP SDK expose run methods with different
	signatures.  Rather than maintaining a version-specific call per SDK release,
	this helper inspects the function's signature at runtime and filters out any
	kwargs that are not in the parameter list.  This avoids TypeError on unknown
	keyword arguments while still passing the ones that are supported.

	None-valued kwargs are also filtered out so we do not pass `host=None` to a
	function that treats None differently from "not provided".

	Args:
		func:            The callable to invoke.
		preferred_kwargs: All kwargs we *would* pass if the function accepted them.
	"""
	# Inspect the function's parameter names at runtime.
	params = inspect.signature(func).parameters
	accepted_kwargs = {
		k: v for k, v in preferred_kwargs.items() if k in params and v is not None
	}
	func(**accepted_kwargs)


def _discover_asgi_app(server: FastMCP, transport: str) -> Optional[Any]:
	"""Attempt to obtain an ASGI application object from the FastMCP instance.

	FastMCP SDK versions differ in which attribute or method exposes the ASGI
	app for SSE and streamable-HTTP transports.  This function tries the
	transport-specific methods first (most precise), then falls back to generic
	ASGI app accessors.  Returns None if no ASGI app can be found, in which case
	the caller falls back to the SDK's own run() method.

	Why we need this:
	  When running over HTTP we want to hand the ASGI app directly to uvicorn so
	  we control the host/port binding.  Some SDK versions ignore the host/port
	  passed to their run() method, making explicit uvicorn hosting the only
	  reliable way to bind to the correct interface.

	Args:
		server:    The FastMCP instance.
		transport: The transport name ("sse" or "streamable-http").

	Returns:
		An ASGI callable, or None if discovery failed.
	"""
	# Try transport-specific getter methods first; these are the most reliable
	# when the SDK version is known to expose them.
	transport_specific_methods = (
		("streamable-http", "streamable_http_app"),
		("streamable-http", "get_streamable_http_app"),
		("sse", "sse_app"),
		("sse", "get_sse_app"),
	)

	for transport_name, method_name in transport_specific_methods:
		if transport != transport_name:
			continue
		method = getattr(server, method_name, None)
		if callable(method):
			try:
				return method()
			except TypeError:
				# The method exists but its signature changed; try the next one.
				continue

	# Fall back to generic ASGI app accessors that may work for any transport.
	for method_name in ("asgi_app", "get_asgi_app", "app"):
		method_or_attr = getattr(server, method_name, None)
		if callable(method_or_attr):
			try:
				return method_or_attr()
			except TypeError:
				continue
		# Some SDK versions expose `app` as a plain attribute rather than a method.
		if method_or_attr is not None:
			return method_or_attr

	# Could not locate an ASGI app via any known accessor.
	return None


def _configure_allowed_hosts(asgi_app: Any, allowed_hosts_arg: str) -> None:
	"""Patch TrustedHostMiddleware in the ASGI stack to permit remote clients.

	Some MCP / Starlette builds default to allowing only localhost Host headers.
	When the MCP server is exposed to remote clients (e.g. running on a server
	and accessed over the network), this middleware rejects requests with a
	"400 Invalid Host header" error.

	This function walks the Starlette middleware stack, finds
	TrustedHostMiddleware if present, and either removes it entirely (when
	allowed_hosts="*") or updates its allowed_hosts list.

	If the ASGI app does not have a Starlette-style user_middleware list, this
	function is a no-op and will not raise an error.

	Args:
		asgi_app:          The ASGI application (expected to be a Starlette app).
		allowed_hosts_arg: Comma-separated Host header values, or "*" for all.
	"""
	# Starlette stores middleware as a list on the app object.
	user_middleware = getattr(asgi_app, "user_middleware", None)
	if not isinstance(user_middleware, list):
		return

	# Parse the comma-separated host list; fall back to "*" if empty.
	allowed_hosts = [h.strip() for h in allowed_hosts_arg.split(",") if h.strip()]
	if not allowed_hosts:
		allowed_hosts = ["*"]

	updated = False
	for middleware in user_middleware:
		middleware_cls = getattr(middleware, "cls", None)
		if getattr(middleware_cls, "__name__", "") != "TrustedHostMiddleware":
			continue

		if allowed_hosts == ["*"]:
			# Wildcard: remove host validation entirely so any Host header is allowed.
			user_middleware.remove(middleware)
			updated = True
			logging.info("Disabled TrustedHostMiddleware (allowed hosts: *)")
			break

		# Update the middleware's kwargs to use the provided host list.
		kwargs = getattr(middleware, "kwargs", None)
		if isinstance(kwargs, dict):
			kwargs["allowed_hosts"] = allowed_hosts
			updated = True
			logging.info("Configured TrustedHostMiddleware allowed hosts: %s", allowed_hosts)
			break

	# If we modified the middleware stack, force Starlette to rebuild the
	# compiled middleware chain so our changes take effect at request time.
	if updated and hasattr(asgi_app, "build_middleware_stack"):
		asgi_app.middleware_stack = asgi_app.build_middleware_stack()


class _HostHeaderRewriteApp:
	"""ASGI middleware wrapper that rewrites the Host header before downstream checks.

	Some reverse-proxy setups (e.g. SSH tunnels, Nginx with proxy_pass) forward
	requests with a Host header that differs from what the MCP transport's
	TrustedHostMiddleware expects.  This wrapper intercepts every HTTP/WebSocket
	request and replaces the Host header with a fixed value before passing the
	request to the wrapped ASGI app.

	Usage:
	  asgi_app = _HostHeaderRewriteApp(asgi_app, "127.0.0.1:8000")
	"""

	def __init__(self, app: Any, host_header_value: str):
		"""Initialise the wrapper.

		Args:
			app:               The downstream ASGI application to wrap.
			host_header_value: The Host header value to inject (e.g. "host:port").
		"""
		self._app = app
		# Pre-encode to bytes once at init time rather than on every request.
		self._host_bytes = host_header_value.encode("ascii", errors="ignore")

	async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
		"""ASGI callable.  Rewrites the Host header in `scope` before forwarding.

		Only HTTP and WebSocket scopes carry headers; other scope types (e.g.
		"lifespan") are passed through untouched.

		Args:
			scope:   ASGI connection scope dict.
			receive: ASGI receive callable.
			send:    ASGI send callable.
		"""
		if scope.get("type") in {"http", "websocket"}:
			headers = list(scope.get("headers", []))
			replaced = False

			# Scan the header list for an existing Host header and replace it.
			for idx, (key, _value) in enumerate(headers):
				if key.lower() == b"host":
					headers[idx] = (key, self._host_bytes)
					replaced = True
					break

			# If no Host header was present, add one.
			if not replaced:
				headers.append((b"host", self._host_bytes))

			# scope is a dict; copy it before mutating to avoid side-effects.
			scope = dict(scope)
			scope["headers"] = headers

		await self._app(scope, receive, send)


def run_server_transport(
	server: FastMCP,
	transport: str,
	host: str,
	port: int,
	allowed_hosts: str,
	force_host_header: str,
	https_enabled: bool = False,
	tls_cert_file: Optional[str] = None,
	tls_key_file: Optional[str] = None,
) -> None:
	"""Start the FastMCP server using the specified transport.

	This function is intentionally tolerant of different FastMCP SDK versions.
	The SDK's API has changed between releases and different installations may
	have different capabilities.  The resolution order is:

	  1. stdio — call server.run(transport="stdio") directly; no network binding.
	  2. ASGI discovery — if the SDK exposes an ASGI app, hand it to uvicorn
	     directly for reliable host/port binding.
	  3. Transport-specific run methods — e.g. server.run_streamable_http().
	  4. Generic server.run() with whatever kwargs its signature accepts.
	  5. Last resort: call server.run(transport) positionally.

	Args:
		server:            The FastMCP server instance to run.
		transport:         One of "stdio", "sse", "streamable-http".
		host:              IP address to bind for network transports.
		port:              TCP port to bind for network transports.
		allowed_hosts:     Comma-separated Host header allowlist (or "*").
		force_host_header: If non-empty, rewrite all incoming Host headers to
		                   this value before MCP transport security checks.
		https_enabled:     Enable TLS for HTTP transports.
		tls_cert_file:     Path to TLS certificate file (PEM/CRT).
		tls_key_file:      Path to TLS private key file.
	"""
	# stdio transport is the simplest case: no network socket, just read from
	# stdin and write to stdout.  Host/port/allowed_hosts are irrelevant.
	if transport == "stdio":
		_call_with_supported_kwargs(server.run, {"transport": "stdio"})
		return

	# Parse the comma-separated allowed_hosts string into a list for SDK methods
	# that accept a list rather than a string.
	allowed_host_list = [h.strip() for h in allowed_hosts.split(",") if h.strip()]
	if not allowed_host_list:
		allowed_host_list = ["*"]

	# --- Strategy 1: explicit uvicorn hosting via discovered ASGI app ---
	# This is the most reliable approach because we control the host/port.
	asgi_app = _discover_asgi_app(server, transport=transport)
	if asgi_app is not None:
		# Patch TrustedHostMiddleware before adding the Host rewrite wrapper
		# so the rewritten header passes the middleware check.
		_configure_allowed_hosts(asgi_app, allowed_hosts_arg=allowed_hosts)

		if force_host_header.strip():
			logging.info(
				"Rewriting incoming Host header to %s for MCP transport security compatibility",
				force_host_header.strip(),
			)
			# Wrap the ASGI app with the header rewrite middleware.
			asgi_app = _HostHeaderRewriteApp(asgi_app, force_host_header.strip())

		logging.info(
			"Using explicit uvicorn hosting for %s on %s:%d (%s)",
			transport,
			host,
			port,
			"https" if https_enabled else "http",
		)
		uvicorn_kwargs: Dict[str, Any] = {"host": host, "port": port}
		if https_enabled:
			uvicorn_kwargs["ssl_certfile"] = tls_cert_file
			uvicorn_kwargs["ssl_keyfile"] = tls_key_file
		uvicorn.run(asgi_app, **uvicorn_kwargs)
		return

	if https_enabled:
		raise RuntimeError(
			"HTTPS mode requires ASGI app discovery for explicit uvicorn hosting, but no ASGI app was exposed by this FastMCP version."
		)

	# --- Strategy 2: transport-specific run methods ---
	if transport == "streamable-http" and hasattr(server, "run_streamable_http"):
		_call_with_supported_kwargs(
			getattr(server, "run_streamable_http"),
			{
				"host": host,
				"port": port,
				"allowed_hosts": allowed_host_list,
				"allowedHosts": allowed_host_list,
			},
		)
		return

	if transport == "sse" and hasattr(server, "run_sse"):
		_call_with_supported_kwargs(
			getattr(server, "run_sse"),
			{
				"host": host,
				"port": port,
				"allowed_hosts": allowed_host_list,
				"allowedHosts": allowed_host_list,
			},
		)
		return

	# --- Strategy 3: generic server.run() with supported kwargs ---
	# Introspect the run() signature and pass only what it accepts.
	run_params = inspect.signature(server.run).parameters
	kwargs: Dict[str, Any] = {}

	if "transport" in run_params:
		kwargs["transport"] = transport

	# Different SDK versions use different parameter names for the bind address.
	host_key = None
	for candidate in ("host", "bind", "hostname"):
		if candidate in run_params:
			host_key = candidate
			break

	port_key = "port" if "port" in run_params else None

	if host_key:
		kwargs[host_key] = host
	if port_key:
		kwargs[port_key] = port
	if "allowed_hosts" in run_params:
		kwargs["allowed_hosts"] = allowed_host_list
	if "allowedHosts" in run_params:
		kwargs["allowedHosts"] = allowed_host_list

	if kwargs:
		server.run(**kwargs)
		return

	# --- Strategy 4: positional transport argument (oldest SDK versions) ---
	server.run(transport)


def main() -> int:
	"""Entry point: parse arguments, configure the server, and run it.

	Workflow:
	  1. Parse CLI arguments.
	  2. Configure logging at the requested level.
	  3. Apply optional CLI auth overrides, then load Portnox config.
	  4. Optionally daemonize the process.
	  5. Install signal handlers for SIGTERM and SIGINT so the daemon shuts
	     down cleanly and removes its PID file.
	  6. Create the PortnoxClient and MCP server, then start the transport.
	  7. On any exception, log and return a non-zero exit code.
	  8. Always close the HTTP client and remove the PID file on exit.

	Returns:
		0 on clean exit, 1 on unexpected error, 2 on configuration error.
	"""
	args = parse_args()
	_configure_logging(args.log_level)
	logging.warning(
		"Legal notice: Portnox MCP Server is community-supported (no SLA/support guarantees). "
		"Review and approve all automated changes, and use a dedicated least-privilege admin account."
	)

	# Resolve PID/log file paths only when daemon mode is active; otherwise
	# leave them as None so daemonize() and remove_pid_file() are no-ops.
	pid_file = Path(args.pid_file) if args.daemon else None
	log_file = Path(args.log_file) if args.daemon else None

	# Optional auth/config CLI overrides.  These let operators run:
	#   python MCP Server.py --username ... --password ...
	# without needing to export environment variables first.
	if args.token_file is not None:
		os.environ["PORTNOX_TOKEN_FILE"] = args.token_file
	if args.token is not None:
		os.environ["PORTNOX_TOKEN"] = args.token
	if args.username is not None:
		os.environ["PORTNOX_USERNAME"] = args.username
	if args.password is not None:
		os.environ["PORTNOX_PASSWORD"] = args.password

	# Load and validate configuration before forking; a missing token should
	# produce a clear error message to the terminal, not a silent daemon death.
	try:
		config = PortnoxConfig.from_env()
	except ValueError as exc:
		logging.error(str(exc))
		return 2  # Exit code 2 = configuration error.

	# Resolve TLS files (including optional self-signed generation) before
	# serving network traffic when HTTPS mode is enabled.
	try:
		tls_config = _resolve_tls_files(args)
	except ValueError as exc:
		logging.error(str(exc))
		return 2

	# Detach from the terminal if daemon mode was requested.
	if args.daemon:
		daemonize(pid_file=pid_file, log_file=log_file)

	def _handle_shutdown(signum: int, _frame: Any) -> None:
		"""Signal handler for SIGTERM and SIGINT.

		Logs the received signal, removes the PID file, and raises SystemExit
		so the finally block in main() runs (closing the HTTP client cleanly).
		"""
		logging.info("Received signal %s; shutting down.", signum)
		remove_pid_file(pid_file)
		raise SystemExit(0)

	# Register the same handler for both SIGTERM (systemd stop) and
	# SIGINT (Ctrl-C in foreground mode).
	signal.signal(signal.SIGTERM, _handle_shutdown)
	signal.signal(signal.SIGINT, _handle_shutdown)

	client = None
	try:
		# Create the HTTP client and build the MCP server with all registered tools.
		client = PortnoxClient(config)
		server = build_server(client)

		if args.transport == "stdio":
			logging.info("Starting Portnox MCP server with stdio transport")
			run_server_transport(
				server,
				transport="stdio",
				host=args.host,
				port=args.port,
				allowed_hosts=args.allowed_hosts,
				force_host_header=args.force_host_header,
				https_enabled=False,
				tls_cert_file=None,
				tls_key_file=None,
			)
		else:
			logging.info(
				"Starting Portnox MCP server with %s transport on %s:%d (%s, allowed-hosts=%s, force-host-header=%s)",
				args.transport,
				args.host,
				args.port,
				"https" if tls_config["enabled"] else "http",
				args.allowed_hosts,
				args.force_host_header or "<disabled>",
			)
			run_server_transport(
				server,
				transport=args.transport,
				host=args.host,
				port=args.port,
				allowed_hosts=args.allowed_hosts,
				force_host_header=args.force_host_header,
				https_enabled=bool(tls_config["enabled"]),
				tls_cert_file=tls_config["certfile"],
				tls_key_file=tls_config["keyfile"],
			)
		return 0  # Clean exit.

	except Exception:
		# Log the full traceback so the operator can diagnose what went wrong.
		logging.exception("Portnox MCP server failed")
		return 1  # Exit code 1 = unexpected runtime error.

	finally:
		# Always clean up resources regardless of how we exit (normal, exception,
		# or SystemExit from the signal handler).
		if client:
			try:
				client.close()
				logging.debug("Closed Portnox client resources")
			except Exception:
				logging.exception("Error closing Portnox client")
		remove_pid_file(pid_file)


if __name__ == "__main__":
	raise SystemExit(main())