#!/usr/bin/env python3
"""Update only the description of a Portnox site.

This script is intentionally simple for troubleshooting API behavior outside MCP.

Auth:
- Uses PORTNOX_TOKEN environment variable.

Examples:
- Update by site ID (recommended):
  python3 update_site_description.py --site-id 81ef7028-c7df-4625-b569-20dde99c9331 --description "this site was modified by Claude AI"

- Update by site name (fails if duplicates exist):
  python3 update_site_description.py --site-name Claude --description "this site was modified by Claude AI"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

import requests


DEFAULT_BASE_URL = "https://clear.portnox.com:8081/CloudPortalBackEnd"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update Portnox site description")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--site-id", help="Target site ID")
    group.add_argument("--site-name", help="Target site name (must be unique)")
    parser.add_argument("--description", required=True, help="New site description")
    parser.add_argument(
        "--base-url",
        default=os.getenv("PORTNOX_BASE_URL", DEFAULT_BASE_URL),
        help="Portnox base URL",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        default=os.getenv("PORTNOX_VERIFY_TLS", "true").lower() != "false",
        help="Verify TLS certificates (default: true)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("PORTNOX_TIMEOUT_SECONDS", "30")),
        help="HTTP timeout seconds",
    )
    return parser.parse_args()


def build_session(token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "X-API-Token": token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    return session


def get_sites(session: requests.Session, base_url: str, timeout: int, verify_tls: bool) -> List[Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/api/nases/sites"
    resp = session.get(url, timeout=timeout, verify=verify_tls)
    if resp.status_code != 200:
        raise RuntimeError(f"GET /api/nases/sites failed: HTTP {resp.status_code} - {resp.text[:400]}")

    body = resp.json()
    if not isinstance(body, dict) or not isinstance(body.get("Sites"), list):
        raise RuntimeError("Unexpected response shape from GET /api/nases/sites")
    return body["Sites"]


def put_site(session: requests.Session, base_url: str, payload: Dict[str, Any], timeout: int, verify_tls: bool) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/api/nases/sites"
    resp = session.put(url, data=json.dumps(payload), timeout=timeout, verify=verify_tls)
    if resp.status_code != 200:
        raise RuntimeError(f"PUT /api/nases/sites failed: HTTP {resp.status_code} - {resp.text[:400]}")

    try:
        body = resp.json()
    except ValueError:
        return {"raw": resp.text}

    if not isinstance(body, dict):
        return {"raw": body}
    return body


def main() -> int:
    args = parse_args()

    token = os.getenv("PORTNOX_TOKEN", "").strip()
    if not token:
        print("ERROR: PORTNOX_TOKEN is not set", file=sys.stderr)
        return 2

    session = build_session(token)

    sites_before = get_sites(session, args.base_url, args.timeout, args.verify_tls)

    target = None
    if args.site_id:
        for site in sites_before:
            if str(site.get("Id", "")).strip() == args.site_id.strip():
                target = site
                break
        if target is None:
            print(f"ERROR: No site found with ID {args.site_id}", file=sys.stderr)
            return 3
    else:
        matches = [s for s in sites_before if str(s.get("Name", "")).strip().casefold() == args.site_name.strip().casefold()]
        if len(matches) == 0:
            print(f"ERROR: No site found with name '{args.site_name}'", file=sys.stderr)
            return 3
        if len(matches) > 1:
            print(f"ERROR: Multiple sites found with name '{args.site_name}'. Use --site-id instead.", file=sys.stderr)
            for m in matches:
                print(f"  - Id={m.get('Id')} Name={m.get('Name')} Description={m.get('Description')}", file=sys.stderr)
            return 4
        target = matches[0]

    target_id = str(target.get("Id", "")).strip()
    target_name = str(target.get("Name", "")).strip()
    old_desc = str(target.get("Description", ""))

    payload = dict(target)
    payload["Description"] = args.description

    print(f"Updating site Id={target_id} Name='{target_name}'")
    print(f"Old description: {old_desc!r}")
    print(f"New description: {args.description!r}")

    put_result = put_site(session, args.base_url, payload, args.timeout, args.verify_tls)

    sites_after = get_sites(session, args.base_url, args.timeout, args.verify_tls)
    after_target = next((s for s in sites_after if str(s.get("Id", "")).strip() == target_id), None)

    if after_target is None:
        print("ERROR: Target site ID no longer present after PUT.", file=sys.stderr)
        print(f"PUT response: {json.dumps(put_result, indent=2, default=str)}", file=sys.stderr)
        return 5

    new_desc = str(after_target.get("Description", ""))
    same_name_count_before = sum(1 for s in sites_before if str(s.get("Name", "")).strip().casefold() == target_name.casefold())
    same_name_count_after = sum(1 for s in sites_after if str(s.get("Name", "")).strip().casefold() == target_name.casefold())

    print(f"After PUT: Id={target_id} Name='{target_name}' Description={new_desc!r}")
    print(f"Sites with same name before={same_name_count_before}, after={same_name_count_after}")

    if new_desc != args.description:
        print("ERROR: Description did not update on the target ID.", file=sys.stderr)
        print(f"PUT response: {json.dumps(put_result, indent=2, default=str)}", file=sys.stderr)
        return 6

    if same_name_count_after > same_name_count_before:
        print("WARNING: A duplicate site with the same name appears to have been created.")

    print("SUCCESS: Target site description updated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
