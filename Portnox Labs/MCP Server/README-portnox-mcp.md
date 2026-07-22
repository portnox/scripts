# Portnox MCP Server (Python)

## Legal Disclaimer

The Portnox MCP Server is an open source project sponsored by Portnox and
licensed under the Apache License, Version 2.0. The terms of the Apache 2.0
license govern your use of this software.

### Support

The Portnox MCP Server is **not** an officially supported Portnox product. It
is provided as a community-supported project, and Portnox does not provide
technical support, service level agreements (SLAs), maintenance commitments,
or guaranteed response times for issues related to this software.

Bug reports, feature requests, and questions should be submitted through the
project's GitHub repository.

### Community Contributions

Community contributions are welcome. Bug fixes, new features, documentation
improvements, and other enhancements may be submitted as GitHub pull requests.

Portnox may periodically review community submissions and, at its sole
discretion, accept, reject, modify, or merge contributions that are
appropriate for the project. Submission of a contribution does not guarantee
that it will be incorporated into future releases.

### Use Responsibly

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

### License

This project is licensed under the Apache License, Version 2.0. By using,
modifying, or distributing this software, you agree to the terms and
conditions of that license, including its provisions regarding warranties,
liability, and patent rights.

**Security Notice:** We recommend creating a dedicated Portnox Cloud
administrator account for use with the MCP server and granting it only the
permissions required for your intended workflows. Avoid using personal
administrator accounts or credentials with unrestricted administrative access.
Following the principle of least privilege can significantly reduce the impact
of unintended or incorrect MCP operations.

This MCP server exposes thirty tools:

- `list_nas_devices(mode=0, info=0)`
- `list_nas_sites()`
- `list_portnox_nas_sites()`
- `create_or_update_site(name, description=None, parent_id=None, rules=None)`
- `update_portnox_site(name, description=None, parent_id=None, rules=None)`
- `update_site_by_id(site_id, name=None, description=None, parent_id=None, rules=None)`
- `update_portnox_site_by_id(site_id, name=None, description=None, parent_id=None, rules=None)`
- `delete_site_by_id(site_id)`
- `delete_portnox_site_by_id(site_id)`
- `delete_site_by_name(name)`
- `delete_portnox_site(name)`
- `update_site_rules_by_id(site_id, rules)`
- `update_portnox_site_rules_by_id(site_id, rules)`
- `update_site_rules_by_name(name, rules)`
- `update_portnox_site_rules(name, rules)`
- `list_devices(page_number=1, page_size=10, search_value=None, search_field=None, include_account_without_devices=False, client_time_offset=0)`
- `list_portnox_devices(page_number=1, page_size=10, search_value=None, search_field=None, include_account_without_devices=False, client_time_offset=0)`
- `list_all_devices(page_size=10, search_value=None, search_field=None, include_account_without_devices=False, client_time_offset=0, max_pages=1000)`
- `list_all_portnox_devices(page_size=10, search_value=None, search_field=None, include_account_without_devices=False, client_time_offset=0, max_pages=1000)`
- `find_devices_by_account_name(account_name, search_field=1)`
- `find_portnox_devices_by_account_name(account_name, search_field=1)`
- `block_device(entity_id, reason=None)`
- `block_portnox_device(entity_id, reason=None)`
- `block_device_by_account_name(account_name, reason=None)`
- `block_portnox_device_by_account_name(account_name, reason=None)`
- `unblock_device(entity_id)`
- `unblock_portnox_device(entity_id)`
- `update_nas_devices(nases)`
- `update_nas_display_name_by_ip(ip_address, display_name, mode=0, info=0)`
- `update_portnox_nas_display_name(ip_address, display_name, mode=0, info=0)`

It calls the Portnox Cloud endpoints:

- `POST https://clear.portnox.com:8081/CloudPortalBackEnd/api/nases`
- `POST https://clear.portnox.com:8081/CloudPortalBackEnd/api/device/list`
- `POST https://clear.portnox.com:8081/CloudPortalBackEnd/api/device/block`
- `POST https://clear.portnox.com:8081/CloudPortalBackEnd/api/device/unblock`
- `GET https://clear.portnox.com:8081/CloudPortalBackEnd/api/nases/sites`
- `PUT https://clear.portnox.com:8081/CloudPortalBackEnd/api/nases/sites`
- `DELETE https://clear.portnox.com:8081/CloudPortalBackEnd/api/nases/sites/{siteId}`
- `POST https://clear.portnox.com:8081/CloudPortalBackEnd/api/nases/sites/{siteId}/rules`

with request body:

```json
{
  "Mode": 0,
  "Info": 0
}
```

## 1) Install

```bash
cd /Users/jeremy.morrill
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-portnox-mcp.txt
```

## 2) Configure environment

Built-in defaults (used automatically when not provided):

- `PORTNOX_BASE_URL=https://clear.portnox.com:8081/CloudPortalBackEnd`
- `MCP_ALLOWED_HOSTS=*`
- `MCP_FORCE_HOST_HEADER=localhost:8765`
- `MCP_ENABLE_HTTPS=false`
- `MCP_TLS_CERT_DIR=/tmp/portnox-mcp-tls`

If you pass any of these via environment variables or CLI flags, your values
override the defaults.

HTTPS/TLS configuration defaults:

- `MCP_TLS_CERT_FILE` + `MCP_TLS_KEY_FILE`: use user-provided PEM/CRT + key.
- `MCP_TLS_PFX_FILE` (+ optional `MCP_TLS_PFX_PASSWORD`): use user-provided
  PKCS#12 bundle (`.pfx`/`.p12`), converted automatically at startup.
- If HTTPS is enabled and no cert inputs are provided, the server auto-generates
  a self-signed certificate on first start.

Preferred (more secure) option is to keep the token in a file and point the
server at that file path.

```bash
mkdir -p ./secrets
chmod 700 ./secrets
printf '%s\n' 'YOUR_LONG_LIVED_TOKEN' > ./secrets/portnox_token.txt
chmod 600 ./secrets/portnox_token.txt
export PORTNOX_TOKEN_FILE="$(pwd)/secrets/portnox_token.txt"
```

Legacy option (still supported):

```bash
export PORTNOX_TOKEN="YOUR_LONG_LIVED_TOKEN"
export PORTNOX_TIMEOUT_SECONDS="30"
export PORTNOX_VERIFY_TLS="true"
```

The server now reads the token from `PORTNOX_TOKEN_FILE` first, then falls
back to `PORTNOX_TOKEN` if the file path is not configured.

Alternative auth option (local admin username/password):

```bash
export PORTNOX_USERNAME="YOUR_LOCAL_ADMIN_USERNAME"
export PORTNOX_PASSWORD="YOUR_LOCAL_ADMIN_PASSWORD"
export PORTNOX_TIMEOUT_SECONDS="30"
export PORTNOX_VERIFY_TLS="true"
```

Important notes for username/password auth:

- This must be a local Portnox Cloud admin account.
- Federated accounts (Entra ID, Okta, Google Workspace, Active Directory)
  are not supported for this login flow.
- Token auth remains the recommended mode for automation.

## 3) Run in stdio mode (best for Claude/Desktop style MCP clients)

```bash
python3 "/Users/jeremy.morrill/MCP Server.py"
```

Pass credentials directly on the command line (testing/convenience):

```bash
python3 "/Users/jeremy.morrill/MCP Server.py" \
  --username "YOUR_LOCAL_ADMIN_USERNAME" \
  --password "YOUR_LOCAL_ADMIN_PASSWORD"
```

You can also pass token auth directly on the command line:

```bash
python3 "/Users/jeremy.morrill/MCP Server.py" \
  --token "YOUR_LONG_LIVED_TOKEN"
```

## 3b) Run as a Claude Desktop extension (recommended)

This repo includes a ready-to-copy Claude config template:

- `claude_desktop_config.portnox.example.json`

Then copy the template entry into your Claude Desktop MCP config, typically:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

Token-file example entry:

```json
{
  "mcpServers": {
    "portnox-mcp": {
      "command": "/opt/homebrew/bin/python3",
      "args": [
        "/Volumes/share/MCP/MCP Server.py",
        "--transport",
        "stdio"
      ],
      "env": {
        "PORTNOX_BASE_URL": "https://clear.portnox.com:8081/CloudPortalBackEnd",
        "PORTNOX_TOKEN_FILE": "/Volumes/share/MCP/secrets/portnox_token.txt",
        "PORTNOX_TIMEOUT_SECONDS": "30",
        "PORTNOX_VERIFY_TLS": "true"
      }
    }
  }
}
```

Username/password example entry:

```json
{
  "mcpServers": {
    "portnox-mcp": {
      "command": "/opt/homebrew/bin/python3",
      "args": [
        "/Volumes/share/MCP/MCP Server.py",
        "--transport",
        "stdio"
      ],
      "env": {
        "PORTNOX_BASE_URL": "https://clear.portnox.com:8081/CloudPortalBackEnd",
        "PORTNOX_USERNAME": "YOUR_LOCAL_ADMIN_USERNAME",
        "PORTNOX_PASSWORD": "YOUR_LOCAL_ADMIN_PASSWORD",
        "PORTNOX_TIMEOUT_SECONDS": "30",
        "PORTNOX_VERIFY_TLS": "true"
      }
    }
  }
}
```

Notes:

- This extension mode connects over stdio directly, so you do not need `mcp-remote`.
- Because there is no HTTP hop, host-header/TLS reverse-proxy settings are not required for Claude Desktop local usage.
- If Claude logs show "Operation not permitted" while launching a script from `/Volumes/...`, use direct Python command mode (as above) rather than a shell script command.

## 4) Run as Linux daemon (systemd)

Use the service template file:

- `/Users/jeremy.morrill/portnox-mcp-server.service`

Typical deployment:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin portnox || true
sudo mkdir -p /opt/portnox-mcp
sudo cp "/Users/jeremy.morrill/MCP Server.py" /opt/portnox-mcp/
sudo cp /Users/jeremy.morrill/requirements-portnox-mcp.txt /opt/portnox-mcp/
cd /opt/portnox-mcp
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements-portnox-mcp.txt
sudo cp /Users/jeremy.morrill/portnox-mcp-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now portnox-mcp-server
sudo systemctl status portnox-mcp-server
```

## 5) Run with Docker + Docker Compose (auto-start + secret file)

This repo includes:

- `Dockerfile`
- `docker-compose.yml`

The compose file is configured to:

- mount the token as a Docker secret file at `/run/secrets/portnox_token`
- set `PORTNOX_TOKEN_FILE` to that secret file path
- start automatically after reboot with `restart: unless-stopped`
- run with a read-only root filesystem and non-root user
- rewrite the Host header to `localhost:8765` by default so remote MCP
  clients such as Claude Desktop's `mcp-remote` wrapper do not trip host
  validation on the container

Prepare the secret file once:

```bash
mkdir -p ./secrets
chmod 700 ./secrets
printf '%s\n' 'YOUR_LONG_LIVED_TOKEN' > ./secrets/portnox_token.txt
chmod 600 ./secrets/portnox_token.txt
```

Start the container:

```bash
docker compose up -d --build
```

### HTTPS mode (auto self-signed cert)

Enable HTTPS and let the container generate a self-signed certificate
automatically:

```bash
docker run -d \
  --name portnox-mcp-https \
  --restart unless-stopped \
  -p 8765:8765 \
  -e MCP_ENABLE_HTTPS="true" \
  -e PORTNOX_TOKEN="YOUR_LONG_LIVED_TOKEN" \
  --read-only \
  --tmpfs /tmp \
  alt3r3g0/portnox-mcp:latest
```

### HTTPS mode with PEM/CRT + KEY

Mount certificate files into the container and point the TLS file variables
to those paths:

```bash
docker run -d \
  --name portnox-mcp-https-custom \
  --restart unless-stopped \
  -p 8765:8765 \
  -v /path/on/host/certs:/certs:ro \
  -e MCP_ENABLE_HTTPS="true" \
  -e MCP_TLS_CERT_FILE="/certs/server.crt" \
  -e MCP_TLS_KEY_FILE="/certs/server.key" \
  -e PORTNOX_TOKEN="YOUR_LONG_LIVED_TOKEN" \
  --read-only \
  --tmpfs /tmp \
  alt3r3g0/portnox-mcp:latest
```

### HTTPS mode with PFX/P12 bundle

Mount your `.pfx` or `.p12` file and set the PKCS#12 variables. The container
converts it to PEM key/cert automatically at startup:

```bash
docker run -d \
  --name portnox-mcp-https-pfx \
  --restart unless-stopped \
  -p 8765:8765 \
  -v /path/on/host/certs:/certs:ro \
  -e MCP_ENABLE_HTTPS="true" \
  -e MCP_TLS_PFX_FILE="/certs/server.p12" \
  -e MCP_TLS_PFX_PASSWORD="YOUR_PFX_PASSWORD" \
  -e PORTNOX_TOKEN="YOUR_LONG_LIVED_TOKEN" \
  --read-only \
  --tmpfs /tmp \
  alt3r3g0/portnox-mcp:latest
```

Stop it:

```bash
docker compose down
```

### Optional testing mode: pass token directly in docker run

For quick testing only, you can pass the token as an environment variable
instead of using a mounted secret file.

Security note:

- This is less secure than `PORTNOX_TOKEN_FILE` because environment variables
  can be exposed via process inspection, shell history, and container metadata.
- Keep using the secret-file approach for production.

```bash
docker run -d \
  --name portnox-mcp-test \
  --restart unless-stopped \
  -p 8765:8765 \
  -e PORTNOX_TOKEN="YOUR_LONG_LIVED_TOKEN" \
  -e PORTNOX_TIMEOUT_SECONDS="30" \
  -e PORTNOX_VERIFY_TLS="true" \
  --read-only \
  --tmpfs /tmp \
  alt3r3g0/portnox-mcp:latest
```

Because the server reads `PORTNOX_TOKEN_FILE` first and then falls back to
`PORTNOX_TOKEN`, this works as long as `PORTNOX_TOKEN_FILE` is not set to a
non-empty path inside the container.

### Optional testing mode with docker compose override

If you want to test `PORTNOX_TOKEN` via compose, create a temporary override:

```yaml
# docker-compose.override.yml (testing only)
services:
  portnox-mcp:
    environment:
      PORTNOX_TOKEN_FILE: ""
      PORTNOX_TOKEN: "YOUR_LONG_LIVED_TOKEN"
```

Then run:

```bash
docker compose up -d --build
```

### Optional testing mode: username/password in docker run

```bash
docker run -d \
  --name portnox-mcp-test-credentials \
  --restart unless-stopped \
  -p 8765:8765 \
  -e PORTNOX_USERNAME="YOUR_LOCAL_ADMIN_USERNAME" \
  -e PORTNOX_PASSWORD="YOUR_LOCAL_ADMIN_PASSWORD" \
  -e PORTNOX_TIMEOUT_SECONDS="30" \
  -e PORTNOX_VERIFY_TLS="true" \
  --read-only \
  --tmpfs /tmp \
  alt3r3g0/portnox-mcp:latest
```

Security note:

- This is useful for testing only.
- Token file auth remains the preferred production approach.
- If you supply credentials in `docker run`, pass them as `-e PORTNOX_USERNAME=...`
  and `-e PORTNOX_PASSWORD=...` as shown above.

## Error mapping

The tool maps Portnox API responses as:

- `400`: Missing or malformed parameter
- `401`: Provided organizational credentials are not valid
- `403`: Access denied due to license restrictions
- `404`: Site was not found
- `500`: Internal server error

## Example natural language prompts

- `Update the display name for Portnox NAS '10.1.1.1' to 'USG'`
- `List all Portnox NAS devices`
- `List the Portnox sites where a NAS can be deployed`
- `Create a new Portnox site named 'Branch Office' with description 'New branch location'`
- `Create a Portnox site called 'Data Center' with CIDR rule 10.0.0.0/24 and IP range 192.168.1.1-192.168.1.254`
- `Add the description 'this site was modified by Claude AI' to the Portnox site 'Claude'` (updates existing site by name, preserves other fields)
- `Update the Portnox site with ID 'abc123' to have description 'Updated site'` (direct ID-based update)
- `Delete the Portnox site named 'Claude'`
- `Delete Portnox site ID '81ef7028-c7df-4625-b569-20dde99c9331'`
- `Update rules for Portnox site ID '81ef7028-c7df-4625-b569-20dde99c9331' to 10.10.20.0/24`
- `Set rules on Portnox site 'Branch Office' to CIDR 10.10.20.0/24 and range 192.168.10.10-192.168.10.100`
- `List Portnox devices`
- `List Portnox devices page 2 with page size 10`
- `List Portnox devices where search value is 'alice'`
- `List all Portnox devices across every page`
- `List all Portnox devices with search value 'alice'`
- `Block device ID 'f2d0d4f1-2222-4444-9999-4f7f97294711' with reason 'Too many authentication attempts'`
- `Block device ID 'f2d0d4f1-2222-4444-9999-4f7f97294711'`
- `Block all devices for account joe.bob@hackermail.com with reason 'Compromised credentials'`
- `Block all devices for account joe.bob@hackermail.com`
- `Unblock device ID 'f2d0d4f1-2222-4444-9999-4f7f97294711'`

### Deleting sites

- `delete_site_by_id(site_id)` is the safest option and should be preferred when ID is known.
- `delete_site_by_name(name)` resolves by name and fails if multiple sites share that name.
- Delete tools verify the site no longer exists after the API call; they fail if deletion cannot be confirmed.

### Updating site rules

- `update_site_rules_by_id(site_id, rules)` is the safest option and should be preferred when ID is known.
- `update_site_rules_by_name(name, rules)` resolves by name and fails if multiple sites share that name.
- Rules payload must be a non-empty list.

Rules model:

```json
{
  "Rules": [
    {
      "Type": 1,
      "From": "10.10.20.0",
      "To": null,
      "Mask": 24
    },
    {
      "Type": 2,
      "From": "192.168.10.10",
      "To": "192.168.10.100",
      "Mask": null
    }
  ]
}
```

Expected response format:

```json
{
  "Site": {
    "Id": "string",
    "Name": "string",
    "Description": "string",
    "ParentId": "string",
    "Rules": [
      {
        "Type": 1,
        "From": "string",
        "To": "string",
        "Mask": 0
      }
    ]
  }
}
```

### Listing devices

- Use `list_devices(...)` or `list_portnox_devices(...)`.
- Pagination defaults to `page_number=1` and `page_size=10`.
- Optional search can be passed with `search_value` and `search_field`.
- Use `list_all_devices(...)` or `list_all_portnox_devices(...)` to fetch all pages automatically.
- `list_all_*` returns flattened rows as `{"account": {...}, "device": {...}}`.
- Use `max_pages` as a safety cap for very large environments.

### Finding devices by account name

- Use `find_devices_by_account_name(account_name, search_field=1)` or `find_portnox_devices_by_account_name(account_name, search_field=1)`.
- `account_name` is the email or account identifier to search for.
- `search_field` defaults to `1` (commonly email/account in Portnox); override if needed.
- Returns a list of matching devices with entity IDs, device names, MAC addresses, and IP addresses.

### Blocking devices by account name

- Use `block_device_by_account_name(account_name, reason=None)` or `block_portnox_device_by_account_name(account_name, reason=None)`.
- `account_name` is the email or account identifier to block all devices for.
- Automatically searches for all devices associated with the account and blocks them.
- If `reason` is omitted, the default reason is: `Device blocked by the Portnox MCP server`.
- Returns the list of blocked devices and any errors encountered.

### Blocking devices

- Use `block_device(entity_id, reason=None)` or `block_portnox_device(entity_id, reason=None)`.
- If `reason` is omitted, the default reason is: `Device blocked by the Portnox MCP server`.
- `entity_id` is required and should be the device GUID.

### Unblocking devices

- Use `unblock_device(entity_id)` or `unblock_portnox_device(entity_id)`.
- `entity_id` is required and should be the device GUID.

Request model sent to Portnox:

```json
{
  "Query": {
    "Filter": null,
    "PageNumber": 1,
    "PageSize": 10,
    "Order": 0,
    "OrderBy": null
  },
  "Search": null,
  "ClientTimeOffset": 0,
  "IncludeAccountWithoutDevices": false,
  "Order": null,
  "StartTimeLimit": null,
  "EndTimeLimit": null,
  "StartReportedTimeLimit": null,
  "EndReportedTimeLimit": null,
  "StartCreatedTimeLimit": null,
  "EndCreatedTimeLimit": null
}
```

Response includes:
- `Result` (account/device entries)
- `TotalPages`
- `TotalDevices`

### Updating sites: two approaches

**1. Update by name (recommended for user-friendly prompts):**
- Use `create_or_update_site(name, description, parent_id, rules)` 
- The tool automatically looks up the site by name and preserves its ID
- If the site name already exists once, only the provided fields are updated; others are kept intact
- If multiple sites share the same name, the tool fails and asks for `update_site_by_id(...)`
- If the site doesn't exist, a new one is created

**2. Update by ID (recommended for reliable programmatic updates):**
- Use `update_site_by_id(site_id, name, description, parent_id, rules)`
- Directly updates a specific site by ID without name lookup
- Only provided parameters are updated; omitted parameters preserve their existing values
- The tool verifies the response ID matches the requested ID and fails fast on mismatch

### Full site object structure

When retrieving sites via `list_nas_sites()`, each site has the following structure:

```json
{
  "Id": "unique-site-id",
  "Name": "string",
  "Description": "string",
  "ParentId": "string or null",
  "Rules": [
    {
      "Type": 1,
      "From": "10.0.0.0",
      "To": null,
      "Mask": 24
    },
    {
      "Type": 2,
      "From": "192.168.1.1",
      "To": "192.168.1.254",
      "Mask": null
    }
  ]
}
```

### Site creation and update request body

For `create_or_update_site()` and `update_site_by_id()`, the `rules` parameter accepts a list of rule objects:

```json
{
  "Type": 1,
  "From": "10.0.0.0",
  "To": null,
  "Mask": 24
}
```

Rule types:
- Type 1: CIDR notation (From=IP address, Mask=prefix length, To=null)
- Type 2: IP range (From=start IP, To=end IP, Mask=null)
