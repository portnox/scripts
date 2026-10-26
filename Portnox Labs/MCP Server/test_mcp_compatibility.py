import json
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import Mock, patch

from mcp import Client, StdioServerParameters


SERVER_PATH = Path(__file__).with_name("MCP Server.py")
SERVER = runpy.run_path(str(SERVER_PATH), run_name="portnox_mcp_tests")


class MCPCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.backend = Mock(spec=SERVER["PortnoxClient"])
        self.server = SERVER["build_server"](self.backend)

    async def test_tool_registration(self):
        async with Client(self.server) as client:
            result = await client.list_tools()
        names = {tool.name for tool in result.tools}
        self.assertEqual(len(names), 80)
        self.assertTrue(
            {"list_nas_devices", "list_nas_sites", "list_portnox_nas_sites"} <= names
        )

    async def test_tool_arguments_and_result_envelope(self):
        devices = [{"Name": "test-nas"}]
        self.backend.get_nases.return_value = devices
        async with Client(self.server) as client:
            result = await client.call_tool("list_nas_devices", {"mode": 1, "info": 2})
        self.backend.get_nases.assert_called_once_with(mode=1, info=2)
        self.assertFalse(result.is_error)
        expected = {"count": 1, "items": devices}
        self.assertEqual(json.loads(result.content[0].text), expected)
        self.assertEqual(result.structured_content, {"result": expected})

    async def test_site_alias_preserves_result(self):
        sites = [{"Name": "test-site"}]
        self.backend.get_sites.return_value = sites
        async with Client(self.server) as client:
            original = await client.call_tool("list_nas_sites", {})
            alias = await client.call_tool("list_portnox_nas_sites", {})
        self.assertFalse(alias.is_error)
        self.assertEqual(alias.structured_content, original.structured_content)
        self.assertEqual(json.loads(alias.content[0].text), {"count": 1, "items": sites})

    async def test_invalid_arguments_do_not_call_backend(self):
        async with Client(self.server) as client:
            result = await client.call_tool("list_nas_devices", {"mode": "invalid"})
        self.assertTrue(result.is_error)
        self.backend.get_nases.assert_not_called()

    async def test_stdio_protocol_initialization(self):
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[
                str(SERVER_PATH),
                "--transport",
                "stdio",
                "--token",
                "test-token-not-a-real-credential",
            ],
        )
        async with Client(parameters, read_timeout_seconds=15) as client:
            result = await client.list_tools()
        self.assertEqual(len(result.tools), 80)

    def test_http_apps_expose_existing_paths(self):
        for transport, expected_path in (("sse", "/sse"), ("streamable-http", "/mcp")):
            with self.subTest(transport=transport):
                app = SERVER["_discover_asgi_app"](self.server, transport)
                self.assertIsNotNone(app)
                self.assertIn(expected_path, {route.path for route in app.routes})

    def test_https_hosting_preserves_bind_and_certificate_options(self):
        with patch.object(SERVER["uvicorn"], "run") as run:
            SERVER["run_server_transport"](
                self.server,
                transport="streamable-http",
                host="0.0.0.0",
                port=8765,
                allowed_hosts="*",
                force_host_header="localhost:8765",
                https_enabled=True,
                tls_cert_file="/tmp/cert.pem",
                tls_key_file="/tmp/key.pem",
            )
        app = run.call_args.args[0]
        self.assertIsInstance(app, SERVER["_HostHeaderRewriteApp"])
        self.assertEqual(
            run.call_args.kwargs,
            {
                "host": "0.0.0.0",
                "port": 8765,
                "ssl_certfile": "/tmp/cert.pem",
                "ssl_keyfile": "/tmp/key.pem",
            },
        )


if __name__ == "__main__":
    unittest.main()
