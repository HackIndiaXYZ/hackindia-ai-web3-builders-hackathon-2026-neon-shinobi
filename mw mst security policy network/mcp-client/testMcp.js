/**
 * MST-MCP client — Phase 7.
 *
 * SCOPE, ON PURPOSE:
 * The official MST-MCP server exposes exactly three tools, all read-only:
 *   - list_documents
 *   - read_document
 *   - search_documents
 * There is no transaction/signing capability here. This client is for
 * looking up official docs on demand (e.g. by the AI agent, or by a
 * developer), NOT for executing anything on-chain. Do not extend this
 * to assume write capability exists — it doesn't.
 *
 * AUTH IS UNCONFIRMED (docs.mstblockchain.com blocks automated access,
 * so this wasn't verifiable ahead of time). This script tries HTTP Basic
 * Auth (base64 client_id:client_secret) first, since that's the most
 * common scheme for client-credential pairs like these. If the server
 * rejects it, the error message from the SSE handshake should indicate
 * why — report that back before we guess at a second scheme.
 */

require("dotenv").config();
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { SSEClientTransport } = require("@modelcontextprotocol/sdk/client/sse.js");

const SERVER_URL = process.env.MCP_SERVER_URL || "https://mcp.mstblockchain.com/sse";
const CLIENT_ID = process.env.MCP_OAUTH_CLIENT_ID;
const CLIENT_SECRET = process.env.MCP_OAUTH_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("Missing MCP_OAUTH_CLIENT_ID / MCP_OAUTH_CLIENT_SECRET in mcp-client/.env");
  process.exit(1);
}

function buildAuthHeaders() {
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  return {
    Authorization: `Basic ${basic}`,
    // Fallback candidates, kept here for quick manual testing if Basic auth
    // is rejected — uncomment ONE at a time, don't send multiple auth
    // schemes at once:
    // Authorization: `Bearer ${CLIENT_SECRET}`,
    // "X-Client-Id": CLIENT_ID,
    // "X-Client-Secret": CLIENT_SECRET,
  };
}

async function main() {
  const headers = buildAuthHeaders();

  const transport = new SSEClientTransport(new URL(SERVER_URL), {
    eventSourceInit: { headers },
    requestInit: { headers },
  });

  const client = new Client({ name: "mst-security-policy-agent", version: "1.0.0" }, { capabilities: {} });

  console.log(`Connecting to ${SERVER_URL} ...`);
  await client.connect(transport);
  console.log("Connected.\n");

  const tools = await client.listTools();
  console.log(
    "Available tools:",
    tools.tools.map((t) => t.name)
  );

  console.log("\n--- list_documents ---");
  const listResult = await client.callTool({ name: "list_documents", arguments: {} });
  console.log(JSON.stringify(listResult, null, 2));

  console.log("\n--- search_documents: 'testnet deployment' ---");
  const searchResult = await client.callTool({
    name: "search_documents",
    arguments: { query: "testnet deployment" },
  });
  console.log(JSON.stringify(searchResult, null, 2));

  await client.close();
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("\nMCP client failed:");
  console.error(err.message || err);
  if (err.cause) console.error("Cause:", err.cause);
  process.exitCode = 1;
});
