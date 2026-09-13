require("dotenv").config();
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { SSEClientTransport } = require("@modelcontextprotocol/sdk/client/sse.js");

const documentName = process.argv.slice(2).join(" ");
const serverUrl = process.env.MCP_SERVER_URL || "https://mcp.mstblockchain.com/sse";
const clientId = process.env.MCP_OAUTH_CLIENT_ID;
const clientSecret = process.env.MCP_OAUTH_CLIENT_SECRET;

if (!documentName) {
  console.error('Usage: node readDoc.js "document name"');
  process.exit(1);
}
if (!clientId || !clientSecret) {
  console.error("Missing MCP_OAUTH_CLIENT_ID / MCP_OAUTH_CLIENT_SECRET in mcp-client/.env");
  process.exit(1);
}

const auth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
const transport = new SSEClientTransport(new URL(serverUrl), {
  eventSourceInit: { headers: { Authorization: `Basic ${auth}` } },
  requestInit: { headers: { Authorization: `Basic ${auth}` } },
});
const client = new Client({ name: "mst-mcp-read-doc", version: "1.0.0" }, { capabilities: {} });

function isSuccessful(result) {
  return result && result.isError !== true;
}

async function main() {
  await client.connect(transport);
  console.log(`Connected to ${serverUrl}`);
  console.log(`Requested document: ${documentName}`);

  const candidates = ["document", "filename", "name"];
  for (const parameter of candidates) {
    const result = await client.callTool({
      name: "read_document",
      arguments: { [parameter]: documentName },
    });

    console.log(`\n--- tried parameter: ${parameter} ---`);
    console.log(JSON.stringify(result, null, 2));

    if (isSuccessful(result)) {
      console.log(`\nWORKED: read_document expects '${parameter}'`);
      await client.close();
      return;
    }
  }

  await client.close();
  throw new Error("None of document, filename, or name worked.");
}

main().catch((error) => {
  console.error("\nMCP read failed:");
  console.error(error.message || error);
  process.exitCode = 1;
});
