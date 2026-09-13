const fs = require("fs");
const path = require("path");

const DATA_FILE = path.join(__dirname, "..", "data", "policies.json");

function readAll() {
  if (!fs.existsSync(DATA_FILE)) return {};
  const raw = fs.readFileSync(DATA_FILE, "utf8").trim();
  return raw ? JSON.parse(raw) : {};
}

function writeAll(data) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function savePolicy(policyId, record) {
  const all = readAll();
  all[policyId] = { ...(all[policyId] || {}), ...record };
  writeAll(all);
  return all[policyId];
}

function getPolicy(policyId) {
  const all = readAll();
  return all[policyId] || null;
}

function listPolicies() {
  const all = readAll();
  return Object.entries(all).map(([policyId, record]) => ({ policyId, ...record }));
}

module.exports = { savePolicy, getPolicy, listPolicies };
