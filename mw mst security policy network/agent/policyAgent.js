/**
 * Security Policy Agent — Phase 6 (kept intentionally simple).
 *
 * IMPORTANT SAFETY BOUNDARY:
 * This agent only ever calls POST /policies (propose). It NEVER calls
 * the approve endpoint. Approval is a human authorization step, done
 * through the dashboard. This is a deliberate design constraint per
 * the project's authorization-boundary requirement, not a missing
 * feature — do not "complete" it by having the agent self-approve.
 *
 * Usage:
 *   BACKEND_URL=http://localhost:4000 node agent/policyAgent.js
 */

const fs = require("fs");
const path = require("path");
const { analyzeEvent, buildPolicyPayload } = require("./rules");

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:4000";

async function proposeToBackend(payload) {
  const res = await fetch(`${BACKEND_URL}/policies`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await res.json();
  if (!res.ok) {
    throw new Error(body.error || `Backend returned ${res.status}`);
  }
  return body;
}

async function main() {
  const eventsPath = path.join(__dirname, "events.sample.json");
  const events = JSON.parse(fs.readFileSync(eventsPath, "utf8"));

  console.log(`Security Policy Agent — analyzing ${events.length} observed event(s)\n`);

  for (const event of events) {
    console.log(`--- OBSERVE: ${event.eventId} ---`);
    console.log(`${event.sourceSegment} -> ${event.destSegment} (${event.protocol}/${event.port})`);
    console.log(`Source: ${event.observation}`);

    console.log(`ANALYZE / REASON:`);
    const analysis = analyzeEvent(event);

    if (!analysis) {
      console.log(`  No policy action warranted (routine/trusted traffic pattern).\n`);
      continue;
    }

    console.log(`  Decision: ${analysis.action} (risk: ${analysis.risk})`);
    console.log(`  Rationale: ${analysis.reason}`);

    const payload = buildPolicyPayload(event, analysis);
    console.log(`GENERATE POLICY PROPOSAL:`, payload);

    console.log(`SUBMIT: sending to backend for on-chain proposal (human approval still required)...`);
    try {
      const result = await proposeToBackend(payload);
      console.log(`  ✓ Proposed on-chain. policyId=${result.policyId}`);
      console.log(`  ✓ Propose tx: ${result.proposeTx}`);
      console.log(`REPORT: Awaiting human approval via dashboard before this policy becomes ACTIVE.\n`);
    } catch (err) {
      console.error(`  ✗ Failed to submit proposal: ${err.message}\n`);
    }
  }

  console.log("Agent run complete. No policies were approved automatically — that step is reserved for a human.");
}

main().catch((err) => {
  console.error("Agent crashed:", err);
  process.exitCode = 1;
});
