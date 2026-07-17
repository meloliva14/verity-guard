/**
 * The payer's two guarantees, proven by executing them against a hostile 402.
 *
 * The fake endpoint below speaks x402 **v2** — challenge in the base64 `payment-required`
 * header, empty body — because that is what our engine actually serves and what 7 of 9
 * live x402 sellers serve. An earlier draft of this file mocked a **v1** body instead; it
 * passed 15/15 against a protocol our own engine has never spoken, while the payer it was
 * "proving" died on the real thing with `TypeError: ... (reading 'map')`. A mock that
 * disagrees with production is not a test, it's a second bug.
 *
 * Every signature here comes from an UNFUNDED throwaway key, and both refusals are decided
 * before `createPaymentPayload`, so all of it is provable at $0 — including the controls,
 * since the signature is built locally and never submitted on-chain.
 *
 * The controls are the point. A harness that can only report "refused" would pass just as
 * happily with the payer deleted, so each guarantee is paired with a case that MUST sign.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { x402Payer, walletAddress, atomicUsdc, DEFAULT_MAX_PRICE_USDC, BASE_MAINNET } from "../dist/payer.js";

const DUMMY_KEY = "0x" + "5c".repeat(32); // unfunded; never a real wallet
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const USDC_POLYGON = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";
const POLYGON = "eip155:137";

/** A v2 402 that names whatever price/chain the test asks for — i.e. an untrusted endpoint. */
function hostileEndpoint() {
  let signed = null;
  const server = http.createServer((req, res) => {
    if (req.headers["payment-signature"]) {
      signed = req.headers["payment-signature"];
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ decision: "allow", risk: 0.1 }));
    }
    const q = new URL(req.url, "http://x").searchParams;
    const network = q.get("net") ?? BASE_MAINNET;
    const challenge = {
      x402Version: 2,
      error: "Payment required",
      resource: { url: "https://api.veritylayer.dev/verify", description: "VerityLayer", mimeType: "application/json" },
      accepts: [{
        scheme: "exact",
        network,
        asset: q.get("asset") ?? (network === POLYGON ? USDC_POLYGON : USDC_BASE),
        amount: q.get("atomic"),
        payTo: "0x000000000000000000000000000000000000dEaD",
        maxTimeoutSeconds: 300,
        extra: { name: "USD Coin", version: "2" },
      }],
    };
    res.writeHead(402, {
      "content-type": "application/json",
      "payment-required": Buffer.from(JSON.stringify(challenge)).toString("base64"),
    });
    res.end("{}"); // v2 leaves the body empty — exactly like api.veritylayer.dev
  });
  return {
    listen: () => new Promise((r) => server.listen(0, "127.0.0.1", r)),
    url: () => `http://127.0.0.1:${server.address().port}`,
    get signed() { return signed; },
    reset: () => { signed = null; },
    close: () => server.close(),
  };
}

/** @returns {Promise<{signed: boolean, error: string|null}>} */
async function call(ep, payer, { usd, net = BASE_MAINNET }) {
  ep.reset();
  const atomic = String(atomicUsdc(usd));
  try {
    await payer(`${ep.url()}/verify?atomic=${atomic}&net=${encodeURIComponent(net)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
  } catch (e) {
    return { signed: Boolean(ep.signed), error: e.message };
  }
  return { signed: Boolean(ep.signed), error: null };
}

test("atomicUsdc converts money exactly, and rejects nonsense", () => {
  assert.equal(atomicUsdc("1.00"), 1_000_000n);
  assert.equal(atomicUsdc("0.35"), 350_000n);
  assert.equal(atomicUsdc(0.1), 100_000n); // 0.1*10**6 in float is 100000.00000000001
  assert.equal(atomicUsdc("$0.02"), 20_000n);
  assert.throws(() => atomicUsdc("abc"));
  assert.throws(() => atomicUsdc("0.0000001")); // more precision than USDC has
});

test("walletAddress reports the address that will actually pay", async () => {
  assert.equal(await walletAddress(DUMMY_KEY), "0xb7cF38e4B36B03895E5580abE5b379E6739e8C4C");
  assert.equal(await walletAddress(DUMMY_KEY.slice(2)), "0xb7cF38e4B36B03895E5580abE5b379E6739e8C4C"); // 0x optional
});

test("CONTROL: a legitimate call on the pinned chain still settles", async () => {
  const ep = hostileEndpoint();
  await ep.listen();
  const payer = await x402Payer(DUMMY_KEY);
  const r = await call(ep, payer, { usd: "0.02" });
  ep.close();
  assert.equal(r.error, null);
  assert.equal(r.signed, true, "the payer must still pay — otherwise the refusals below prove nothing");
});

test("CONTROL: the default cap covers every real VerityLayer tier", async () => {
  // The bug this closes: the old advice (x402-fetch) defaulted to a $0.10 cap, so `verify`
  // ($0.25, our DEFAULT tier) and /verify/pro ($0.35) could never be bought at all.
  const ep = hostileEndpoint();
  await ep.listen();
  const payer = await x402Payer(DUMMY_KEY);
  for (const usd of ["0.02", "0.06", "0.08", "0.15", "0.20", "0.25", "0.35"]) {
    const r = await call(ep, payer, { usd });
    assert.equal(r.signed, true, `tier $${usd} must settle under the $${DEFAULT_MAX_PRICE_USDC} default cap`);
  }
  ep.close();
});

test("a 402 naming more than the cap is refused, with nothing signed", async () => {
  const ep = hostileEndpoint();
  await ep.listen();
  const payer = await x402Payer(DUMMY_KEY);
  const r = await call(ep, payer, { usd: "750.00" }); // the drain the Python reviewer built
  ep.close();
  assert.equal(r.signed, false, "signing $750 for a $0.02 call is the whole attack");
});

test("a per-call cap is honored (a $0.50 challenge against a $0.35 ceiling)", async () => {
  const ep = hostileEndpoint();
  await ep.listen();
  const payer = await x402Payer(DUMMY_KEY, { maxPriceUsdc: "0.35" });
  const over = await call(ep, payer, { usd: "0.50" });
  const under = await call(ep, payer, { usd: "0.35" });
  ep.close();
  assert.equal(over.signed, false, "$0.50 must not be signed against a $0.35 ceiling");
  assert.equal(under.signed, true, "the ceiling must not block the tier it was sized for");
});

test("a wrong-chain challenge is refused, not signed", async () => {
  // Unpinned, the v1 client signs a REAL polygon USDC authorization from a wallet whose
  // holder believed it was Base-only — the emitted header reads network=polygon. Verified.
  const ep = hostileEndpoint();
  await ep.listen();
  const payer = await x402Payer(DUMMY_KEY);
  const r = await call(ep, payer, { usd: "0.05", net: POLYGON }); // under the cap: only the pin can stop this
  ep.close();
  assert.equal(r.signed, false, "a Base-pinned wallet must never sign polygon");
});

test("an unparseable price is refused rather than guessed at", async () => {
  const ep = hostileEndpoint();
  await ep.listen();
  const payer = await x402Payer(DUMMY_KEY);
  ep.reset();
  let signed = false;
  try {
    // `amount` omitted entirely — a price we cannot read is not a price we can agree to.
    await payer(`${ep.url()}/verify?net=${encodeURIComponent(BASE_MAINNET)}`, { method: "POST", body: "{}" });
  } catch {}
  signed = Boolean(ep.signed);
  ep.close();
  assert.equal(signed, false);
});

test("a hostile ASSET on the pinned chain is refused, not signed", async () => {
  // The cap is a number with no unit until the asset is pinned. cbBTC has 8 decimals, so
  // `amount: 1000000` reads as "$1.00" to a USDC-denominated cap and means 0.01 BTC.
  // Same chain, under the cap: only the asset pin can stop this.
  const CBBTC = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf";
  const ep = hostileEndpoint();
  await ep.listen();
  const payer = await x402Payer(DUMMY_KEY);
  ep.reset();
  let threw = null;
  try {
    await payer(`${ep.url()}/verify?atomic=1000000&net=${encodeURIComponent(BASE_MAINNET)}&asset=${CBBTC}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}",
    });
  } catch (e) { threw = e.message; }
  const signed = Boolean(ep.signed);
  ep.close();
  assert.equal(signed, false, "a Base-pinned, $1.00-capped payer must not sign 0.01 BTC");
});

test("CONTROL: real USDC on the pinned chain still settles after the asset pin", async () => {
  const ep = hostileEndpoint();
  await ep.listen();
  const payer = await x402Payer(DUMMY_KEY);
  const r = await call(ep, payer, { usd: "0.25" });
  ep.close();
  assert.equal(r.signed, true, "the asset pin must not block our own USDC tiers");
});
