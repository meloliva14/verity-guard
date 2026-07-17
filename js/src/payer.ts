/**
 * x402 payer — a wallet-holding `fetch` that settles VerityLayer's paid routes.
 *
 * The base package is keyless by design and holds no wallet. This module is the opt-in
 * money path, and it exists because the advice we shipped instead — "wrap fetch yourself
 * with x402-fetch" — was wrong three times over. All three verified against the live
 * engine, not inferred:
 *
 *  1. WRONG PACKAGE. `x402-fetch` (unscoped, latest 1.2.0) speaks x402 **v1**: it reads the
 *     challenge from the response BODY. Our engine speaks **v2** (x402 2.15.0), which puts
 *     the challenge in the base64 `payment-required` HEADER and leaves the body `{}`. So
 *     the documented one-liner didn't return a verdict, or a 402 — it threw
 *     `TypeError: Cannot read properties of undefined (reading 'map')`. The v2 line is
 *     `@x402/fetch` (scoped, 2.x). This is not our engine being exotic: of nine live x402
 *     sellers probed, seven serve the v2 header ONLY and none serve v1 alone.
 *  2. UNPAYABLE TIERS. x402-fetch's `maxValue` defaults to $0.10 — below our `verify`
 *     default tier ($0.25) and pro ($0.35). Only the $0.02 tier fit under it, which is
 *     exactly why this went unnoticed.
 *  3. UNPINNED CHAIN. Pinning a *signer* to Base does not pin the *payment*. The v1
 *     selector prefers the signer's network but falls back to whatever the 402 offers, and
 *     then signs it: a Base signer handed a polygon challenge emits a real polygon USDC
 *     authorization (the header reads `network=polygon`). A wallet its holder believed was
 *     Base-only, exposed on any chain the counterparty names.
 *
 * (2) and (3) are only reachable because the endpoint is not a trust anchor:
 * VERITY_ENGINE_URL / VERITY_SUITE_URL are env-overridable, and DNS/TLS interception is
 * real. So this payer treats the 402 as untrusted input: it caps the spend and pins the
 * chain, then signs. Mirrors `verity_guard.payer` on the Python side deliberately — the
 * same guarantees in both languages, or the guarantee is a language-specific accident.
 */

/** v2 network identifiers are CAIP-2. Base mainnet. */
export const BASE_MAINNET = "eip155:8453";

/** Native USDC on Base — the only asset VerityLayer ever prices in, and the only one we sign for. */
export const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/** ~3x our priciest tier ($0.35): room for every real call, a hard stop far below a drain. */
export const DEFAULT_MAX_PRICE_USDC = "1.00";

const USDC_DECIMALS = 6;

/**
 * Dollars -> atomic USDC, without float. `0.1 * 10**6` is 100000.00000000001 in binary
 * floating point; money conversions do not get to be approximately right.
 */
export function atomicUsdc(price: string | number): bigint {
  const s = String(price).trim().replace(/^\$/, "");
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`not a USDC amount: ${JSON.stringify(price)}`);
  const [whole, frac = ""] = s.split(".");
  if (frac.length > USDC_DECIMALS) throw new Error(`USDC has ${USDC_DECIMALS} decimals; got ${s}`);
  return BigInt(whole + frac.padEnd(USDC_DECIMALS, "0"));
}

/** v2 names the price `amount`; v1 named it `maxAmountRequired`. Read whichever is present. */
function requiredAmount(r: any): bigint | null {
  const raw = r?.amount ?? r?.maxAmountRequired;
  try {
    return raw === undefined || raw === null ? null : BigInt(raw);
  } catch {
    return null;
  }
}

export interface PayerOptions {
  /** The chain this wallet may pay on. Anything else is refused, not signed. */
  network?: string;
  /** The assets this wallet may pay in. Defaults to USDC on Base — the only thing we price in. */
  assets?: string[];
  /** Hard per-call ceiling in USDC. A 402 naming more is refused before any signature. */
  maxPriceUsdc?: string | number;
  /** The fetch to wrap. Defaults to the global. */
  fetch?: typeof fetch;
}

/**
 * Refuse anything above `cap`.
 *
 * A policy filters; it does not throw. An empty result means "nothing here is payable",
 * which the client surfaces as a failure to select — the payment simply never happens.
 * An unreadable amount is refused too: a price we cannot parse is not a price we can
 * agree to.
 */
function maxAmountPolicy(cap: bigint) {
  return (_version: number, requirements: any[]) =>
    (requirements ?? []).filter((r) => {
      const amt = requiredAmount(r);
      return amt !== null && amt <= cap;
    });
}

/** Refuse every chain but `network`. The signer's chain is a preference; this is a boundary. */
function networkPinPolicy(network: string) {
  return (_version: number, requirements: any[]) =>
    (requirements ?? []).filter((r) => r?.network === network);
}

/**
 * Refuse every asset but `assets`.
 *
 * Without this, the cap is a number with no unit. `maxAmountPolicy` compares raw minor units
 * against a ceiling computed in USDC's 6 decimals — so a 402 on the PINNED chain naming a
 * different EIP-3009 token slips a much larger transfer under the same integer: cbBTC has 8
 * decimals, so `amount: 1000000` reads as "$1.00" to the cap and means 0.01 BTC. The wallet
 * must actually hold that token for it to land (a USDC-only wallet is unaffected), but the
 * README states the guarantee unconditionally — "a hostile 402 can't name its own price" — and
 * a cap that can be denominated by the counterparty is not a cap. Pin the unit.
 */
function assetPinPolicy(assets: string[]) {
  const allowed = new Set(assets.map((a) => a.toLowerCase()));
  return (_version: number, requirements: any[]) =>
    (requirements ?? []).filter((r) => typeof r?.asset === "string" && allowed.has(r.asset.toLowerCase()));
}

/**
 * A `fetch` that settles VerityLayer's 402s from `privateKey`, capped and chain-pinned.
 *
 * ```ts
 * import { VerityClient } from "@veritylayer/guard";
 * import { x402Payer } from "@veritylayer/guard/payer";
 *
 * const v = new VerityClient({ fetch: await x402Payer(process.env.WALLET_KEY!) });
 * const res = await v.verify("The Eiffel Tower is in Paris.");   // $0.25, actually settles
 * ```
 *
 * Requires the optional peers `@x402/fetch`, `@x402/evm`, and `viem`; the base install
 * stays keyless and fetch-only.
 */
export async function x402Payer(
  privateKey: string,
  { network = BASE_MAINNET, assets = [USDC_BASE], maxPriceUsdc = DEFAULT_MAX_PRICE_USDC, fetch: baseFetch }: PayerOptions = {},
): Promise<typeof fetch> {
  const cap = atomicUsdc(maxPriceUsdc);
  const { wrapFetchWithPayment, x402Client, ExactEvmScheme, toClientEvmSigner, privateKeyToAccount } =
    await loadX402();

  const account = privateKeyToAccount(normalizeKey(privateKey));
  const client = new x402Client()
    // v2 only. `registerV1` is deliberately NOT called: it would opt this key into legacy
    // chains whose challenges ride in the body, which is precisely how a Base-pinned wallet
    // ends up signing someone else's chain.
    .register(network, new ExactEvmScheme(toClientEvmSigner(account)))
    .registerPolicy(networkPinPolicy(network))
    // Asset BEFORE amount: the cap is denominated in USDC's 6 decimals, so it only means
    // anything once the asset is pinned.
    .registerPolicy(assetPinPolicy(assets))
    .registerPolicy(maxAmountPolicy(cap));

  return wrapFetchWithPayment(baseFetch ?? fetch, client) as typeof fetch;
}

/** The address that will pay — so you can fund it, or check what you just wired up. */
export async function walletAddress(privateKey: string): Promise<string> {
  const { privateKeyToAccount } = await loadX402();
  return privateKeyToAccount(normalizeKey(privateKey)).address;
}

function normalizeKey(k: string): `0x${string}` {
  const s = (k ?? "").trim();
  if (!s) throw new Error("x402Payer: no private key given");
  return (s.startsWith("0x") ? s : `0x${s}`) as `0x${string}`;
}

async function loadX402(): Promise<any> {
  try {
    const [fetchMod, evmMod, viemMod] = await Promise.all([
      import("@x402/fetch" as string),
      import("@x402/evm" as string),
      import("viem/accounts" as string),
    ]);
    return {
      wrapFetchWithPayment: fetchMod.wrapFetchWithPayment,
      x402Client: fetchMod.x402Client,
      ExactEvmScheme: evmMod.ExactEvmScheme,
      toClientEvmSigner: evmMod.toClientEvmSigner,
      privateKeyToAccount: viemMod.privateKeyToAccount,
    };
  } catch {
    throw new Error(
      "The x402 payer needs its optional peers. Install them:\n" +
        "  npm install @x402/fetch @x402/evm viem\n" +
        "Note: the unscoped `x402-fetch` package is the OLD v1 protocol client and cannot " +
        "read VerityLayer's v2 challenge (it looks for the requirements in the response " +
        "body; v2 puts them in the `payment-required` header). Use the scoped @x402/* line.\n" +
        "The base @veritylayer/guard install is deliberately keyless and holds no wallet.",
    );
  }
}
