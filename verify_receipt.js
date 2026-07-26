#!/usr/bin/env node
/**
 * Verify a VerityLayer signed receipt OFFLINE. Zero dependencies - Node's built-in crypto only.
 *
 *   node verify_receipt.js receipt.json pubkey.json
 *   node verify_receipt.js receipt.json pubkey.json --claim "the claim it should vouch for"
 *
 * Makes no network call and shares no code with the service that issues the receipts. If the
 * two agreed because they were the same code, that would prove nothing.
 *
 *   curl -o receipt.json https://api.veritylayer.dev/receipt/selftest
 *   curl -o pubkey.json  https://api.veritylayer.dev/.well-known/verity-pubkey.json
 *
 * Full spec: RECEIPTS.md in this repo.
 * Exit 0 = signature valid (and bound, if --claim given). Non-zero otherwise.
 */
const fs = require("fs");
const crypto = require("crypto");

/**
 * The exact bytes that were signed: sorted keys, no whitespace, `signature` excluded, UTF-8.
 *
 * JSON.stringify already renders integral numbers without a decimal point (1 -> "1", not
 * "1.0"), which is what the signer does - so this matches. It also emits non-ASCII literally,
 * matching ensure_ascii=false. Key order below is by code point via Array.sort()'s default
 * comparator on the code-unit level; identical for every field name in use.
 */
function canonicalBytes(receipt) {
  const body = {};
  for (const k of Object.keys(receipt).filter((k) => k !== "signature").sort()) body[k] = receipt[k];
  return Buffer.from(JSON.stringify(body), "utf8");
}

/** key_id is derived from the key, so you can confirm you hold the right one yourself. */
function deriveKeyId(publicKeyHex) {
  return "ed25519:" + crypto.createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex").slice(0, 16);
}

function verify(receipt, publicKeyHex) {
  for (const f of ["signature", "key_id"]) {
    if (typeof receipt[f] !== "string") return [false, `not a receipt: missing ${f}`];
  }
  const derived = deriveKeyId(publicKeyHex);
  if (receipt.key_id !== derived) {
    // Do NOT 'helpfully' fetch a key that works. That is the trust this file avoids.
    return [false, `wrong key: receipt signed by ${receipt.key_id}, you supplied ${derived}`];
  }
  try {
    // Wrap the raw 32-byte key as SPKI DER so crypto can read it; the prefix is the fixed
    // Ed25519 AlgorithmIdentifier.
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                               Buffer.from(publicKeyHex, "hex")]);
    const pub = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    const ok = crypto.verify(null, canonicalBytes(receipt), pub, Buffer.from(receipt.signature, "hex"));
    return ok ? [true, "signature valid"]
              : [false, "SIGNATURE INVALID - this content is not what was signed"];
  } catch (e) {
    return [false, `could not verify: ${e.message}`];
  }
}

/** A valid signature says WE SIGNED THIS. Not that it vouches for YOUR claim. */
function checkBinding(receipt, claim) {
  const want = crypto.createHash("sha256").update(Buffer.from(claim, "utf8")).digest("hex");
  return want === receipt.claim_sha256
    ? [true, "this receipt was issued for the claim you supplied"]
    : [false, "SIGNATURE VALID BUT FOR A DIFFERENT CLAIM - it does not vouch for the claim you supplied"];
}

function load(p) {
  const d = JSON.parse(fs.readFileSync(p, "utf8"));
  return d.sample_receipt || d.receipt || d;   // /receipt/selftest wraps it
}

function main(argv) {
  if (argv.length < 2) { console.log(require("fs").readFileSync(__filename, "utf8").split("*/")[0]); return 2; }
  const receipt = load(argv[0]);
  const pubHex = JSON.parse(fs.readFileSync(argv[1], "utf8")).public_key_hex;

  const [ok, why] = verify(receipt, pubHex);
  console.log(`signature : ${ok ? "VALID" : "INVALID"} - ${why}`);
  if (!ok) return 1;

  if (receipt.test === true) {
    console.log("warning   : this is a SELF-TEST receipt, not a paid verdict - it proves the " +
                "signing chain works and nothing about any real claim");
  }
  console.log(`verdict   : ${receipt.verdict}  (confidence ${receipt.confidence})`);
  console.log(`endpoint  : ${receipt.endpoint}   issued ${receipt.issued_at}`);

  const i = argv.indexOf("--claim");
  if (i !== -1) {
    const [bound, whyB] = checkBinding(receipt, argv[i + 1]);
    console.log(`binding   : ${bound ? "BOUND" : "NOT BOUND"} - ${whyB}`);
    if (!bound) return 1;
  } else {
    console.log('binding   : not checked - pass --claim "..." to confirm this receipt ' +
                "vouches for the claim you actually care about");
  }
  return 0;
}

process.exit(main(process.argv.slice(2)));
