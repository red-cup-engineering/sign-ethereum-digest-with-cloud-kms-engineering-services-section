import assert from "node:assert/strict";
import test from "node:test";
import { Signature, Wallet, keccak256, toUtf8Bytes } from "ethers";

import { createCloudKmsSecp256k1Signer } from "../src/index.mjs";

function derInteger(hex) {
  let bytes = Buffer.from(hex.slice(2), "hex");
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
  if ((bytes[0] & 0x80) !== 0) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
}

test("recovers an Ethereum signature from a Cloud KMS DER response", async () => {
  const wallet = Wallet.createRandom();
  const digest = keccak256(toUtf8Bytes("one canonical outer bundle"));
  const signed = Signature.from(wallet.signingKey.sign(digest));
  const r = derInteger(signed.r), s = derInteger(signed.s);
  const der = Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]).toString("base64");
  let request;
  const signer = createCloudKmsSecp256k1Signer({
    keyVersion: "projects/example/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1",
    address: wallet.address,
    accessToken: async () => "access-token",
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { ok: true, json: async () => ({ signature: der }) };
    },
  });

  assert.equal(await signer.signDigest(digest), signed.serialized);
  assert.match(request.url, /:asymmetricSign$/u);
  assert.equal(JSON.parse(request.options.body).digest.sha256, Buffer.from(digest.slice(2), "hex").toString("base64"));
});
