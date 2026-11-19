import { Signature, recoverAddress } from "ethers";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const DIGEST = /^0x[0-9a-fA-F]{64}$/u;
const KEY_VERSION = /^projects\/[^/]+\/locations\/[^/]+\/keyRings\/[^/]+\/cryptoKeys\/[^/]+\/cryptoKeyVersions\/[^/]+$/u;

function derLength(bytes, offset) {
  const first = bytes[offset];
  if (first === undefined) throw new Error("Cloud KMS signature is truncated DER");
  if ((first & 0x80) === 0) return { length: first, next: offset + 1 };
  const width = first & 0x7f;
  if (width === 0 || width > 2 || offset + 1 + width > bytes.length) throw new Error("Cloud KMS signature has an invalid DER length");
  let length = 0;
  for (let at = offset + 1; at <= offset + width; at += 1) length = (length << 8) | bytes[at];
  return { length, next: offset + 1 + width };
}

function derInteger(bytes, offset) {
  if (bytes[offset] !== 0x02) throw new Error("Cloud KMS signature is not a DER sequence of integers");
  const { length, next } = derLength(bytes, offset + 1);
  const end = next + length;
  if (length === 0 || end > bytes.length) throw new Error("Cloud KMS signature is truncated DER");
  let value = bytes.subarray(next, end);
  const prefixedPositive = value[0] === 0;
  if (prefixedPositive) value = value.subarray(1);
  if (value.length === 0 || value.length > 32 || (!prefixedPositive && (value[0] & 0x80) !== 0)) throw new Error("Cloud KMS signature has an invalid DER integer");
  return { value: `0x${Buffer.from(value).toString("hex").padStart(64, "0")}`, next: end };
}

function ethereumSignatureFromDer({ der, digest, expectedAddress }) {
  const bytes = Buffer.from(der, "base64");
  if (bytes[0] !== 0x30) throw new Error("Cloud KMS signature is not DER");
  const sequence = derLength(bytes, 1);
  if (sequence.next + sequence.length !== bytes.length) throw new Error("Cloud KMS signature has trailing or truncated DER bytes");
  const r = derInteger(bytes, sequence.next);
  const s = derInteger(bytes, r.next);
  if (s.next !== bytes.length) throw new Error("Cloud KMS signature has trailing DER fields");
  for (const yParity of [0, 1]) {
    const signature = Signature.from({ r: r.value, s: s.value, yParity }).serialized;
    if (recoverAddress(digest, signature).toLowerCase() === expectedAddress) return signature;
  }
  throw new Error("Cloud KMS signature does not recover to the configured Ethereum address");
}

/** A domain KMS key-version and Ethereum digest produce one recovered Ethereum signature. */
export function createCloudKmsSecp256k1Signer({ keyVersion, address, accessToken, fetchImpl = fetch }) {
  if (!KEY_VERSION.test(keyVersion ?? "")) throw new TypeError("Cloud KMS key version is required");
  if (!ADDRESS.test(address ?? "") || typeof accessToken !== "function" || typeof fetchImpl !== "function") throw new TypeError("Cloud KMS signer address, token provider, and fetch are required");
  const expectedAddress = address.toLowerCase();
  return Object.freeze({
    custody: "remote-cloud-kms-hsm",
    address: expectedAddress,
    keyVersion,
    async signDigest(digest) {
      if (!DIGEST.test(digest ?? "")) throw new TypeError("Ethereum digest must be bytes32");
      const response = await fetchImpl(`https://cloudkms.googleapis.com/v1/${keyVersion}:asymmetricSign`, {
        method: "POST",
        headers: { authorization: `Bearer ${await accessToken()}`, "content-type": "application/json" },
        body: JSON.stringify({ digest: { sha256: Buffer.from(digest.slice(2), "hex").toString("base64") } }),
      });
      const body = await response.json();
      if (!response.ok || typeof body.signature !== "string") throw new Error(`Cloud KMS asymmetricSign refused: ${body.error?.message ?? response.status}`);
      return ethereumSignatureFromDer({ der: body.signature, digest, expectedAddress });
    },
  });
}
