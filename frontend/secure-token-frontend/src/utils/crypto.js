// Generate RSA key pair
export async function generateKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
}

// Export public key to PEM
export async function exportPublicKey(key) {
  const spki = await window.crypto.subtle.exportKey("spki", key);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64
    .match(/.{1,64}/g)
    .join("\n")}\n-----END PUBLIC KEY-----`;
}

// Sign RAW BYTES (for challenge + protected PoP)
export async function signRawBytes(privateKey, rawBytes) {
  const signature = await window.crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    rawBytes
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// Helper to sign text
export async function signText(privateKey, text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  return signRawBytes(privateKey, data);
}