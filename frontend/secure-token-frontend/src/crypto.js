// src/crypto.js

let keyPair = null;

export async function generateKeyPair() {
  keyPair = await window.crypto.subtle.generateKey(
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

export async function exportPublicKeyPEM() {
  const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

export async function signMessage(message) {
  const sig = await window.crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    keyPair.privateKey,
    new TextEncoder().encode(message)
  );
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

export async function signBase64Nonce(b64) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const sig = await window.crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    keyPair.privateKey,
    bytes
  );
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
