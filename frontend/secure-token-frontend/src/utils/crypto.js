// src/utils/crypto.js

// Generate RSA key pair (Web Crypto)
export async function generateRSAKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  const publicKey = await window.crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  );
  const privateKey = await window.crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey
  );

  return {
    publicKeyPem: toPem(publicKey, "PUBLIC KEY"),
    privateKeyPem: toPem(privateKey, "PRIVATE KEY"),
    privateKey: keyPair.privateKey, // keep for signing
  };
}

// ✅ BASE64 signature (matches backend)
export async function signMessage(message, privateKey) {
  const encoded = new TextEncoder().encode(message);

  const signature = await window.crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    encoded
  );

  return arrayBufferToBase64(signature); // ✅ BASE64
}

// ---------- helpers ----------

function toPem(buffer, label) {
  const base64 = btoa(
    String.fromCharCode(...new Uint8Array(buffer))
  );
  const formatted = base64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----`;
}

function arrayBufferToBase64(buffer) {
  return btoa(
    String.fromCharCode(...new Uint8Array(buffer))
  );
}
