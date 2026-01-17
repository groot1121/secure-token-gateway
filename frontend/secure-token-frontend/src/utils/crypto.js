// src/utils/crypto.js

function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function stringToUint8Array(str) {
  return new TextEncoder().encode(str); // UTF‑8 ONLY
}

export async function signMessage(message) {
  const jwk = JSON.parse(localStorage.getItem("private_key"));
  if (!jwk) throw new Error("Private key not found");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const data = stringToUint8Array(message);

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    data
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}
