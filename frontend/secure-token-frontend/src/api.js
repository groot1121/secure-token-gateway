// src/api.js

const BASE_URL = "http://127.0.0.1:8000";

async function handleResponse(res) {
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || "API error");
  return data;
}

export async function registerDevice(userId, deviceId, publicKey) {
  const res = await fetch(
    `${BASE_URL}/register-device?user_id=${userId}&device_id=${deviceId}&public_key=${encodeURIComponent(publicKey)}`,
    { method: "POST" }
  );
  return handleResponse(res);
}

export async function issueToken(userId, deviceId) {
  const res = await fetch(
    `${BASE_URL}/issue-token?user_id=${userId}&device_id=${deviceId}`,
    { method: "POST" }
  );
  return handleResponse(res);
}

export async function accessProtected(token, popSignature) {
  const res = await fetch(`${BASE_URL}/protected`, {
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Pop-Signature": popSignature,
    },
  });
  return handleResponse(res);
}

export async function rotateToken(token) {
  const res = await fetch(`${BASE_URL}/rotate-token`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  return handleResponse(res);
}

export async function getChallenge() {
  const res = await fetch(`${BASE_URL}/challenge`);
  return handleResponse(res);
}

export async function verifyChallenge(challengeId, signature, userId, deviceId) {
  const res = await fetch(
    `${BASE_URL}/challenge-verify?challenge_id=${challengeId}&signature=${encodeURIComponent(signature)}&user_id=${userId}&device_id=${deviceId}`,
    { method: "POST" }
  );
  return handleResponse(res);
}
