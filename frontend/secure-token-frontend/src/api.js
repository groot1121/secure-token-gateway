import axios from "axios";

const API = axios.create({
  baseURL: "http://127.0.0.1:8000",
});

// REGISTER DEVICE
export async function registerDevice(user_id, device_id, public_key) {
  const res = await API.post("/register-device", {
    user_id,
    device_id,
    public_key,
  });
  return res.data;
}

// REQUEST CHALLENGE
export async function requestChallenge(user_id, device_id) {
  const res = await API.post("/challenge", null, {
    params: { user_id, device_id },
  });
  return res.data;
}

// VERIFY CHALLENGE
export async function verifyChallenge(user_id, device_id, signature) {
  const res = await API.post("/verify-challenge", {
    user_id,
    device_id,
    signature,
  });
  return res.data;
}

// ISSUE TOKEN
export async function issueToken(user_id, device_id) {
  const res = await API.post("/issue-token", null, {
    params: { user_id, device_id },
  });
  return res.data;
}

// ACCESS PROTECTED
export async function accessProtected(token, signature) {
  const res = await API.get("/protected", {
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Pop-Signature": signature,
    },
  });
  return res.data;
}