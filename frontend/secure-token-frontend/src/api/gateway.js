import axios from "axios";

const API = "http://127.0.0.1:8000";

export function registerDevice(user, device, publicKey) {
  return axios.post(`${API}/register-device`, {
    user_id: user,
    device_id: device,
    public_key: publicKey
  });
}

export function requestChallenge(user, device) {
  return axios.post(`${API}/challenge`, null, {
    params: {
      user_id: user,
      device_id: device
    }
  });
}

export function verifyChallenge(user, device, signature) {
  return axios.post(`${API}/verify-challenge`, {
    user_id: user,
    device_id: device,
    signature: signature
  });
}

export function issueToken(user, device) {
  return axios.post(`${API}/issue-token`, null, {
    params: {
      user_id: user,
      device_id: device
    }
  });
}

export function accessProtected(token, signature) {
  return axios.get(`${API}/protected`, {
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Pop-Signature": signature
    }
  });
}

export function rotateToken(token, signature) {
  return axios.post(`${API}/rotate-token`, {}, {
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Pop-Signature": signature
    }
  });
}