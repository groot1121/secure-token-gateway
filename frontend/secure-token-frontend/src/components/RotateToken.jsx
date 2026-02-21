import { useState } from "react";
import axios from "axios";
import { signMessage } from "../utils/crypto";

const API = "http://localhost:8000";

// Base64URL-safe decode
function decodeJwt(token) {
  const payload = token.split(".")[1];
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, "=");
  return JSON.parse(atob(padded));
}

export default function RotateToken() {
  const [status, setStatus] = useState("");

  async function handleRotate() {
    try {
      const token = localStorage.getItem("access_token");
      const privateKey = window.__PRIVATE_KEY__;

      if (!token || !privateKey) {
        alert("Missing token or private key");
        return;
      }

      setStatus("Rotating token...");

      const payload = decodeJwt(token);
      const message = `ROTATE:${payload.jti}`;

      const signature = await signMessage(message, privateKey);

      const res = await axios.post(
        `${API}/rotate-token`,
        {},
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "X-Pop-Signature": signature,
          },
        }
      );

      // ✅ Save new token
      localStorage.setItem("access_token", res.data.access_token);

      setStatus("✅ Token rotated successfully");
    } catch (err) {
      console.error(err);
      setStatus("❌ Rotation failed");
    }
  }

  return (
    <div style={{ padding: 20 }}>
      <h3>Rotate Token</h3>
      <button onClick={handleRotate}>Rotate</button>
      <p>{status}</p>
    </div>
  );
}