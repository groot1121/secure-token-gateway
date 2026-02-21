import { useEffect } from "react";
import axios from "axios";
import { signMessage } from "../utils/crypto";

const API = "http://localhost:8000";

function decodeJwt(token) {
  const payload = token.split(".")[1];
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + (4 - (base64.length % 4)) % 4,
    "="
  );
  return JSON.parse(atob(padded));
}

export default function useAutoRotate() {
  useEffect(() => {
    let interval;

    async function checkAndRotate() {
      const token = localStorage.getItem("access_token");
      const privateKey = window.__PRIVATE_KEY__;

      if (!token || !privateKey) return;

      const payload = decodeJwt(token);

      const now = Math.floor(Date.now() / 1000);
      const lifetime = payload.exp - payload.iat;
      const elapsed = now - payload.iat;

      const rotationThreshold = lifetime * 0.8;

      if (elapsed >= rotationThreshold) {
        try {
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

          localStorage.setItem("access_token", res.data.access_token);
          console.log("🔁 Token auto-rotated");
        } catch (err) {
          console.error("Auto rotation failed", err);
        }
      }
    }

    interval = setInterval(checkAndRotate, 10000); // check every 10s

    return () => clearInterval(interval);
  }, []);
}