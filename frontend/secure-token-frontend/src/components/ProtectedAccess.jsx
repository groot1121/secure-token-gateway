import { useState } from "react";
import axios from "axios";
import { signMessage } from "../utils/crypto";

// ✅ Base64URL-safe JWT decode
function decodeJwt(token) {
  const payload = token.split(".")[1];
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, "=");
  return JSON.parse(atob(padded));
}

export default function ProtectedAccess() {
  const [result, setResult] = useState("");

  async function handleAccess() {
    try {
      const token = localStorage.getItem("access_token");
      const privateKey = window.__PRIVATE_KEY__;

      if (!token || !privateKey) {
        alert("Missing token or private key");
        return;
      }

      // ✅ correct JWT payload
      const jwtPayload = decodeJwt(token);

      // ✅ EXACT canonical message
      const message = `ACCESS:${jwtPayload.jti}`;

      // ✅ Base64 signature
      const signature = await signMessage(message, privateKey);

      const res = await axios.get("http://localhost:8000/protected", {
        headers: {
          Authorization: `Bearer ${token}`,
          "X-Pop-Signature": signature,
        },
      });

      setResult(JSON.stringify(res.data, null, 2));
    } catch (err) {
      console.error(err);
      setResult("ACCESS DENIED");
    }
  }

  return (
    <div>
      <h3>Protected Resource</h3>
      <button onClick={handleAccess}>Access</button>
      <pre>{result}</pre>
    </div>
  );
}
