// src/components/ProtectedAccess.jsx
import axios from "axios";
import { signMessage } from "../utils/crypto";

export default function ProtectedAccess() {
  const access = async () => {
    const token = localStorage.getItem("access_token");
    if (!token) return alert("No token");

    // extract jti from JWT payload
    const payload = JSON.parse(atob(token.split(".")[1]));
    const jti = payload.jti;

    // 🔐 EXACT BACKEND MESSAGE
    const message = `ACCESS:${jti}`;
    const signature = await signMessage(message);

    const res = await axios.get("http://localhost:8000/protected", {
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Pop-Signature": signature,
      },
    });

    alert(res.data.message);
  };

  return <button onClick={access}>Access Protected</button>;
}
