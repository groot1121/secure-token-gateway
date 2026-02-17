// src/components/IssueToken.jsx

import { useState } from "react";
import axios from "axios";

const API = "http://localhost:8000";

export default function IssueToken() {
  const [status, setStatus] = useState("");

  async function handleIssue() {
    try {
      const userId = localStorage.getItem("user_id");
      const deviceId = localStorage.getItem("device_id");

      if (!userId || !deviceId) {
        setStatus("❌ Device not registered");
        return;
      }

      setStatus("Issuing token...");

      const res = await axios.post(`${API}/issue-token`, null, {
        params: {
          user_id: userId,
          device_id: deviceId,
        },
      });

      localStorage.setItem("access_token", res.data.access_token);
      setStatus("✅ Token issued");
    } catch (e) {
      console.error(e);
      setStatus("❌ Token issue failed");
    }
  }

  return (
    <div style={{ padding: 20 }}>
      <h2>Issue Token</h2>
      <button onClick={handleIssue}>Issue Token</button>
      <p>{status}</p>
    </div>
  );
}
