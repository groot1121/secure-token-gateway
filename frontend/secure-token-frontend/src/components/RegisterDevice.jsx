// src/components/RegisterDevice.jsx

import { useState } from "react";
import axios from "axios";
import { generateRSAKeyPair } from "../utils/crypto";

const API = "http://localhost:8000";

export default function RegisterDevice() {
  const [userId, setUserId] = useState("g1");
  const [deviceId, setDeviceId] = useState("1234");
  const [status, setStatus] = useState("");

  async function handleRegister() {
  try {
    setStatus("Checking existing keys...");

    let privateKey = window.__PRIVATE_KEY__;
    let publicKeyPem = localStorage.getItem("publicKeyPem");

    if (!privateKey || !publicKeyPem) {
      setStatus("Generating keys...");

      const keys = await generateRSAKeyPair();

      localStorage.setItem("privateKeyPem", keys.privateKeyPem);
      localStorage.setItem("publicKeyPem", keys.publicKeyPem);

      window.__PRIVATE_KEY__ = keys.privateKey;
      privateKey = keys.privateKey;
      publicKeyPem = keys.publicKeyPem;
    }

    setStatus("Registering device...");

    await axios.post(`${API}/register-device`, null, {
      params: {
        user_id: userId,
        device_id: deviceId,
        public_key: publicKeyPem,
      },
    });

    setStatus("✅ Registered");
  } catch (e) {
    console.error(e);
    setStatus("❌ Failed");
  }
}

  return (
    <div style={{ padding: 20 }}>
      <h2>Register Device</h2>

      <div>
        <label>User ID</label>
        <br />
        <input
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
      </div>

      <div style={{ marginTop: 10 }}>
        <label>Device ID</label>
        <br />
        <input
          value={deviceId}
          onChange={(e) => setDeviceId(e.target.value)}
        />
      </div>

      <button style={{ marginTop: 20 }} onClick={handleRegister}>
        Register Device
      </button>

      <p style={{ marginTop: 15 }}>{status}</p>
    </div>
  );
}
