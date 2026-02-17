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
      setStatus("Checking keys...");

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

      // ✅ SINGLE SOURCE OF TRUTH
      localStorage.setItem("user_id", userId);
      localStorage.setItem("device_id", deviceId);

      setStatus("✅ Device registered");
    } catch (e) {
      console.error(e);
      setStatus("❌ Registration failed");
    }
  }

  return (
    <div style={{ padding: 20 }}>
      <h2>Register Device</h2>

      <label>User ID</label>
      <input value={userId} onChange={(e) => setUserId(e.target.value)} />

      <br />

      <label>Device ID</label>
      <input value={deviceId} onChange={(e) => setDeviceId(e.target.value)} />

      <br />

      <button onClick={handleRegister}>Register Device</button>
      <p>{status}</p>
    </div>
  );
}
