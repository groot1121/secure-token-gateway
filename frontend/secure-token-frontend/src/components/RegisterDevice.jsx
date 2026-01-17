// src/components/RegisterDevice.jsx

import api from "../api/gateway";
import { generateRSAKeyPair } from "../utils/crypto";

export default function RegisterDevice() {
  const register = async () => {
    const user_id = "user1";
    const device_id = crypto.randomUUID();

    const { publicKeyPem, privateKeyJwk } =
      await generateRSAKeyPair();

    // ✅ Store private key ONLY in browser
    localStorage.setItem("private_key", JSON.stringify(privateKeyJwk));
    localStorage.setItem("device_id", device_id);

    // ✅ SEND ONLY PUBLIC KEY PEM
    await api.post("/register-device", null, {
      params: {
        user_id,
        device_id,
        public_key: publicKeyPem,
      },
    });

    alert("Device registered ✅");
  };

  return <button onClick={register}>Register Device</button>;
}
