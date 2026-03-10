import { useState } from "react";

import {
  generateKeyPair,
  exportPublicKey,
  signRawBytes,
  signText
} from "../utils/crypto";

import {
  registerDevice,
  requestChallenge,
  verifyChallenge,
  issueToken,
  accessProtected
} from "../api/gateway";

export default function ControlPanel() {

  const [privateKey, setPrivateKey] = useState(null);
  const [token, setToken] = useState(null);
  const [status, setStatus] = useState("");

  const user = "testuser";
  const device = "device1";

  // =========================
  // FULL AUTH FLOW
  // =========================

  async function handleFullFlow() {

    try {

      setStatus("Generating keys...");

      const keyPair = await generateKeyPair();
      setPrivateKey(keyPair.privateKey);

      const publicPem = await exportPublicKey(keyPair.publicKey);

      setStatus("Registering device...");
      await registerDevice(user, device, publicPem);

      setStatus("Requesting challenge...");
      const challengeRes = await requestChallenge(user, device);

      const challenge =
        challengeRes.data?.challenge || challengeRes.challenge;

      // decode base64 challenge
      const rawBytes = Uint8Array.from(
        atob(challenge),
        c => c.charCodeAt(0)
      );

      setStatus("Signing challenge...");

      const signature = await signRawBytes(
        keyPair.privateKey,
        rawBytes
      );

      setStatus("Verifying challenge...");

      await verifyChallenge(user, device, signature);

      setStatus("Issuing token...");

      const tokenRes = await issueToken(user, device);

      const newToken =
        tokenRes.data?.access_token || tokenRes.access_token;

      setToken(newToken);

      setStatus("Secure flow completed 🔐");

    } catch (err) {

      console.error(err);
      setStatus("Secure flow failed ❌");

    }

  }

  // =========================
  // ACCESS PROTECTED
  // =========================

  async function handleProtected() {

    try {

      if (!token || !privateKey) {
        setStatus("Run secure flow first");
        return;
      }

      const payload = JSON.parse(atob(token.split(".")[1]));

      const message = `ACCESS:${payload.jti}`;

      const signature = await signText(privateKey, message);

      await accessProtected(token, signature);

      setStatus("Protected resource accessed ✅");

    } catch (err) {

      console.error(err);
      setStatus("Protected access failed ❌");

    }

  }

  // =========================
  // LOGOUT
  // =========================

  function logout() {

    localStorage.removeItem("access_token");

    window.location.href = "/";

  }

  // =========================
  // UI
  // =========================

  return (

    <div className="mt-8 p-6 bg-black/40 rounded-xl border border-blue-800">

      <h2 className="text-xl font-semibold mb-4 text-cyan-400">
        🔐 Interactive Secure Client
      </h2>

      <div className="flex gap-4">

        <button
          onClick={handleFullFlow}
          className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded"
        >
          Run Secure Flow
        </button>

        <button
          onClick={handleProtected}
          className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded"
        >
          Access Protected
        </button>

        <button
          onClick={logout}
          className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded"
        >
          Logout
        </button>

      </div>

      <div className="mt-4 text-sm text-gray-300">
        {status}
      </div>

    </div>

  );

}