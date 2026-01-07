import { useState } from "react";
import {
  registerDevice,
  issueToken,
  accessProtected,
  rotateToken,
  getChallenge,
  verifyChallenge,
} from "./api";

export default function App() {
  const [userId, setUserId] = useState("g1");
  const [deviceId, setDeviceId] = useState("123");
  const [token, setToken] = useState(null);
  const [challenge, setChallenge] = useState(null);
  const [log, setLog] = useState([]);

  const addLog = (msg) =>
    setLog((l) => [...l, `[${new Date().toLocaleTimeString()}] ${msg}`]);

  const register = async () => {
    await registerDevice(userId, deviceId, "frontend-demo-public-key");
    addLog("✅ Device registered");
  };

  const issue = async () => {
    const r = await issueToken(userId, deviceId);
    setToken(r.access_token);
    addLog("✅ Token issued");
  };

  const protectedCall = async () => {
    await accessProtected(token, "invalid-demo-signature");
    addLog("🔐 Protected attempted");
  };

  const rotate = async () => {
    const r = await rotateToken(token);
    setToken(r.access_token);
    addLog("🔁 Token rotated");
  };

  const getCh = async () => {
    const c = await getChallenge();
    setChallenge(c);
    addLog(`🧩 Challenge issued`);
  };

  const verifyCh = async () => {
    await verifyChallenge(
      challenge.challenge_id,
      "invalid-demo-signature",
      userId,
      deviceId
    );
    addLog("✅ Challenge verified");
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>Secure Token Gateway – Full Demo</h2>

      <input value={userId} onChange={(e) => setUserId(e.target.value)} />
      <input value={deviceId} onChange={(e) => setDeviceId(e.target.value)} />

      <br /><br />

      <button onClick={register}>Register Device</button>
      <button onClick={issue}>Issue Token</button>
      <button onClick={protectedCall}>Access Protected</button>
      <button onClick={rotate}>Rotate Token</button>
      <button onClick={getCh}>Get Challenge</button>
      <button onClick={verifyCh} disabled={!challenge}>Verify Challenge</button>

      <pre style={{ marginTop: 20, background: "#eee", padding: 10 }}>
        {log.join("\n")}
      </pre>
    </div>
  );
}
