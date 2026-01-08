import { useState } from "react";
import "./index.css";
import ProjectOrb from "./components/ProjectOrb";
import {
  registerDevice,
  issueToken,
  rotateToken,
  getChallenge,
} from "./api";

export default function App() {
  const [userId, setUserId] = useState("g1");
  const [deviceId, setDeviceId] = useState("123");
  const [token, setToken] = useState(null);
  const [log, setLog] = useState([]);

  const addLog = (msg) =>
    setLog((l) => [...l, `[${new Date().toLocaleTimeString()}] ${msg}`]);

  return (
    <div style={styles.page}>
      <ProjectOrb />

      <h1 style={styles.title}>Zero‑Day Secure Token Gateway</h1>
      <p style={styles.subtitle}>
        Device‑bound tokens · PoP · Replay protection
      </p>

      <div style={styles.panel}>
        <input
          style={styles.input}
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="User ID"
        />
        <input
          style={styles.input}
          value={deviceId}
          onChange={(e) => setDeviceId(e.target.value)}
          placeholder="Device ID"
        />

        <div style={styles.buttons}>
          <button
            style={styles.btn}
            onClick={async () => {
              await registerDevice(userId, deviceId, "frontend-demo-key");
              addLog("✅ Device registered");
            }}
          >
            Register
          </button>

          <button
            style={styles.btnAccent}
            onClick={async () => {
              const r = await issueToken(userId, deviceId);
              setToken(r.access_token);
              addLog("🎟 Token issued");
            }}
          >
            Issue Token
          </button>

          <button
            style={styles.btn}
            disabled={!token}
            onClick={async () => {
              const r = await rotateToken(token);
              setToken(r.access_token);
              addLog("🔁 Token rotated");
            }}
          >
            Rotate
          </button>

          <button
            style={styles.btn}
            onClick={async () => {
              await getChallenge();
              addLog("🧩 Challenge issued");
            }}
          >
            Challenge
          </button>
        </div>
      </div>

      <pre style={styles.log}>{log.join("\n")}</pre>
    </div>
  );
}

const styles = {
  page: {
    minHeight: "100vh",
    padding: "40px 20px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
  },
  title: {
    margin: "10px 0 4px",
    letterSpacing: "0.5px",
  },
  subtitle: {
    color: "var(--muted)",
    marginBottom: 24,
  },
  panel: {
    background: "var(--panel)",
    borderRadius: 16,
    padding: 24,
    width: "100%",
    maxWidth: 420,
    boxShadow: "0 10px 40px rgba(0,0,0,0.5)",
  },
  input: {
    width: "100%",
    padding: 12,
    marginBottom: 12,
    background: "#0b0f1a",
    border: "1px solid #1f2547",
    borderRadius: 8,
    color: "var(--text)",
  },
  buttons: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: 10,
  },
  btn: {
    padding: 12,
    background: "#151b34",
    color: "var(--text)",
    border: "1px solid #1f2547",
    borderRadius: 10,
    cursor: "pointer",
  },
  btnAccent: {
    padding: 12,
    background: "linear-gradient(135deg, #6cf2c2, #7aa2ff)",
    color: "#000",
    border: "none",
    borderRadius: 10,
    fontWeight: 600,
    cursor: "pointer",
  },
  log: {
    marginTop: 20,
    maxWidth: 420,
    width: "100%",
    background: "#060814",
    padding: 16,
    borderRadius: 12,
    color: "#9aa4bf",
    fontSize: 12,
  },
};
