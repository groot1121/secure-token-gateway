import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "../dashboard.css";

export default function AdminDashboard() {

  const navigate = useNavigate();

  const [devices, setDevices] = useState([]);
  const [logs, setLogs] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [selectedToken, setSelectedToken] = useState(null);

  const [nonce, setNonce] = useState("");
  const [signature, setSignature] = useState("");
  const [tokenData, setTokenData] = useState(null);

  const API = "http://127.0.0.1:8000";

  // ================= LOGOUT =================

  const logout = () => {
    localStorage.clear();
    navigate("/");
  };

  // ================= INIT =================

  useEffect(() => {
    fetchDevices();
    decodeToken();
    connectWebSocket();

    setNonce(localStorage.getItem("challenge_nonce") || "");
    setSignature(localStorage.getItem("signature_output") || "");
  }, []);

  // ================= TOKEN DECODE =================

  const decodeToken = () => {

    const token = localStorage.getItem("access_token");
    if (!token) return;

    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      setTokenData(payload);
    } catch {
      console.warn("Invalid token");
    }

  };

  // ================= FETCH DEVICES =================

  const fetchDevices = async () => {

    try {

      const res = await fetch(`${API}/admin/devices?secret=superadmin123`);
      const data = await res.json();

      const seen = new Set();
      const unique = [];

      for (const d of data.devices) {

        if (!seen.has(d.device_id)) {
          seen.add(d.device_id);
          unique.push(d);
        }

      }

      setDevices(unique.slice(0, 10));

    } catch (err) {

      console.log(err);

    }

  };

  // ================= SESSION TRACKING =================

  const updateSession = (user, device, jti) => {

    const token = localStorage.getItem("access_token");

    const shortDevice = device?.slice(0, 16);
    const shortJti = jti?.slice(0, 8);

    setSessions(prev => {

      const existing = prev.find(s => s.device === device);

      if (existing) {

        return prev.map(s =>
          s.device === device
            ? {
                ...s,
                jti: shortJti,
                token,
                time: new Date().toLocaleTimeString()
              }
            : s
        );

      }

      return [
        ...prev,
        {
          user,
          device: shortDevice,
          jti: shortJti,
          token,
          time: new Date().toLocaleTimeString()
        }
      ];

    });

  };

  // ================= LOG SYSTEM =================

  const addLog = (type, msg) => {

    setLogs(prev => [
      { type, msg, time: new Date().toLocaleTimeString() },
      ...prev.slice(0, 20)
    ]);

  };

  // ================= WEBSOCKET =================

  const connectWebSocket = () => {

    const ws = new WebSocket("ws://127.0.0.1:8000/ws/audit");

    ws.onmessage = (event) => {

      const data = JSON.parse(event.data);

      if (data.action === "RISK_UPDATE") return;

      const user = data.user_id ?? "-";
      const device = data.device_id ?? "-";

      addLog("EVENT", `${data.action} | user=${user} device=${device}`);

      if (data.action === "CHALLENGE_ISSUED") {
        setNonce(data.payload?.nonce || "Challenge issued");
      }

      if (data.action === "CHALLENGE_VERIFIED") {
        setSignature(data.payload?.signature || "Signature verified");
      }

      if (data.action === "ISSUE_TOKEN") {
        if (data.payload?.jti) {
          updateSession(user, device, data.payload.jti);
        }
      }

      if (data.action === "TOKEN_ROTATED") {
        if (data.payload?.new_jti) {
          updateSession(user, device, data.payload.new_jti);
        }
      }

      if (data.action === "REGISTER_DEVICE") {
        fetchDevices();
      }

    };

    ws.onclose = () => setTimeout(connectWebSocket, 2000);

  };

  // ================= JWT VIEWER =================

  const renderJWTViewer = () => {

  if (!selectedToken) return null;

  const parts = selectedToken.split(".");
  const header = JSON.parse(atob(parts[0]));
  const payload = JSON.parse(atob(parts[1]));
  const signature = parts[2];

  return (

    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.85)",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        zIndex: 9999
      }}
      onClick={() => setSelectedToken(null)}
    >

      <div
        style={{
          width: "720px",
          maxHeight: "80vh",
          overflowY: "auto",
          background: "#020617",
          border: "1px solid #00ff9f",
          borderRadius: "8px",
          padding: "20px",
          color: "#00ff9f",
          fontFamily: "monospace"
        }}
        onClick={(e) => e.stopPropagation()}
      >

        <h2 style={{ marginBottom: "15px" }}>JWT Viewer</h2>

        <h3>Header</h3>
        <pre style={{ background: "#000", padding: "10px" }}>
{JSON.stringify(header, null, 2)}
        </pre>

        <h3>Payload</h3>
        <pre style={{ background: "#000", padding: "10px" }}>
{JSON.stringify(payload, null, 2)}
        </pre>

        <h3>Signature</h3>
        <pre style={{ background: "#000", padding: "10px", wordBreak: "break-all" }}>
{signature}
        </pre>

        <div style={{ marginTop: "15px" }}>

          <button
            onClick={() => navigator.clipboard.writeText(selectedToken)}
            style={{
              marginRight: "10px",
              padding: "6px 12px",
              background: "#00aaff",
              border: "none",
              borderRadius: "6px",
              cursor: "pointer"
            }}
          >
            Copy Token
          </button>

          <button
            onClick={() => setSelectedToken(null)}
            style={{
              padding: "6px 12px",
              background: "#ff4444",
              border: "none",
              borderRadius: "6px",
              color: "white",
              cursor: "pointer"
            }}
          >
            Close
          </button>

        </div>

      </div>

    </div>

  );
};
  // ================= UI =================

  return (

    <div className="dashboard">

      <div className="title">

        Secure Token Gateway SOC Dashboard

        <div style={{ float: "right" }}>

          <button
            onClick={() => navigate("/soc")}
            style={{
              marginRight: "10px",
              padding: "6px 14px",
              background: "#00ff9f",
              border: "none",
              borderRadius: "6px",
              cursor: "pointer"
            }}
          >
            SOC View
          </button>

          <button
            onClick={logout}
            style={{
              padding: "6px 14px",
              background: "#ff4444",
              border: "none",
              borderRadius: "6px",
              color: "white",
              cursor: "pointer"
            }}
          >
            Logout
          </button>

        </div>

      </div>

      {/* TOKEN SESSIONS */}

      <div className="panel">

        <h2>Active Token Sessions</h2>

        <table>

          <thead>
            <tr>
              <th>User</th>
              <th>Device</th>
              <th>Token ID</th>
              <th>Last Rotation</th>
            </tr>
          </thead>

          <tbody>

            {sessions.map((s, i) => (

              <tr key={i}>

                <td>{s.user}</td>
                <td>{s.device}</td>

                <td>

                  {s.jti}

                  <span
                    style={{
                      marginLeft: "6px",
                      cursor: "pointer",
                      color: "#00ffff"
                    }}
                    onClick={() => setSelectedToken(s.token)}
                  >
                    🔍
                  </span>

                </td>

                <td>{s.time}</td>

              </tr>

            ))}

          </tbody>

        </table>

      </div>

      {/* DEVICES */}

      <div className="panel">

        <h2>Registered Devices</h2>

        <table>

          <thead>
            <tr>
              <th>User</th>
              <th>Device</th>
              <th>Public Key</th>
            </tr>
          </thead>

          <tbody>

            {devices.map((d, i) => (

              <tr key={i}>
                <td>{d.user_id}</td>
                <td>{d.device_id}</td>
                <td style={{ fontSize: "11px" }}>
                  {d.public_key.slice(0, 70)}...
                </td>
              </tr>

            ))}

          </tbody>

        </table>

      </div>

      {/* CHALLENGE */}

      <div className="panel">

        <h2>Challenge Monitor</h2>

        <p><b>Nonce</b></p>
        <div className="challenge">{nonce}</div>

        <p><b>Signature</b></p>
        <div className="signature">{signature}</div>

      </div>

      {/* TOKEN INSPECTOR */}

      <div className="panel">

        <h2>JWT Token Inspector</h2>

        {tokenData && (
          <div className="token-box">
            <p>User: {tokenData.sub}</p>
            <p>Device: {tokenData.device_id}</p>
            <p>Token ID: {tokenData.jti}</p>
          </div>
        )}

      </div>

      {/* LOGS */}

      <div className="panel">

        <h2>Live Security Logs</h2>

        <div className="log-box">

          {logs.map((l, i) => (

            <div key={i}>
              <b>[{l.type}]</b> {l.msg} — {l.time}
            </div>

          ))}

        </div>

      </div>

      {renderJWTViewer()}

    </div>

  );

}