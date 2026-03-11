🛡 Secure Token Gateway SOC
A Zero‑Trust Authentication Gateway with Proof‑of‑Possession (PoP) tokens, device authentication, replay attack protection, and a real‑time SOC dashboard.

This project demonstrates how modern authentication systems defend against:

Token theft

Replay attacks

Device impersonation

Suspicious login patterns

Geo anomalies

The system also includes a live Security Operations Center (SOC) dashboard to visualize threats in real time.

🚀 Features
🔐 Authentication & Security
Proof‑of‑Possession JWT tokens

Device‑bound authentication

Challenge‑response cryptographic verification

Replay attack detection

Token rotation

JTI token revocation

Redis‑based security controls

Device quarantine system

🧠 Threat Detection
Device risk scoring

Global threat level monitoring

Geo anomaly detection

Replay attack escalation

Automatic device quarantine

Risk decay system

📊 SOC Dashboard
Real‑time security visualization built with React.

Features include:

Threat meter

Attack map

Attack globe

Risk charts

Device table

Audit log feed

AI threat prediction panels

WebSocket live threat streaming

🧪 Attack Simulation
A Python attack client demonstrates real attack scenarios:

Device authentication flow

Replay attacks

Token rotation

Proof‑of‑Possession verification

Flood attack simulation

This allows the SOC dashboard to visualize live security events.

🏗 Architecture
                WebCrypto Client
                       │
                       │ Challenge–Response
                       ▼
            Secure Token Gateway (FastAPI)
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
      Redis                      MongoDB
 (Replay protection)        (Encrypted audit logs)
         │
         ▼
     Threat Engine
 (Risk scoring & detection)
         │
         ▼
     SOC Dashboard (React)
🔑 Authentication Flow
1. User logs in
2. Client generates device key pair
3. Device registers public key
4. Server issues cryptographic challenge
5. Client signs challenge
6. Server verifies signature
7. Server issues PoP JWT
8. Client accesses protected endpoints
🔁 Token Rotation
Tokens are automatically rotated within a dynamic time window.

10–15 second rotation window
If a token is reused or replayed:

Replay detected → Risk increases → Token revoked
🚨 Replay Attack Detection
The system prevents replay attacks using:

JTI token tracking

Redis replay counters

Signature verification

Token revocation

Example:

Access 1 → allowed
Access 2 → replay detected
Access 3 → token revoked
🌍 Geo Anomaly Detection
Every request checks the client IP location.

If login originates from an unusual region:

GEO_ANOMALY detected
Risk score increases
Threat level escalates
📡 Real‑Time SOC Dashboard
Security events are streamed using WebSockets.

The dashboard visualizes:

global threat level

device risk

replay attacks

token rotations

authentication events

Example event:

{
  "user_id": "testuser",
  "device_id": "device1",
  "action": "ACCESS_DENIED",
  "status": "REPLAY_JTI",
  "device_risk": 65,
  "device_threat": "HIGH"
}
🧪 Attack Simulation Client
Run the Python client to simulate attacks.

client/client_challenge_flow.py
This script performs:

1️⃣ Device registration
2️⃣ Challenge verification
3️⃣ Token issuance
4️⃣ Protected access
5️⃣ Token rotation
6️⃣ Replay attack simulation

⚙️ Running the Project
1️⃣ Clone the repository
git clone https://github.com/groot1121/secure-token-gateway.git

cd secure-token-gateway
2️⃣ Start Redis
redis-server
3️⃣ Start MongoDB
mongod
4️⃣ Start backend
python -m uvicorn app.main:app --reload
Server:

http://127.0.0.1:8000
5️⃣ Start frontend
cd frontend/secure-token-frontend

npm install
npm run dev
Frontend:

http://localhost:5173

Admin users can access the SOC dashboard.

Normal users see a secure welcome page.

📂 Project Structure
secure-token-gateway
│
├── app
│   ├── main.py
│   ├── auth_utils.py
│   ├── threat_engine.py
│   ├── replay_guard.py
│   ├── audit_logger.py
│
├── client
│   ├── client_challenge_flow.py
│   └── decrypt_audit_log.py
│
├── frontend
│   └── secure-token-frontend
│
├── keys
│
└── logs
🔐 Security Concepts Demonstrated
This project demonstrates several modern security concepts:

Zero‑Trust Authentication

Device‑bound tokens

Proof‑of‑Possession JWT

Replay attack detection

Token rotation

Threat scoring systems

SOC monitoring

Security event streaming

🧠 Technologies Used
Backend

FastAPI

Redis

MongoDB

JWT

RSA Cryptography

Frontend

React

Vite

TailwindCSS

WebSockets

D3 / Visualization libraries

Security

Proof‑of‑Possession tokens

Device cryptography

Replay protection

Threat detection engine

📈 Future Improvements
Possible future upgrades:

Docker deployment

Kubernetes support

SIEM integration

ML‑based anomaly detection

Multi‑region threat detection

OAuth / OpenID integration

📜 License
MIT License

⭐ Acknowledgment
This project was built as a cybersecurity architecture demonstration showing how modern authentication gateways detect and prevent token abuse attacks.





