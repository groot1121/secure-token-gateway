import { useState } from "react";
import "../dashboard.css";

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

import useAutoRotate from "../hooks/useAutoRotate";

import axios from "axios";

const API = "http://127.0.0.1:8000";

export default function UserAuthPage() {

  const [username,setUsername] = useState("");
  const [password,setPassword] = useState("");

  const [privateKey,setPrivateKey] = useState(null);
  const [token,setToken] = useState(null);

  const [status,setStatus] = useState("");

  const [device] = useState("device-" + crypto.randomUUID());

  // 🔁 AUTO TOKEN ROTATION
  useAutoRotate(token,privateKey,setToken);

  // =========================
  // REGISTER USER
  // =========================

  async function registerUser(){

    try{

      await axios.post(`${API}/register`,{
        username,
        password
      });

      setStatus("✅ User registered successfully");

    }
    catch(err){

      console.error(err);
      setStatus("❌ Registration failed");

    }

  }

  // =========================
  // LOGIN + WEBCRYPTO FLOW
  // =========================

  async function startAuth(){

    try{

      setStatus("🔐 Logging in...");

      await axios.post(`${API}/login`,{
        username,
        password
      });

      // --------------------------
      // GENERATE DEVICE KEYS
      // --------------------------

      setStatus("🔑 Generating device keys...");

      const keyPair = await generateKeyPair();

      setPrivateKey(keyPair.privateKey);

      sessionStorage.setItem(
        "privateKey",
        JSON.stringify(
          await crypto.subtle.exportKey("jwk", keyPair.privateKey)
        )
      );

      const publicKeyPem = await exportPublicKey(
        keyPair.publicKey
      );

      // --------------------------
      // REGISTER DEVICE
      // --------------------------

      setStatus("📱 Registering device...");

      await registerDevice(
        username,
        device,
        publicKeyPem
      );

      // --------------------------
      // REQUEST CHALLENGE
      // --------------------------

      setStatus("📨 Requesting challenge...");

      const challengeRes = await requestChallenge(
        username,
        device
      );

      const challenge =
        challengeRes.data?.challenge ||
        challengeRes.challenge;

      if(!challenge){
        throw new Error("Challenge not received from server");
      }

      localStorage.setItem("challenge_nonce",challenge);

      // --------------------------
      // SIGN CHALLENGE
      // --------------------------

      const rawBytes = Uint8Array.from(
        atob(challenge),
        c => c.charCodeAt(0)
      );

      setStatus("✍️ Signing challenge...");

      const signature = await signRawBytes(
        keyPair.privateKey,
        rawBytes
      );

      localStorage.setItem(
        "signature_output",
        typeof signature === "string"
          ? signature
          : btoa(String.fromCharCode(...new Uint8Array(signature)))
      );

      // --------------------------
      // VERIFY CHALLENGE
      // --------------------------

      setStatus("✅ Verifying challenge...");

      await verifyChallenge(
        username,
        device,
        signature
      );

      // --------------------------
      // ISSUE TOKEN
      // --------------------------

      setStatus("🎟 Issuing token...");

      const tokenRes = await issueToken(
        username,
        device
      );

      const newToken =
        tokenRes.data?.access_token ||
        tokenRes.access_token;

      setToken(newToken);

      localStorage.setItem("access_token",newToken);
      localStorage.setItem("user",username);

      setStatus("✅ Login successful");

      // 🔴 REDIRECT AFTER AUTH
      if(username === "admin"){
        window.location.href="/dashboard";
      }else{
        window.location.href="/welcome";
      }

    }
    catch(err){

      console.error(err);

      setStatus("❌ Authentication failed");

    }

  }

  // =========================
  // ACCESS PROTECTED API
  // =========================

  async function accessAPI(){

    try{

      if(!token){
        setStatus("⚠ Token missing");
        return;
      }

      const payload = JSON.parse(
        atob(token.split(".")[1])
      );

      const message = `ACCESS:${payload.jti}`;

      const signature = await signText(
        privateKey,
        message
      );

      const res = await accessProtected(
        token,
        signature
      );

      setStatus(res.data.message);

    }
    catch(err){

      console.error(err);
      setStatus("❌ Protected access failed");

    }

  }

  // =========================
  // UI
  // =========================

  return (

    <div className="auth-container">

      <div className="auth-card">

        <h1 className="auth-title">
  🛡 Cryptographically Secured Access Token System for Zero‑Day Attack Prevention
</h1>

        <p className="auth-subtitle">
          SOC Authentication Portal
        </p>

        <input
          placeholder="Username"
          value={username}
          onChange={(e)=>setUsername(e.target.value)}
          className="auth-input"
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e)=>setPassword(e.target.value)}
          className="auth-input"
        />

        <div className="auth-buttons">

          <button
            onClick={registerUser}
            className="btn-secondary"
          >
            Register
          </button>

          <button
            onClick={startAuth}
            className="btn-primary"
          >
            Login
          </button>

        </div>

        <button
          onClick={accessAPI}
          className="btn-access"
        >
          Access Protected
        </button>

        <div className="status-box">

          <span className="status-label">
            Status:
          </span>

          <p>{status}</p>

        </div>

      </div>

    </div>

  );

}