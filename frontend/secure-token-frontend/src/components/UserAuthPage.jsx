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
  useAutoRotate(token, privateKey, setToken);

  // =========================
  // REGISTER USER
  // =========================

  async function registerUser(){

    try{

      await axios.post(`${API}/register`,{
        username,
        password
      });

      setStatus("User registered successfully");

    }
    catch(err){

      console.error(err);
      setStatus("Registration failed");

    }

  }

  // =========================
  // LOGIN + WEBCRYPTO FLOW
  // =========================

  async function startAuth(){

    try{

      setStatus("Logging in...");

      await axios.post(`${API}/login`,{
        username,
        password
      });

      setStatus("Generating device keys...");

      const keyPair = await generateKeyPair();
      setPrivateKey(keyPair.privateKey);

      const publicKeyPem = await exportPublicKey(keyPair.publicKey);

      setStatus("Registering device...");

      await registerDevice(username, device, publicKeyPem);

      setStatus("Requesting challenge...");

      const challengeRes = await requestChallenge(username, device);

      const challenge =
        challengeRes.data?.challenge || challengeRes.challenge;

      if(!challenge){
        throw new Error("Challenge not received from server");
      }

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

      await verifyChallenge(username, device, signature);

      setStatus("Issuing token...");

      const tokenRes = await issueToken(username, device);

      const newToken =
        tokenRes.data?.access_token || tokenRes.access_token;

      setToken(newToken);

      setStatus("Login successful");

    }
    catch(err){

      console.error(err);
      setStatus("Authentication failed");

    }

  }

  // =========================
  // ACCESS PROTECTED API
  // =========================

  async function accessAPI(){

    try{

      if(!token){
        setStatus("Token missing");
        return;
      }

      const payload = JSON.parse(atob(token.split(".")[1]));

      const message = `ACCESS:${payload.jti}`;

      const signature = await signText(privateKey,message);

      const res = await accessProtected(token,signature);

      setStatus(res.data.message);

    }
    catch(err){

      console.error(err);

      setStatus("Protected access failed");

    }

  }

  // =========================
  // UI
  // =========================

  return(

    <div style={{padding:"40px"}}>

      <h2>Secure Gateway Login</h2>

      <input
        placeholder="username"
        value={username}
        onChange={(e)=>setUsername(e.target.value)}
      />

      <br/><br/>

      <input
        type="password"
        placeholder="password"
        value={password}
        onChange={(e)=>setPassword(e.target.value)}
      />

      <br/><br/>

      <button onClick={registerUser}>
        Register
      </button>

      <br/><br/>

      <button onClick={startAuth}>
        Login
      </button>

      <br/><br/>

      <button onClick={accessAPI}>
        Access Protected
      </button>

      <p>{status}</p>

    </div>

  );

}