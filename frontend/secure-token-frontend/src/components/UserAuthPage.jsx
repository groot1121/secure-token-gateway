import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

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

const API = "http://127.0.0.1:8000";

export default function UserAuthPage(){

  const navigate = useNavigate();

  const [username,setUsername] = useState("");
  const [password,setPassword] = useState("");

  const [privateKey,setPrivateKey] = useState(null);
  const [token,setToken] = useState(null);

  const [status,setStatus] = useState("");
  const [loading,setLoading] = useState(false);

  const [device] = useState("device-" + crypto.randomUUID());

  useAutoRotate(token, privateKey, setToken);

  // MATRIX BACKGROUND EFFECT
  useEffect(()=>{

    const canvas = document.getElementById("matrix");

    if(!canvas) return;

    const ctx = canvas.getContext("2d");

    canvas.height = window.innerHeight;
    canvas.width = window.innerWidth;

    const letters = "01SECUREGATEWAYCYBER";
    const fontSize = 14;
    const columns = canvas.width / fontSize;

    const drops = [];

    for(let x = 0; x < columns; x++){
      drops[x] = 1;
    }

    function draw(){

      ctx.fillStyle = "rgba(0,0,0,0.05)";
      ctx.fillRect(0,0,canvas.width,canvas.height);

      ctx.fillStyle = "#0f0";
      ctx.font = fontSize + "px monospace";

      for(let i = 0; i < drops.length; i++){

        const text = letters[Math.floor(Math.random()*letters.length)];

        ctx.fillText(text,i*fontSize,drops[i]*fontSize);

        if(drops[i]*fontSize > canvas.height && Math.random() > 0.975){
          drops[i] = 0;
        }

        drops[i]++;

      }

    }

    const interval = setInterval(draw,33);

    return ()=>clearInterval(interval);

  },[]);

  async function registerUser(){

    try{

      setLoading(true);

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
    finally{
      setLoading(false);
    }

  }

  async function startAuth(){

    try{

      setLoading(true);
      setStatus("Initializing Zero‑Trust authentication...");

      await axios.post(`${API}/login`,{
        username,
        password
      });

      const keyPair = await generateKeyPair();
      setPrivateKey(keyPair.privateKey);

      const publicKeyPem = await exportPublicKey(keyPair.publicKey);

      setStatus("Registering device identity...");

      await registerDevice(username,device,publicKeyPem);

      const challengeRes = await requestChallenge(username,device);

      const challenge =
        challengeRes.data?.challenge || challengeRes.challenge;

      const rawBytes = Uint8Array.from(
        atob(challenge),
        c=>c.charCodeAt(0)
      );

      const signature = await signRawBytes(
        keyPair.privateKey,
        rawBytes
      );

      setStatus("Verifying device proof‑of‑possession...");

      await verifyChallenge(username,device,signature);

      const tokenRes = await issueToken(username,device);

      const newToken =
        tokenRes.data?.access_token || tokenRes.access_token;

      setToken(newToken);

      localStorage.setItem("access_token",newToken);

      const payload = JSON.parse(atob(newToken.split(".")[1]));

      if(payload.role === "admin"){
        navigate("/dashboard");
      }else{
        navigate("/welcome");
      }

    }
    catch(err){

      console.error(err);
      setStatus("Authentication failed");

    }
    finally{
      setLoading(false);
    }

  }

  async function accessAPI(){

    if(!token || !privateKey){
      setStatus("Login first");
      return;
    }

    try{

      const payload = JSON.parse(atob(token.split(".")[1]));

      const message = `ACCESS:${payload.jti}`;

      const signature = await signText(privateKey,message);

      const res = await accessProtected(token,signature);

      setStatus(res.data.message);

    }
    catch(err){

      console.error(err);
      setStatus("Protected request failed");

    }

  }

  return(

    <div className="min-h-screen flex items-center justify-center bg-black text-white relative overflow-hidden">

      {/* MATRIX BACKGROUND */}

      <canvas
        id="matrix"
        className="absolute inset-0 opacity-30"
      />

      {/* LOGIN CARD */}

      <div className="relative z-10 bg-white/5 backdrop-blur-xl border border-cyan-500/30 p-10 rounded-xl w-[420px] shadow-2xl">

        <h2 className="text-3xl font-bold mb-6 text-center text-cyan-400">
          🔐 Secure Gateway
        </h2>

        <p className="text-center text-gray-400 mb-6 text-sm">
          Zero‑Trust Authentication Portal
        </p>

        <input
          placeholder="Username"
          value={username}
          onChange={(e)=>setUsername(e.target.value)}
          className="w-full mb-4 px-4 py-3 rounded bg-black/40 border border-cyan-700 focus:outline-none focus:border-cyan-400"
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e)=>setPassword(e.target.value)}
          className="w-full mb-6 px-4 py-3 rounded bg-black/40 border border-cyan-700 focus:outline-none focus:border-cyan-400"
        />

        <button
          onClick={startAuth}
          disabled={loading}
          className="w-full bg-cyan-500 hover:bg-cyan-600 py-3 rounded mb-4 font-semibold transition-all duration-300 shadow-lg shadow-cyan-500/30"
        >
          {loading ? "Authenticating..." : "Secure Login"}
        </button>

        <button
          onClick={registerUser}
          className="w-full bg-gray-700 hover:bg-gray-800 py-3 rounded mb-4"
        >
          Register User
        </button>

        <button
          onClick={accessAPI}
          className="w-full bg-green-600 hover:bg-green-700 py-3 rounded"
        >
          Access Protected API
        </button>

        <div className="mt-6 text-center text-xs text-gray-400">
          {status}
        </div>

      </div>

    </div>

  );

}