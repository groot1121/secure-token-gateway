import { useEffect } from "react";
import { signText } from "../utils/crypto";

export default function Welcome(){

  const user = localStorage.getItem("user");

  const API = "http://127.0.0.1:8000";

  // ================= LOGOUT =================

  const logout = () => {

    localStorage.removeItem("access_token");
    localStorage.removeItem("challenge_nonce");
    localStorage.removeItem("signature_output");
    localStorage.removeItem("user");
    sessionStorage.removeItem("privateKey");

    window.location.href="/";

  };

  // ================= TOKEN ROTATION =================

  useEffect(()=>{

    const rotateToken = async () => {

      const token = localStorage.getItem("access_token");
      const stored = sessionStorage.getItem("privateKey");

      if(!token || !stored) return;

      try{

        const jwk = JSON.parse(stored);

        const privateKey = await crypto.subtle.importKey(
          "jwk",
          jwk,
          {
            name:"RSASSA-PKCS1-v1_5",
            hash:"SHA-256"
          },
          true,
          ["sign"]
        );

        const payload = JSON.parse(atob(token.split(".")[1]));

        const jti = payload.jti;

        const message = `ROTATE:${jti}`;

        const signature = await signText(privateKey,message);

        await fetch(`${API}/rotate-token`,{
          method:"POST",
          headers:{
            "Authorization":`Bearer ${token}`,
            "X-Pop-Signature":signature
          }
        });

      }
      catch(err){
        console.log("Rotation failed:",err);
      }

    };

    // rotate every 10 seconds
    const interval = setInterval(rotateToken,10000);

    return () => clearInterval(interval);

  },[]);

  // ================= UI =================

  return(

    <div style={{
      padding:"40px",
      fontFamily:"monospace",
      background:"#020617",
      minHeight:"100vh",
      color:"#00ff9f"
    }}>

      <div style={{display:"flex",justifyContent:"space-between"}}>

        <h1>
🛡 Cryptographically Secured Access Token System for Zero‑Day Attack Prevention
</h1>

        <button
          onClick={logout}
          style={{
            padding:"6px 14px",
            background:"#ff4444",
            border:"none",
            borderRadius:"6px",
            color:"white",
            cursor:"pointer"
          }}
        >
          Logout
        </button>

      </div>

      <p>User: {user}</p>

      <p>This is a dummy user dashboard.</p>

      <div style={{
        marginTop:"30px",
        padding:"20px",
        background:"#111",
        color:"#00ff9f",
        borderRadius:"8px"
      }}>

        <p>Session Active</p>
        <p>Security Level: Normal</p>
        <p>Device Trusted</p>

      </div>

    </div>

  );

}