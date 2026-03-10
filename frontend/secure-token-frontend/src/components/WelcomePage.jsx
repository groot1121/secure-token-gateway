import { useNavigate } from "react-router-dom";
import { accessProtected } from "../api/gateway";
import { signText } from "../utils/crypto";
import { useState } from "react";

export default function WelcomePage(){

  const navigate = useNavigate();

  const token = localStorage.getItem("access_token");

  const [status,setStatus] = useState("");

  let isAdmin = false;

  if(token){
    const payload = JSON.parse(atob(token.split(".")[1]));
    isAdmin = payload.role === "admin";
  }

  function logout(){

    localStorage.removeItem("access_token");
    window.privateKey = null;

    navigate("/");

  }

  function goDashboard(){
    navigate("/dashboard");
  }

  async function accessAPI(){

    try{

      const payload = JSON.parse(atob(token.split(".")[1]));

      const message = `ACCESS:${payload.jti}`;

      const signature = await signText(
        window.privateKey,
        message
      );

      const res = await accessProtected(token,signature);

      setStatus(res.data.message);

    }
    catch(err){

      console.error(err);
      setStatus("Protected access failed");

    }

  }

  return(

    <div className="min-h-screen bg-[#050816] text-white flex flex-col items-center justify-center">

      <h1 className="text-4xl font-bold mb-6">
        🔐 Secure Gateway
      </h1>

      <p className="mb-8 text-gray-400">
        Authentication successful
      </p>

      <div className="flex gap-6">

        {isAdmin && (

          <button
            onClick={goDashboard}
            className="bg-blue-600 px-6 py-3 rounded-lg"
          >
            Open Security Dashboard
          </button>

        )}

        <button
          onClick={accessAPI}
          className="bg-green-600 px-6 py-3 rounded-lg"
        >
          Access Protected API
        </button>

        <button
          onClick={logout}
          className="bg-red-600 px-6 py-3 rounded-lg"
        >
          Logout
        </button>

      </div>

      <p className="mt-6 text-gray-400">{status}</p>

    </div>

  );

}