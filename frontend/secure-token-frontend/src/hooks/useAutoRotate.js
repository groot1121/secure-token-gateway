import { useEffect } from "react";
import { signText } from "../utils/crypto";
import { rotateToken } from "../api/gateway";

export default function useAutoRotate(token, privateKey, setToken) {

  useEffect(() => {

    if (!token || !privateKey) return;

    const interval = setInterval(async () => {

      try {

        const payload = JSON.parse(atob(token.split(".")[1]));
        const message = `ROTATE:${payload.jti}`;

        const signature = await signText(privateKey, message);

        const res = await rotateToken(token, signature);

        const newToken = res.data.access_token;

        console.log("Token rotated");

        setToken(newToken);

      } catch (err) {

        console.error("Rotation failed", err);

      }

    }, 8000); // every 8 seconds for demo

    return () => clearInterval(interval);

  }, [token, privateKey, setToken]);

}