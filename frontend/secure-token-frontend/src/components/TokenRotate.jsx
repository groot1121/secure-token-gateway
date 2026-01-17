import api from "../api/gateway";
import { getToken, saveToken } from "../utils/token";

export default function TokenRotate() {
  const rotate = async () => {
    const res = await api.post("/rotate-token", null, {
      headers: {
        Authorization: `Bearer ${getToken()}`,
      },
    });

    saveToken(res.data.access_token);
    alert("Token Rotated");
  };

  return <button onClick={rotate}>Rotate Token</button>;
}
