import api from "../api/gateway";
import { getDeviceId } from "../utils/device";
import { saveToken } from "../utils/token";

export default function IssueToken() {
  const issue = async () => {
    const res = await api.post("/issue-token", null, {
      params: {
        user_id: "user1",
        device_id: getDeviceId(),
      },
    });

    saveToken(res.data.access_token);
    alert("Token Issued");
  };

  return <button onClick={issue}>Issue Token</button>;
}
