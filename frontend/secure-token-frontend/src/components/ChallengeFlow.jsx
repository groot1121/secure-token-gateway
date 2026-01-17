// src/components/ChallengeFlow.jsx
import axios from "axios";
import { signMessage } from "../utils/crypto";

export default function ChallengeFlow() {
  const runChallenge = async () => {
    const { data: challenge } = await axios.get(
      "http://localhost:8000/challenge"
    );

    const deviceId = localStorage.getItem("device_id");
    const userId = "user1";

    // 🔐 EXACT BACKEND MESSAGE
    const message = `CHALLENGE:${challenge.challenge_id}:${challenge.nonce}`;
    const signature = await signMessage(message);

    await axios.post("http://localhost:8000/challenge-verify", null, {
      params: {
        challenge_id: challenge.challenge_id,
        signature,
        user_id: userId,
        device_id: deviceId,
      },
    });

    alert("Challenge verified");
  };

  return <button onClick={runChallenge}>Run Challenge</button>;
}
