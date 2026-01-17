import RegisterDevice from "./components/RegisterDevice";
import IssueToken from "./components/IssueToken";
import TokenRotate from "./components/TokenRotate";
import ProtectedAccess from "./components/ProtectedAccess";
import ChallengeFlow from "./components/ChallengeFlow";


export default function App() {
  return (
    <div style={{ padding: 20 }}>
      <h2>Secure Token Gateway</h2>

      <RegisterDevice />
      <IssueToken />
      <ProtectedAccess />
      <ChallengeFlow />
      <TokenRotate />
    </div>
  );
}
