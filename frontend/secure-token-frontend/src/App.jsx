import RegisterDevice from "./components/RegisterDevice";
import IssueToken from "./components/IssueToken";
import ProtectedAccess from "./components/ProtectedAccess";

export default function App() {
  return (
    <>
      <RegisterDevice />
      <hr />
      <IssueToken />
      <hr />
      <ProtectedAccess />
    </>
  );
}
