import RegisterDevice from "./components/RegisterDevice";
import IssueToken from "./components/IssueToken";
import ProtectedAccess from "./components/ProtectedAccess";
import RotateToken from "./components/RotateToken";
import useAutoRotate from "./hooks/useAutoRotate";

export default function App() {

   useAutoRotate();
  return (
    <>
      <RegisterDevice />
      <hr />
      <IssueToken />
      <hr />
      <ProtectedAccess />
      <hr />
      <RotateToken />
    </>
  );
}
