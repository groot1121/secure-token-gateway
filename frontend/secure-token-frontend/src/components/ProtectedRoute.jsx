import { Navigate } from "react-router-dom";

export default function ProtectedRoute({children}){

  const token = localStorage.getItem("access_token");

  if(!token){
    return <Navigate to="/" />;
  }

  const payload = JSON.parse(atob(token.split(".")[1]));

  if(payload.role !== "admin"){
    return <Navigate to="/welcome" />;
  }

  return children;

}