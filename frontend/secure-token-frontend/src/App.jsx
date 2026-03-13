import { BrowserRouter, Routes, Route } from "react-router-dom";

import UserAuthPage from "./components/UserAuthPage";
import AdminDashboard from "./components/AdminDashboard";
import Welcome from "./components/Welcome";
import Dashboard from "./components/Dashboard"; // SOC Dashboard

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<UserAuthPage />} />
        <Route path="/dashboard" element={<AdminDashboard />} />
        <Route path="/welcome" element={<Welcome />} />
        <Route path="/soc" element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;