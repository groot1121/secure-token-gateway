import { BrowserRouter, Routes, Route } from "react-router-dom";

import UserAuthPage from "./components/UserAuthPage";
import WelcomePage from "./components/WelcomePage";
import Dashboard from "./components/Dashboard";
import ProtectedRoute from "./components/ProtectedRoute";

function App() {

  return (

    <BrowserRouter>

      <Routes>

        <Route path="/" element={<UserAuthPage />} />

        <Route path="/welcome" element={<WelcomePage />} />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard/>
            </ProtectedRoute>
          }
        />

      </Routes>

    </BrowserRouter>

  );

}

export default App;