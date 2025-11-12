import { BrowserRouter, Routes, Route } from 'react-router-dom';
import MainPage from './pages/MainPage';
import DkgPage from './pages/DkgPage';
import SigningPage from './pages/SigningPage';
import './App.css';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<MainPage />} />
        <Route path="/dkg" element={<DkgPage />} />
        <Route path="/signing" element={<SigningPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
