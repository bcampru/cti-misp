import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './pages/Layout'
import Home from './pages/Home'
import NoPage from './pages/NoPage'
import AddIoc from './pages/AddIoc'
import Auth from './pages/Auth'
import { useContext, useEffect } from 'react'
import { AuthContext } from './context/Auth.context'
import DeleteIoc from './pages/DeleteIoc'
import IocLogger from './pages/IocLogger'
import service_validcookie from './services/auth/validcookie'

export default function App() {
  const { state, logout } = useContext(AuthContext)
  useEffect(() => {
    service_validcookie(logout)
  }, [])
  if (!state.isLoggedIn) return <Auth />
  else
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Home />} />
            <Route path="/add" element={<AddIoc />} />
            <Route path="/delete" element={<DeleteIoc />} />
            <Route path="/logger" element={<IocLogger />} />
            <Route path="*" element={<NoPage />} />
          </Route>
          <Route path="/auth" element={<Auth />} />
        </Routes>
      </BrowserRouter>
    )
}
