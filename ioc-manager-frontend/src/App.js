import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './pages/Layout'
import Home from './pages/Home'
import NoPage from './pages/NoPage'
import AddIoc from './pages/AddIoc'
import Auth from './pages/Auth'
import { useContext } from 'react'
import { AuthContext } from './context/Auth.context'
import DeleteIoc from './pages/DeleteIoc'
import UpdateIoc from './pages/UpdateIoc'
import IocLogger from './pages/IocLogger'

export default function App() {
  const { state } = useContext(AuthContext)
  if (!state.isLoggedIn) return <Auth />
  else
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Home />} />
            <Route path="/add" element={<AddIoc />} />
            <Route path="/delete" element={<DeleteIoc />} />
            <Route path="/update" element={<UpdateIoc />} />
            <Route path="/logger" element={<IocLogger />} />
            <Route path="*" element={<NoPage />} />
          </Route>
          <Route path="/auth" element={<Auth />} />
        </Routes>
      </BrowserRouter>
    )
}
