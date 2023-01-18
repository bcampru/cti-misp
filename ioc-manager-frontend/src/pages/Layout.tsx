import { Outlet } from 'react-router-dom'
import NavBar from '../components/NavBar'
import { Container } from 'react-bootstrap'

function Layout() {
  return (
    <>
      <NavBar></NavBar>
      <br />
      <Container>
        <Outlet />
      </Container>
    </>
  )
}

export default Layout
