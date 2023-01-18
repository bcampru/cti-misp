import Container from 'react-bootstrap/Container'
import Nav from 'react-bootstrap/Nav'
import Navbar from 'react-bootstrap/Navbar'
import NavDropdown from 'react-bootstrap/NavDropdown'
import { AuthContext } from '../context/Auth.context'
import { useContext } from 'react'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faUser } from '@fortawesome/free-solid-svg-icons'

function NavBar() {
  const { logout } = useContext(AuthContext)
  return (
    <Navbar expand="lg" bg="light">
      <Container>
        <Navbar.Brand href="/">
          <img
            alt=""
            src="/logo.png"
            width="140"
            className="d-inline-block align-top"
          />
        </Navbar.Brand>
        <Navbar.Toggle aria-controls="basic-navbar-nav" />
        <Navbar.Collapse id="basic-navbar-nav">
          <Nav className="me-auto">
            <Nav.Link href="add">Add IOC</Nav.Link>
            <Nav.Link href="delete">Delete IOC</Nav.Link>
            <Nav.Link href="update">Update IOC</Nav.Link>
            <Nav.Link href="logger">MISP Logger</Nav.Link>
          </Nav>

          <Nav id="profile-dropdown">
            <NavDropdown
              title={
                <div style={{ display: 'inline-block' }}>
                  <FontAwesomeIcon icon={faUser} />
                </div>
              }
            >
              <NavDropdown.Item onClick={() => logout()}>
                Logout
              </NavDropdown.Item>
            </NavDropdown>
          </Nav>
        </Navbar.Collapse>
      </Container>
    </Navbar>
  )
}

export default NavBar
