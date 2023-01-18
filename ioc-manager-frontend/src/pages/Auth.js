import {
  Col,
  Button,
  Row,
  Container,
  Card,
  Form,
  Spinner,
  Alert,
  InputGroup,
} from 'react-bootstrap'
import { AuthContext } from '../context/Auth.context'
import { useContext, useState } from 'react'

export default function Auth() {
  const { state: ContextState, login, register } = useContext(AuthContext)
  const { isLoginPending, loginError } = ContextState
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [passwordVerify, setPasswordVerify] = useState('')
  const [name, setName] = useState('')
  const [surname, setSurname] = useState('')
  const [loginMode, setLoginMode] = useState(true)

  const onSubmitLogin = (e) => {
    e.preventDefault()
    login(email, password)
  }
  const onSubmitRegister = (e) => {
    e.preventDefault()
    if (password !== passwordVerify) {
      alert('Both passwords need to be equal')
      return
    }
    register(email, password, name, surname)
  }
  if (loginMode)
    return (
      <div>
        <Container>
          <Row className="vh-100 d-flex justify-content-center align-items-center">
            <Col md={8} lg={6} xs={12}>
              <Card className="shadow">
                <Card.Body>
                  <div className="mb-3 mt-md-4">
                    {loginError && (
                      <Alert variant="danger"> {loginError} </Alert>
                    )}
                    <h2 className="fw-bold mb-2 text-uppercase ">
                      CTI Manager Login
                    </h2>
                    <p className=" mb-5">
                      Please enter your login and password!
                    </p>
                    <div className="mb-3">
                      <Form onSubmit={onSubmitLogin}>
                        <Form.Group className="mb-3" controlId="formBasicEmail">
                          <Form.Label className="text-center">
                            Email address
                          </Form.Label>
                          <InputGroup hasValidation>
                            <InputGroup.Text id="inputGroupPrepend">
                              @
                            </InputGroup.Text>
                            <Form.Control
                              type="email"
                              placeholder="Enter email"
                              aria-describedby="inputGroupPrepend"
                              onChange={(e) => setEmail(e.target.value)}
                              required
                            />
                            <Form.Control.Feedback type="invalid">
                              Please choose a username.
                            </Form.Control.Feedback>
                          </InputGroup>
                        </Form.Group>
                        <Form.Group
                          className="mb-3"
                          controlId="formBasicPassword"
                        >
                          <Form.Label>Password</Form.Label>
                          <Form.Control
                            type="password"
                            placeholder="Password"
                            onChange={(e) => setPassword(e.target.value)}
                            required
                          />
                        </Form.Group>
                        <Form.Group
                          className="mb-3"
                          controlId="formBasicCheckbox"
                        >
                          <p className="small">
                            <a
                              className="text-primary"
                              href="#!"
                              onClick={() =>
                                alert(
                                  'Not implemented yet, ask Biel Camprubí for help'
                                )
                              }
                            >
                              Forgot password?
                            </a>
                          </p>
                        </Form.Group>
                        <div className="d-grid">
                          <Button variant="primary" type="submit">
                            <Row class="row">
                              {isLoginPending && (
                                <Col>
                                  <Spinner
                                    animation="border"
                                    role="status"
                                    size="sm"
                                  ></Spinner>
                                </Col>
                              )}
                              <Col>Login</Col>
                              {isLoginPending && <Col></Col>}
                            </Row>
                          </Button>
                        </div>
                      </Form>
                      <div className="mt-3">
                        <p className="mb-0  text-center">
                          Don't have an account?{' '}
                          <a
                            onClick={() => setLoginMode(false)}
                            href="#!"
                            className="text-primary fw-bold"
                          >
                            Sign Up
                          </a>
                        </p>
                      </div>
                    </div>
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Container>
      </div>
    )
  else
    return (
      <div>
        <Container>
          <Row className="vh-100 d-flex justify-content-center align-items-center">
            <Col md={8} lg={6} xs={12}>
              <Card className="shadow">
                <Card.Body>
                  <div className="mb-3 mt-md-4">
                    {loginError && (
                      <Alert variant="danger"> {loginError} </Alert>
                    )}
                    <h2 className="fw-bold mb-2 text-uppercase ">
                      CTI Manager Register
                    </h2>
                    <p className=" mb-5">Please fill the form</p>
                    <div className="mb-3">
                      <Form onSubmit={onSubmitRegister}>
                        <Row>
                          <Col>
                            <Form.Group
                              className="mb-3"
                              controlId="formBasicEmail"
                            >
                              <Form.Label className="text-center">
                                Name
                              </Form.Label>
                              <Form.Control
                                required
                                type="text"
                                placeholder="Name"
                                onChange={(e) => setName(e.target.value)}
                              />
                            </Form.Group>
                          </Col>
                          <Col>
                            <Form.Group
                              className="mb-3"
                              controlId="formBasicEmail"
                            >
                              <Form.Label className="text-center">
                                Surname
                              </Form.Label>
                              <Form.Control
                                required
                                type="text"
                                placeholder="Surname"
                                onChange={(e) => setSurname(e.target.value)}
                              />
                            </Form.Group>
                          </Col>
                        </Row>

                        <Form.Group className="mb-3" controlId="formBasicEmail">
                          <Form.Label className="text-center">
                            Email address
                          </Form.Label>
                          <InputGroup hasValidation>
                            <InputGroup.Text id="inputGroupPrepend">
                              @
                            </InputGroup.Text>
                            <Form.Control
                              type="email"
                              aria-describedby="inputGroupPrepend"
                              required
                              placeholder="Enter email"
                              onChange={(e) => setEmail(e.target.value)}
                            />
                            <Form.Control.Feedback type="invalid">
                              Please choose a username.
                            </Form.Control.Feedback>
                          </InputGroup>
                        </Form.Group>
                        <Row>
                          <Col>
                            <Form.Group
                              className="mb-3"
                              controlId="formBasicPassword"
                            >
                              <Form.Label>Password</Form.Label>
                              <Form.Control
                                required
                                type="password"
                                placeholder="Password"
                                onChange={(e) => setPassword(e.target.value)}
                              />
                            </Form.Group>
                          </Col>
                          <Col>
                            <Form.Group
                              className="mb-3"
                              controlId="formBasicPassword"
                            >
                              <Form.Label>Repeat Password</Form.Label>
                              <Form.Control
                                required
                                type="password"
                                placeholder="Password"
                                onChange={(e) =>
                                  setPasswordVerify(e.target.value)
                                }
                              />
                            </Form.Group>
                          </Col>
                        </Row>
                        <Form.Group
                          className="mb-3"
                          controlId="formBasicCheckbox"
                        >
                          <p className="small">
                            <a
                              className="text-primary"
                              href="#!"
                              onClick={() =>
                                alert(
                                  'Not implemented yet, ask Biel Camprubí for help'
                                )
                              }
                            >
                              Forgot password?
                            </a>
                          </p>
                        </Form.Group>
                        <div className="d-grid">
                          <Button variant="primary" type="submit">
                            <Row class="row">
                              {isLoginPending && (
                                <Col>
                                  <Spinner
                                    animation="border"
                                    role="status"
                                    size="sm"
                                  ></Spinner>
                                </Col>
                              )}
                              <Col>Sign Up</Col>
                              {isLoginPending && <Col></Col>}
                            </Row>
                          </Button>
                        </div>
                      </Form>
                      <div className="mt-3">
                        <p className="mb-0  text-center">
                          Have an account?{' '}
                          <a
                            onClick={() => setLoginMode(true)}
                            href="#!"
                            className="text-primary fw-bold"
                          >
                            Log In
                          </a>
                        </p>
                      </div>
                    </div>
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Container>
      </div>
    )
}
