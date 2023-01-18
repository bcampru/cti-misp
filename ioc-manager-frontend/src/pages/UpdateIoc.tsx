import Form from 'react-bootstrap/Form'
import Tab from 'react-bootstrap/Tab'
import Tabs from 'react-bootstrap/Tabs'
import {
  Button,
  DropdownButton,
  Dropdown,
  InputGroup,
  Alert,
  ProgressBar,
  ButtonGroup,
} from 'react-bootstrap'
import { useState } from 'react'
import service_updateIocs from '../services/core/updateIocs'

function UpdateIoc() {
  const [mode, setMode] = useState<string>('detect')
  const [iocs, setIocs] = useState<string>('')
  const [file, setFile] = useState<File>()
  const [error, setError] = useState<string>()
  const [progress, setProgress] = useState<number>(0)

  const setState = (
    error: string | undefined,
    progress: number | undefined
  ) => {
    error && setError(error)
    progress && setProgress(progress)
  }
  const sendFile = (e: any) => {
    e.preventDefault()
    setError('')
    setProgress(0)
    if (file) service_updateIocs(file, undefined, mode, setState)
  }
  const sendIocs = (e: any) => {
    e.preventDefault()
    setError('')
    setProgress(0)
    if (iocs !== '') service_updateIocs(undefined, iocs, mode, setState)
  }
  return (
    <>
      <h1>Update IOC</h1>
      <br />
      {error ? <Alert variant="danger"> {error} </Alert> : ''}
      <Tabs defaultActiveKey="Form" className="mb-3" fill>
        <Tab eventKey="Form" title="Form">
          <Form.Group className="mb-3" controlId="exampleForm.ControlTextarea1">
            <Form.Label>Type the IOCs</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              placeholder="1.1.1.1&#10;945c1c2cc6e9ce758cbd5b4e869c0161"
              onChange={(e: any) => setIocs(e.target.value)}
            />
          </Form.Group>
          <div className="mb-3">
            {progress > 0 && <ProgressBar animated now={progress} />}
          </div>
          <ButtonGroup className="mb-3">
            {progress === 100 && (
              <Button
                variant="outline-info"
                href={`${process.env.REACT_APP_API_URL}/getExcel`}
              >
                Download results in Excel
              </Button>
            )}
            <DropdownButton
              title={`Mode: ${mode}`}
              as={ButtonGroup}
              variant="outline-secondary"
            >
              <Dropdown.Item onClick={() => setMode('detect')}>
                Detect
              </Dropdown.Item>
              <Dropdown.Item onClick={() => setMode('prevent')}>
                Prevent
              </Dropdown.Item>
            </DropdownButton>
            <Button variant="outline-success" type="submit" onClick={sendIocs}>
              Update IOCs
            </Button>
          </ButtonGroup>
          {progress === 100 && (
            <Alert variant="success"> Finished updating IOCs! </Alert>
          )}
        </Tab>

        <Tab eventKey="File" title="File">
          <p>Select file with IOCs to update</p>
          <InputGroup className="mb-3">
            <Form.Control
              type="file"
              onChange={(e: any) => setFile(e.target.files[0])}
            />
            <DropdownButton
              title={`Mode: ${mode}`}
              as={ButtonGroup}
              variant="outline-secondary"
            >
              <Dropdown.Item onClick={() => setMode('detect')}>
                Detect
              </Dropdown.Item>
              <Dropdown.Item onClick={() => setMode('prevent')}>
                Prevent
              </Dropdown.Item>
            </DropdownButton>
          </InputGroup>
          <div className="mb-3">
            {progress > 0 && <ProgressBar animated now={progress} />}
          </div>
          <ButtonGroup className="mb-3">
            {progress === 100 && (
              <Button
                variant="outline-info"
                href={`${process.env.REACT_APP_API_URL}/getExcel`}
              >
                Download results in Excel
              </Button>
            )}
            <Button variant="outline-success" type="submit" onClick={sendFile}>
              Update IOCs
            </Button>
          </ButtonGroup>
          {progress === 100 && (
            <Alert variant="success"> Finished updating IOCs! </Alert>
          )}
        </Tab>
      </Tabs>
    </>
  )
}

export default UpdateIoc
