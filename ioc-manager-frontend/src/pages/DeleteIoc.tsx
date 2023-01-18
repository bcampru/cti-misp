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
import { useState, useEffect } from 'react'
import service_deleteIocs from '../services/core/deleteIocs'
import service_getClients from '../services/core/getClients'

function DeleteIoc() {
  const [isShown, setIsShown] = useState(false)
  const [isShown2, setIsShown2] = useState(false)
  const [iocs, setIocs] = useState<string>('')
  const [file, setFile] = useState<File>()
  const [error, setError] = useState<string>()
  const [progress, setProgress] = useState<number>(0)
  const [clients, setClients] = useState<any>({})

  useEffect(
    () =>
      service_getClients((result: Error | Array<any>) => {
        if (result instanceof Error) setError(result.message)
        else setClients(result.reduce((a, v) => ({ ...a, [v]: false }), {}))
      }),
    []
  )

  const onToggleHandler = (isOpen: boolean, metadata: any) => {
    if (metadata.source !== 'select') {
      setIsShown(isOpen)
    }
  }
  const onToggleHandler2 = (isOpen: boolean, metadata: any) => {
    if (metadata.source !== 'select') {
      setIsShown2(isOpen)
    }
  }
  const setState = (
    errorv: string | undefined,
    progressv: number | undefined
  ) => {
    errorv && setError(errorv)
    progressv && setProgress(progressv)
  }
  const sendFile = (e: any) => {
    e.preventDefault()
    setError('')
    setProgress(0)
    if (file) service_deleteIocs(file, undefined, clients, setState)
  }
  const sendIocs = (e: any) => {
    e.preventDefault()
    setError('')
    setProgress(0)
    if (iocs !== '') service_deleteIocs(undefined, iocs, clients, setState)
  }
  const getClients = () => {
    var res: Array<any> = []
    Object.keys(clients).forEach((key) =>
      res.push(
        <Dropdown.Item href="#action/3.2">
          <Form.Check
            key={key}
            type="checkbox"
            id="default-checkbox"
            defaultChecked={clients[key]}
            label={key}
            onClick={(e: any) =>
              setClients({ ...clients, [key]: e.target.checked })
            }
          />
        </Dropdown.Item>
      )
    )
    return res
  }
  return (
    <>
      <h1>Delete IOC</h1>
      <br />
      {error && <Alert variant="danger"> {error} </Alert>}
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
            {progress !== 0 && <ProgressBar animated now={progress} />}
          </div>
          <ButtonGroup className="mb-3">
            <DropdownButton
              title="Select Clients"
              as={ButtonGroup}
              variant="outline-secondary"
              show={isShown}
              onToggle={(isOpen: boolean, metadata: any) =>
                onToggleHandler(isOpen, metadata)
              }
            >
              {getClients()}
            </DropdownButton>
            <Button variant="outline-success" type="submit" onClick={sendIocs}>
              Delete IOCs
            </Button>
          </ButtonGroup>
          {progress === 100 && (
            <Alert variant="success"> Finished deleting IOCs! </Alert>
          )}
          <div className="mb-3"></div>
        </Tab>

        <Tab eventKey="File" title="File">
          <p>Select file with IOCs to delete</p>
          <InputGroup className="mb-3">
            <Form.Control
              type="file"
              onChange={(e: any) => setFile(e.target.files[0])}
            />
            <DropdownButton
              title="Select Clients"
              align="end"
              variant="outline-secondary"
              show={isShown2}
              onToggle={(isOpen: boolean, metadata: any) =>
                onToggleHandler2(isOpen, metadata)
              }
            >
              {getClients()}
            </DropdownButton>
          </InputGroup>
          <div className="mb-3">
            {progress !== 0 && <ProgressBar animated now={progress} />}
          </div>
          <div className="mb-3">
            <Button variant="outline-success" type="submit" onClick={sendFile}>
              Delete IOCs
            </Button>
          </div>
          {progress === 100 && (
            <Alert variant="success"> Finished deleting IOCs! </Alert>
          )}
        </Tab>
      </Tabs>
    </>
  )
}

export default DeleteIoc
