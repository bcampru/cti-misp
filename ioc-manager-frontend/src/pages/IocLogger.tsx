import { useEffect, useState } from 'react'
import { AgGridReact } from 'ag-grid-react'

import 'ag-grid-community/styles/ag-grid.css'
import 'ag-grid-community/styles/ag-theme-alpine.css'
import { Container, Dropdown, Row, Col, Alert, Spinner } from 'react-bootstrap'
import service_getLogs from '../services/logger/getLogs'

function IocLogger() {
  const [error, setError] = useState<string>('')
  const [rowData, setRowData] = useState<Array<any>>()
  const [mode, setMode] = useState<string>('IOC Logs')
  const [loading, setLoading] = useState<boolean>(true)
  useEffect(
    () =>
      service_getLogs('ioc', (result: Error | Array<any>) => {
        if (result instanceof Error) setError(result.message)
        else setRowData(result)
        setTimeout(() => setLoading(false), 500)
      }),
    []
  )

  const mispColumns = [
    { headerName: 'Id', field: 'attribute_id' },
    { headerName: 'Succeed', field: 'succeed' },
    { headerName: 'IOC', field: 'value' },
    { headerName: 'Error', field: 'error' },
  ]
  const iocColumns = [
    { headerName: 'Ioc', field: 'ioc' },
    { headerName: 'Loaded by', field: 'user' },
  ]

  const [columnDefs, setColumnDefs] = useState(iocColumns)

  const changeMode = (newMode: string) => {
    if (newMode !== mode) {
      setMode(newMode)
      let type
      if (newMode === 'MISP Logs') {
        setColumnDefs(mispColumns)
        type = 'misp'
      } else {
        setColumnDefs(iocColumns)
        type = 'ioc'
      }
      setLoading(true)
      service_getLogs(type, (result: Error | Array<any>) => {
        if (result instanceof Error) setError(result.message)
        else setRowData(result)
        setTimeout(() => setLoading(false), 500)
      })
    }
  }

  const gridOptions: any = {
    defaultColDef: {
      resizable: true,
      flex: 1,
      filter: true,
      sortable: true,
      filterParams: {
        buttons: ['apply', 'reset'],
      },
    },
    pagination: true,
    paginationAutoPageSize: true,
    animateRows: true,
    rowData: null,
  }

  return (
    <Container className="ag-theme-alpine" style={{ height: '70vh' }}>
      {error && <Alert variant="danger"> {error} </Alert>}
      <Row>
        <Col>
          <h1>MISP Logger</h1>
        </Col>
        <Col>
          <Dropdown>
            <Dropdown.Toggle variant="secondary" id="dropdown-basic">
              {loading && (
                <Spinner
                  as="span"
                  animation="grow"
                  size="sm"
                  role="status"
                  aria-hidden="true"
                />
              )}{' '}
              {mode}
            </Dropdown.Toggle>
            <Dropdown.Menu>
              <Dropdown.Item onClick={() => changeMode('MISP Logs')}>
                MISP Logs
              </Dropdown.Item>
              <Dropdown.Item onClick={() => changeMode('IOC Logs')}>
                IOC Logs
              </Dropdown.Item>
            </Dropdown.Menu>
          </Dropdown>
        </Col>
      </Row>

      <AgGridReact
        rowData={rowData}
        columnDefs={columnDefs}
        gridOptions={gridOptions}
      ></AgGridReact>
    </Container>
  )
}

export default IocLogger
