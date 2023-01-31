import { useEffect, useState } from 'react'
import { AgGridReact } from 'ag-grid-react'

import 'ag-grid-community/styles/ag-grid.css'
import 'ag-grid-community/styles/ag-theme-alpine.css'
import { Container, Dropdown, Row, Col, Alert, Spinner } from 'react-bootstrap'
import service_getLogs from '../services/logger/getLogs'

function IocLogger() {
  const [error, setError] = useState<string>('')
  const [rowData, setRowData] = useState<Array<any>>()
  const [loading, setLoading] = useState<boolean>(true)
  useEffect(
    () =>
      service_getLogs((result: Error | Array<any>) => {
        if (result instanceof Error) setError(result.message)
        else setRowData(result)
        setTimeout(() => setLoading(false), 500)
      }),
    []
  )

  const iocColumns = [
    { headerName: 'Ioc', field: 'ioc' },
    { headerName: 'Loaded by', field: 'user' },
  ]

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
          {loading && (
            <Spinner
              as="span"
              animation="grow"
              size="sm"
              role="status"
              aria-hidden="true"
            />
          )}
        </Col>
      </Row>

      <AgGridReact
        rowData={rowData}
        columnDefs={iocColumns}
        gridOptions={gridOptions}
      ></AgGridReact>
    </Container>
  )
}

export default IocLogger
