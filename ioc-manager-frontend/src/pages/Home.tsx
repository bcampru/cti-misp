import { Accordion, Tabs, Tab, Table, ListGroup, Badge } from 'react-bootstrap'
import { useState } from 'react'

const Home = () => {
  const [key, setKey] = useState('functionalities')
  return (
    <>
      <h1>Documentation</h1>
      <br />
      <Tabs
        id="controlled-tab-example"
        activeKey={key}
        onSelect={(k: any) => setKey(k)}
        className="mb-3"
      >
        <Tab eventKey="functionalities" title="Functionalities">
          <Accordion defaultActiveKey="0">
            <Accordion.Item eventKey="0">
              <Accordion.Header>Add IOC</Accordion.Header>
              <Accordion.Body>
                In this page you can load IOCs to the system, you can do it
                either with a csv or with a form.
                <br />
                <br />
                You can also set the Expiration time and the clients you want to
                upload the IOCs to. <br /> The expiration time can be setted as
                Days Months or Automatic, if Automatic is selected the system
                will scan the IOC and come up with a TTL deppending of its
                dangerousness, if it's not enough dangerous the IOC will be
                deleted. If you are sure that the IOC needs to be blocked I
                recommend you to set the expiration time manually. <br /> <br />
                <Badge bg="danger">!</Badge> When loading a CTI report it's
                important to select the expiration time as Automatic
                <br /> <br />
                The IOCs will be always uploaded to the clients that have agreed
                that we upload all the IOCs that we find, the clients shown in
                the Select Clients option are the ones that only want us to
                ulpoad IOCs in specific cases.
              </Accordion.Body>
            </Accordion.Item>
            <Accordion.Item eventKey="1">
              <Accordion.Header>Delete IOC</Accordion.Header>
              <Accordion.Body>
                In this page you can remove IOCs from the system, you can do it
                either with a csv or with a form.
                <br /> <br />
                You can also set the clients you want to remove the IOCs from.
                <br />
                If you don't select any client the IOCs will be removed from
                each client.
              </Accordion.Body>
            </Accordion.Item>
            <Accordion.Item eventKey="2">
              <Accordion.Header>Update IOC</Accordion.Header>
              <Accordion.Body>
                In this page you can update IOCs from Clariant's Crowdstrike,
                you can do it either with a csv or with a form.
                <br /> <br />
                You will have to select the mode you want the IOCs to be updated
                (Detect or Prevent). By default it's setted to Detect.
              </Accordion.Body>
            </Accordion.Item>
            <Accordion.Item eventKey="3">
              <Accordion.Header>MISP Logger</Accordion.Header>
              <Accordion.Body>
                In this page you can see the logs from the system, there are two
                types of logs:
                <br />
                <br />
                <ul>
                  <li>
                    IOC Logs: Here you can find all the IOCs that have been
                    loaded to the system and who has loaded it.
                  </li>
                  <li>
                    MISP Logs: Here you can find all the logs from the MISP
                    workflow and from the internal functionalities.
                  </li>
                </ul>
                You can select the log type in the dropdown and you can also
                filter the results by column.
                <br /> <br />
                <Badge bg="danger">!</Badge> When you delete an IOC, its
                registry entry will also be deleted, so if you want to know who
                uploaded an IOC, check before you delete it.
              </Accordion.Body>
            </Accordion.Item>
          </Accordion>
        </Tab>
        <Tab eventKey="load" title="Loading Format">
          <Accordion defaultActiveKey="0">
            <Accordion.Item eventKey="0">
              <Accordion.Header>Form</Accordion.Header>
              <Accordion.Body>
                When using the Form method you must enter the IOCs separated by
                a new line, example:
                <br />
                <br />
                1.1.1.1 <br />
                945c1c2cc6e9ce758cbd5b4e869c0161 <br />
                ...
              </Accordion.Body>
            </Accordion.Item>
            <Accordion.Item eventKey="1">
              <Accordion.Header>File</Accordion.Header>
              <Accordion.Body>
                The file needs to be a csv (separated by commas) with the
                cyberproof CTI report format:
                <br />
                <br />
                <Table striped bordered hover>
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Value</th>
                      <th>Description</th>
                      <th>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>MD5</td>
                      <td>d3bddb5de864afd7e4f5e56027f4e5ea</td>
                      <td>CredoMap</td>
                      <td>
                        https://securityscorecard.com/research/apt28s-stealer-called-credomap
                      </td>
                    </tr>
                    <tr>
                      <td>...</td>
                      <td>...</td>
                      <td>...</td>
                      <td>...</td>
                    </tr>
                  </tbody>
                </Table>
                The Type field isn't case sansitive and it can be:
                <br />
                <br />
                <ListGroup>
                  <ListGroup.Item>ipv4</ListGroup.Item>
                  <ListGroup.Item>domain</ListGroup.Item>
                  <ListGroup.Item>url</ListGroup.Item>
                  <ListGroup.Item>md5</ListGroup.Item>
                  <ListGroup.Item>sha1</ListGroup.Item>
                  <ListGroup.Item>sha256</ListGroup.Item>
                </ListGroup>
              </Accordion.Body>
            </Accordion.Item>
          </Accordion>
        </Tab>
      </Tabs>
    </>
  )
}

export default Home
