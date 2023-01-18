import { getToken, setToken } from '../../helpers/token'

export default function service_getClients(callback: Function) {
  const endpoint: string = '/getClients'
  const options: RequestInit = {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + getToken(),
    },
  }
  if (!process.env.REACT_APP_API_URL)
    return callback(new Error("API isn't specified"))
  fetch(process.env.REACT_APP_API_URL + endpoint, options)
    .then((res) =>
      res.json().then((result) => {
        callback(result)
      })
    )
    .catch((res) => callback(new Error(res.message)))
}
