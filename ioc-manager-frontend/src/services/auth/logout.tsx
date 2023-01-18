import { getToken, deleteToken } from '../../helpers/token'

export default function service_logout(callback: Function) {
  const endpoint: string = '/auth/logout'
  const options: RequestInit = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + getToken(),
    },
  }
  if (!process.env.REACT_APP_API_URL)
    return callback(new Error("API isn't specified"))
  deleteToken()
  fetch(process.env.REACT_APP_API_URL + endpoint, options).then((res) =>
    res.json().then((result) => {
      if (
        result.msg === 'Token has been revoked' ||
        result.msg === 'Token has expired' ||
        result.msg === 'Not enough segments'
      ) {
        return callback(null)
      } else return callback(new Error(result.error))
    })
  )
}
