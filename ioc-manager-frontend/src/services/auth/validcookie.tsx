import { getToken } from '../../helpers/token'

export default function service_validcookie(callback: Function) {
  const endpoint: string = '/auth/getcurrentuser'
  const options: RequestInit = {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + getToken(),
    },
  }
  if (!process.env.REACT_APP_API_URL) callback()
  fetch(process.env.REACT_APP_API_URL + endpoint, options).then((res) =>
    res
      .json()
      .then((result) => {
        console.log(result)
        if (
          result.msg === 'Token has been revoked' ||
          result.msg === 'Token has expired' ||
          result.msg === 'Not enough segments'
        ) {
          callback()
        }
      })
      .catch((err) => {
        callback()
      })
  )
}
