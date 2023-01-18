import { setToken } from '../../helpers/token'

export default function service_login(
  email: string,
  password: string,
  callback: Function
) {
  const endpoint: string = '/auth/login'
  const options: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email, password: password }),
  }
  if (!process.env.REACT_APP_API_URL)
    return callback(new Error("API isn't specified"))
  fetch(process.env.REACT_APP_API_URL + endpoint, options)
    .then((res) =>
      res.json().then((result) => {
        if (result.msg === 'login successful' && result.access_token) {
          setToken(result.access_token)
          return callback(null)
        } else return callback(new Error(result.error))
      })
    )
    .catch((res) => callback(new Error(res.message)))
}
