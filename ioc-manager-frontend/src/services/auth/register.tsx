export default function service_register(
  email: string,
  password: string,
  name: string,
  surname: string,
  callback: Function
) {
  const endpoint: string = '/auth/register'
  const options: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: email,
      password: password,
      name: name,
      surname: surname,
    }),
  }
  if (!process.env.REACT_APP_API_URL)
    return callback(new Error("API isn't specified"))
  fetch(process.env.REACT_APP_API_URL + endpoint, options)
    .then((res) =>
      res.json().then((result) => {
        if (result.success === true) {
          alert('Registration completed, you can now log in!')
          callback(null)
          window.location.reload()
        } else return callback(new Error(result.error))
      })
    )
    .catch((res) => callback(new Error(res.message)))
}
