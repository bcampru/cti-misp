import Cookies from 'universal-cookie'
const cookies = new Cookies()

export function setToken(token: string) {
  if (!cookies.get('access_token') || cookies.get('access_token') === token)
    cookies.set('access_token', token, { httpOnly: false })
}

export function deleteToken() {
  cookies.remove('access_token')
}
export function getToken() {
  return cookies.get('access_token')
}
