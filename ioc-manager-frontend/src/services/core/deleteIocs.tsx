import { setToken, getToken } from '../../helpers/token'
import service_logout from '../auth/logout'

export default function service_deleteIocs(
  file: File | undefined,
  iocs: string | undefined,
  clients: any,
  callback: Function
) {
  const endpoint: string = '/delete'
  const xhr = new XMLHttpRequest()
  let prevBufferEnd = 0
  let total = 0

  xhr.addEventListener('error', (e: any) => {
    console.log(e)
    callback(e.responseText, 0)
  })
  xhr.addEventListener('progress', (e: any) => {
    let currentProgress = e.currentTarget.responseText.substring(
      prevBufferEnd,
      e.currentTarget.responseText.length
    )
    if (e.currentTarget.status !== 200) {
      if (
        e.currentTarget.statusText === 'UNAUTHORIZED' ||
        e.currentTarget.statusText === 'UNPROCESSABLE ENTITY'
      ) {
        service_logout((e: any) => {})
        alert('Session timed out, please login again')
        window.location.reload()
        return
      }
      callback(e.currentTarget.statusText, 0)
      return
    }
    prevBufferEnd = e.currentTarget.responseText.length
    const respData = JSON.parse(currentProgress)
    if (respData) {
      if (respData['total']) {
        total = respData.total
      } else if (respData['progress']) {
        const { progress } = respData
        const percent = (progress / total) * 100
        callback(undefined, percent)
      } else if (respData['finished']) {
        callback(undefined, 100)
        respData['access_token'] && setToken(respData['access_token'])
      } else if (respData['error']) {
        callback(respData.error, 0)
        respData['access_token'] && setToken(respData['access_token'])
      }
    }
  })

  var formData = new FormData()
  if (file) {
    formData.append('file', file)
  } else if (iocs) formData.append('iocs', iocs)
  else {
    callback('You need to provide either a file or a text with IOCs', 0)
    return
  }

  formData.append(
    'clients',
    JSON.stringify(Object.keys(clients).find((key) => clients[key] === true))
  )

  if (!process.env.REACT_APP_API_URL)
    return callback(new Error("API isn't specified"))
  xhr.open('POST', process.env.REACT_APP_API_URL + endpoint)
  xhr.setRequestHeader('Authorization', 'Bearer ' + getToken())
  xhr.send(formData)
  callback(undefined, 1)
}
