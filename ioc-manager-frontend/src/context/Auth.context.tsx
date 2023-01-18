import { createContext, useState } from 'react'
import Cookies from 'universal-cookie'
import service_login from '../services/auth/login'
import service_register from '../services/auth/register'
import service_logout from '../services/auth/logout'

const cookies = new Cookies()
type authContent = {
  state: {
    isLoggedIn: boolean
    isLoginPending: boolean
    loginError: any
  }
  login: Function
  register: Function
  logout: Function
}
const initialState = {
  isLoggedIn: !(!cookies.get('access_token') && true),
  isLoginPending: false,
  loginError: undefined,
}
export const AuthContext = createContext<authContent>({
  state: initialState,
  login: Function,
  register: Function,
  logout: Function,
})

export const ContextProvider = (props: any) => {
  const [state, setState] = useState(initialState)

  const login = (email: string, password: string) => {
    setState({
      isLoggedIn: false,
      isLoginPending: true,
      loginError: undefined,
    })

    service_login(email, password, (error: any) => {
      setState({
        isLoggedIn: !error,
        isLoginPending: false,
        loginError: error?.message,
      })
    })
  }

  const register = (
    email: string,
    password: string,
    name: string,
    surname: string
  ) => {
    setState({
      isLoggedIn: false,
      isLoginPending: true,
      loginError: undefined,
    })

    service_register(email, password, name, surname, (error: any) => {
      setState({
        isLoggedIn: false,
        isLoginPending: false,
        loginError: error?.message,
      })
    })
  }

  const logout = () => {
    service_logout((error: any) => {
      setState({
        isLoggedIn: false,
        isLoginPending: false,
        loginError: undefined,
      })
    })
  }

  return (
    <AuthContext.Provider
      value={{
        state,
        login,
        register,
        logout,
      }}
    >
      {props.children}
    </AuthContext.Provider>
  )
}
