"use client"

import React, { createContext, useContext, useEffect, useState, useCallback } from "react"
import { useRouter } from "next/navigation"
import { authApi, usersApi, tokenStorage } from "@/lib/api"
import type { CurrentUser, UserRole } from "@/types"

interface JwtPayload {
  sub: string
  username: string
  role: UserRole
  scopes: string[]
  exp: number
}

interface AuthContextValue {
  user: CurrentUser | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  hasScope: (scope: string) => boolean
  canManageUsers: boolean
  canViewAudit: boolean
  canWriteSecrets: boolean
  canDeleteSecrets: boolean
}

const AuthContext = createContext<AuthContextValue | null>(null)

function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split(".")
    if (parts.length !== 3) return null
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")))
    if (payload.exp * 1000 < Date.now()) return null
    return payload
  } catch {
    return null
  }
}

function tokenToUser(token: string): CurrentUser | null {
  const payload = decodeJwt(token)
  if (!payload) return null
  return {
    id: payload.sub,
    username: payload.username,
    email: "",
    role: payload.role,
    scopes: payload.scopes ?? [],
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    const token = tokenStorage.getAccess()
    if (token) {
      const decoded = tokenToUser(token)
      if (decoded) {
        setUser(decoded)
        usersApi.me().then((u) => {
          setUser((prev) => prev ? { ...prev, email: u.email } : prev)
        }).catch(() => {})
      } else {
        tokenStorage.clear()
      }
    }
    setIsLoading(false)
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const tokenResp = await authApi.login(username, password)
    const decoded = tokenToUser(tokenResp.access_token)
    if (!decoded) throw new Error("Invalid token received")
    setUser(decoded)
    try {
      const me = await usersApi.me()
      setUser({ ...decoded, email: me.email })
    } catch {}
    router.push("/dashboard")
  }, [router])

  const logout = useCallback(async () => {
    await authApi.logout()
    setUser(null)
    router.push("/login")
  }, [router])

  const hasScope = useCallback((scope: string) => {
    return user?.scopes.includes(scope) ?? false
  }, [user])

  const canManageUsers = user?.role === "admin" || user?.role === "super_admin"
  const canViewAudit = user?.role === "admin" || user?.role === "super_admin"
  const canWriteSecrets = user?.role !== "readonly"
  const canDeleteSecrets = user?.role === "admin" || user?.role === "super_admin"

  return (
    <AuthContext.Provider value={{
      user,
      isAuthenticated: !!user,
      isLoading,
      login,
      logout,
      hasScope,
      canManageUsers,
      canViewAudit,
      canWriteSecrets,
      canDeleteSecrets,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used within AuthProvider")
  return ctx
}
