export type UserRole = 'readonly' | 'developer' | 'admin' | 'super_admin'
export type SecretType = 'kv' | 'json' | 'binary'
export type AuditResult = 'success' | 'failure' | 'denied'

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  scope: string[]
}

export interface AuthState {
  user: CurrentUser | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
}

export interface CurrentUser {
  id: string
  username: string
  email: string
  role: UserRole
  scopes: string[]
}

export interface UserResponse {
  id: string
  username: string
  email: string
  role: UserRole
  is_active: boolean
  is_locked: boolean
  created_at: string
  updated_at: string
  last_login_at: string | null
}

export interface UserListResponse {
  items: UserResponse[]
  total: number
  page: number
  page_size: number
}

export interface UserCreate {
  username: string
  email: string
  password: string
  role: UserRole
}

export interface UserUpdate {
  email?: string
  role?: UserRole
  is_active?: boolean
  is_locked?: boolean
}

export interface SecretListItem {
  id: string
  name: string
  namespace: string
  secret_type: SecretType
  description: string | null
  current_version: number
  created_at: string
  updated_at: string
}

export interface SecretResponse {
  id: string
  name: string
  namespace: string
  secret_type: SecretType
  description: string | null
  current_version: number
  created_at: string
  updated_at: string
  created_by_id: string | null
  value: string | Record<string, unknown> | null
  version_id: string | null
}

export interface SecretListResponse {
  items: SecretListItem[]
  total: number
  page: number
  page_size: number
}

export interface SecretVersionResponse {
  id: string
  secret_id: string
  version: number
  is_current: boolean
  created_at: string
  created_by_id: string | null
  metadata: Record<string, unknown> | null
}

export interface SecretCreate {
  name: string
  namespace: string
  secret_type: SecretType
  value: string | Record<string, unknown>
  description?: string
  metadata?: Record<string, string>
}

export interface SecretUpdate {
  value: string | Record<string, unknown>
  description?: string
  metadata?: Record<string, string>
}

export interface AuditLogResponse {
  id: string
  event_id: string
  event_type: string
  actor_id: string | null
  actor_username: string | null
  resource_type: string
  resource_id: string | null
  action: string
  result: AuditResult
  ip_address: string | null
  user_agent: string | null
  request_id: string | null
  details: Record<string, unknown> | null
  error_message: string | null
  timestamp: string
  prev_hash: string | null
  chain_hash: string
}

export interface AuditLogListResponse {
  items: AuditLogResponse[]
  total: number
  page: number
  page_size: number
}

export interface ChainVerifyResponse {
  valid: boolean
  checked_entries: number
  first_invalid_event_id: string | null
  message: string
}

export interface ApiError {
  detail: string
  request_id?: string
}

export interface DashboardStats {
  totalSecrets: number
  totalUsers: number
  recentAuditEvents: number
  chainValid: boolean | null
}
