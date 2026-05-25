import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { usersApi } from "@/lib/api"
import type { UserCreate, UserUpdate } from "@/types"
import { toast } from "sonner"

export const userKeys = {
  all: ["users"] as const,
  list: (params: object) => [...userKeys.all, "list", params] as const,
  detail: (id: string) => [...userKeys.all, "detail", id] as const,
  me: () => [...userKeys.all, "me"] as const,
}

export function useUsers(params: {
  page?: number
  page_size?: number
  role?: string
  is_active?: boolean
} = {}) {
  return useQuery({
    queryKey: userKeys.list(params),
    queryFn: () => usersApi.list(params),
  })
}

export function useCurrentUser() {
  return useQuery({
    queryKey: userKeys.me(),
    queryFn: () => usersApi.me(),
  })
}

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: UserCreate) => usersApi.create(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: userKeys.all })
      toast.success("User created")
    },
    onError: (e: Error) => toast.error(e.message),
  })
}

export function useUpdateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: UserUpdate }) =>
      usersApi.update(id, payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: userKeys.all })
      toast.success("User updated")
    },
    onError: (e: Error) => toast.error(e.message),
  })
}
