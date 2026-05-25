import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { secretsApi } from "@/lib/api"
import type { SecretCreate, SecretUpdate } from "@/types"
import { toast } from "sonner"

export const secretKeys = {
  all: ["secrets"] as const,
  list: (params: object) => [...secretKeys.all, "list", params] as const,
  detail: (id: string) => [...secretKeys.all, "detail", id] as const,
  versions: (id: string) => [...secretKeys.all, "versions", id] as const,
}

export function useSecrets(params: {
  namespace?: string
  page?: number
  page_size?: number
  search?: string
} = {}) {
  return useQuery({
    queryKey: secretKeys.list(params),
    queryFn: () => secretsApi.list(params),
  })
}

export function useSecret(id: string) {
  return useQuery({
    queryKey: secretKeys.detail(id),
    queryFn: () => secretsApi.get(id),
    enabled: !!id,
  })
}

export function useSecretVersions(id: string) {
  return useQuery({
    queryKey: secretKeys.versions(id),
    queryFn: () => secretsApi.getVersions(id),
    enabled: !!id,
  })
}

export function useCreateSecret() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: SecretCreate) => secretsApi.create(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: secretKeys.all })
      toast.success("Secret created")
    },
    onError: (e: Error) => toast.error(e.message),
  })
}

export function useUpdateSecret() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: SecretUpdate }) =>
      secretsApi.update(id, payload),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: secretKeys.detail(id) })
      qc.invalidateQueries({ queryKey: secretKeys.all })
      toast.success("Secret updated — new version created")
    },
    onError: (e: Error) => toast.error(e.message),
  })
}

export function useDeleteSecret() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => secretsApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: secretKeys.all })
      toast.success("Secret deleted")
    },
    onError: (e: Error) => toast.error(e.message),
  })
}

export function useRollbackSecret() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, version }: { id: string; version: number }) =>
      secretsApi.rollback(id, version),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: secretKeys.detail(id) })
      qc.invalidateQueries({ queryKey: secretKeys.versions(id) })
      toast.success("Rolled back to selected version")
    },
    onError: (e: Error) => toast.error(e.message),
  })
}
