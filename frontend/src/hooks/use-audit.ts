import { useQuery, useMutation } from "@tanstack/react-query"
import { auditApi } from "@/lib/api"
import { toast } from "sonner"

export const auditKeys = {
  all: ["audit"] as const,
  list: (params: object) => [...auditKeys.all, "list", params] as const,
  detail: (id: string) => [...auditKeys.all, "detail", id] as const,
  chain: () => [...auditKeys.all, "chain"] as const,
}

export function useAuditLogs(params: {
  event_type?: string
  actor_id?: string
  resource_type?: string
  result?: string
  from_ts?: string
  to_ts?: string
  page?: number
  page_size?: number
} = {}) {
  return useQuery({
    queryKey: auditKeys.list(params),
    queryFn: () => auditApi.list(params),
  })
}

export function useVerifyChain() {
  return useMutation({
    mutationFn: () => auditApi.verifyChain(),
    onError: (e: Error) => toast.error(e.message),
  })
}
