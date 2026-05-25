"use client"

import { useQuery } from "@tanstack/react-query"
import { KeyRound, Users, Activity, ShieldCheck, AlertTriangle, TrendingUp } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { secretsApi, usersApi, auditApi } from "@/lib/api"
import { useAuth } from "@/contexts/auth-context"
import { formatRelative, AUDIT_RESULT_COLORS } from "@/lib/utils"

function StatCard({
  title,
  value,
  icon: Icon,
  description,
  accent,
  loading,
}: {
  title: string
  value: string | number
  icon: React.ElementType
  description?: string
  accent?: string
  loading?: boolean
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <div className={`rounded-lg p-2 ${accent ?? "bg-muted"}`}>
          <Icon className="h-4 w-4" />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-8 w-24" />
        ) : (
          <p className="text-3xl font-bold">{value}</p>
        )}
        {description && <p className="mt-1 text-xs text-muted-foreground">{description}</p>}
      </CardContent>
    </Card>
  )
}

export default function DashboardPage() {
  const { canViewAudit, canManageUsers } = useAuth()

  const secrets = useQuery({
    queryKey: ["secrets", "list", {}],
    queryFn: () => secretsApi.list({ page: 1, page_size: 1 }),
  })

  const users = useQuery({
    queryKey: ["users", "list", {}],
    queryFn: () => usersApi.list({ page: 1, page_size: 1 }),
    enabled: canManageUsers,
  })

  const recentLogs = useQuery({
    queryKey: ["audit", "list", { page_size: 8 }],
    queryFn: () => auditApi.list({ page: 1, page_size: 8 }),
    enabled: canViewAudit,
  })

  const chainVerify = useQuery({
    queryKey: ["audit", "chain"],
    queryFn: () => auditApi.verifyChain(),
    enabled: canViewAudit,
    staleTime: 5 * 60 * 1000,
  })

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Stats grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Secrets"
          value={secrets.data?.total ?? "—"}
          icon={KeyRound}
          accent="bg-violet-500/10 text-violet-400"
          description="Across all namespaces"
          loading={secrets.isLoading}
        />
        {canManageUsers && (
          <StatCard
            title="Users"
            value={users.data?.total ?? "—"}
            icon={Users}
            accent="bg-blue-500/10 text-blue-400"
            description="Active accounts"
            loading={users.isLoading}
          />
        )}
        {canViewAudit && (
          <StatCard
            title="Audit Events"
            value={recentLogs.data?.total ?? "—"}
            icon={Activity}
            accent="bg-amber-500/10 text-amber-400"
            description="Total log entries"
            loading={recentLogs.isLoading}
          />
        )}
        {canViewAudit && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Chain Integrity</CardTitle>
              <div className="rounded-lg bg-emerald-500/10 p-2 text-emerald-400">
                <ShieldCheck className="h-4 w-4" />
              </div>
            </CardHeader>
            <CardContent>
              {chainVerify.isLoading ? (
                <Skeleton className="h-8 w-20" />
              ) : chainVerify.data?.valid ? (
                <div>
                  <p className="text-3xl font-bold text-emerald-400">Valid</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {chainVerify.data.checked_entries} entries verified
                  </p>
                </div>
              ) : chainVerify.data ? (
                <div>
                  <p className="text-3xl font-bold text-red-400">Broken</p>
                  <p className="mt-1 text-xs text-red-400/70">Chain tamper detected</p>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">—</p>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Recent activity */}
      {canViewAudit && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">Recent Activity</CardTitle>
                <CardDescription>Latest audit log entries</CardDescription>
              </div>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            {recentLogs.isLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <Skeleton className="h-8 w-8 rounded-full" />
                    <div className="flex-1 space-y-1">
                      <Skeleton className="h-3 w-48" />
                      <Skeleton className="h-2 w-32" />
                    </div>
                    <Skeleton className="h-5 w-16" />
                  </div>
                ))}
              </div>
            ) : recentLogs.data?.items.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-center">
                <Activity className="h-8 w-8 text-muted-foreground/40" />
                <p className="mt-3 text-sm text-muted-foreground">No audit events yet</p>
              </div>
            ) : (
              <div className="divide-y divide-border">
                {recentLogs.data?.items.map((log) => (
                  <div key={log.id} className="flex items-center gap-3 py-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                      <Activity className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">{log.event_type}</p>
                      <p className="text-xs text-muted-foreground">
                        {log.actor_username ?? "system"} · {formatRelative(log.timestamp)}
                      </p>
                    </div>
                    <Badge
                      variant="outline"
                      className={AUDIT_RESULT_COLORS[log.result]}
                    >
                      {log.result}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Security summary for non-admins */}
      {!canViewAudit && (
        <Card className="border-violet-500/20 bg-violet-500/5">
          <CardContent className="flex items-center gap-4 pt-6">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-violet-500/20">
              <ShieldCheck className="h-5 w-5 text-violet-400" />
            </div>
            <div>
              <p className="font-medium">Your secrets are protected</p>
              <p className="text-sm text-muted-foreground">
                AES-256-GCM encryption with per-secret DEKs wrapped by a master key
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
