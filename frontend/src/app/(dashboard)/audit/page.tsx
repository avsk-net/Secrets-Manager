"use client"

import { useState } from "react"
import {
  ShieldCheck, ShieldAlert, Activity, Filter, RefreshCw, CheckCircle2, XCircle,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"
import { useAuditLogs, useVerifyChain } from "@/hooks/use-audit"
import { formatDateTime, AUDIT_RESULT_COLORS } from "@/lib/utils"

const EVENT_TYPE_OPTIONS = [
  { value: "", label: "All events" },
  { value: "auth.login.success", label: "Login success" },
  { value: "auth.login.failure", label: "Login failure" },
  { value: "auth.logout", label: "Logout" },
  { value: "secret.create", label: "Secret created" },
  { value: "secret.read", label: "Secret read" },
  { value: "secret.update", label: "Secret updated" },
  { value: "secret.delete", label: "Secret deleted" },
  { value: "secret.rollback", label: "Secret rollback" },
  { value: "user.create", label: "User created" },
  { value: "user.update", label: "User updated" },
  { value: "authz.denied", label: "Access denied" },
]

function EventTypeDot({ eventType }: { eventType: string }) {
  let color = "bg-slate-400"
  if (eventType.includes("login.failure") || eventType.includes("denied")) color = "bg-red-400"
  else if (eventType.includes("login.success") || eventType.includes("logout")) color = "bg-blue-400"
  else if (eventType.includes("secret")) color = "bg-violet-400"
  else if (eventType.includes("user")) color = "bg-amber-400"
  else if (eventType.includes("key")) color = "bg-emerald-400"
  return <span className={`inline-block h-2 w-2 rounded-full ${color} shrink-0`} />
}

export default function AuditPage() {
  const [eventType, setEventType] = useState("")
  const [result, setResult] = useState("")
  const [actorSearch, setActorSearch] = useState("")
  const [page, setPage] = useState(1)
  const verifyChain = useVerifyChain()

  const { data, isLoading, refetch } = useAuditLogs({
    event_type: eventType || undefined,
    result: result || undefined,
    page,
    page_size: 25,
  })

  const filtered = data?.items.filter((log) =>
    !actorSearch || log.actor_username?.toLowerCase().includes(actorSearch.toLowerCase())
  ) ?? []

  const totalPages = Math.ceil((data?.total ?? 0) / 25)

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Chain verification card */}
      <Card className={
        verifyChain.data
          ? verifyChain.data.valid
            ? "border-emerald-500/30 bg-emerald-500/5"
            : "border-red-500/30 bg-red-500/5"
          : ""
      }>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${verifyChain.data?.valid === false ? "bg-red-500/20" : "bg-emerald-500/20"}`}>
                <ShieldCheck className={`h-4 w-4 ${verifyChain.data?.valid === false ? "text-red-400" : "text-emerald-400"}`} />
              </div>
              <div>
                <CardTitle className="text-base">Audit Chain Integrity</CardTitle>
                <CardDescription className="text-xs">
                  HMAC-SHA256 chain across all audit entries
                </CardDescription>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => verifyChain.mutate()}
              disabled={verifyChain.isPending}
            >
              {verifyChain.isPending ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin mr-1.5" />
              ) : (
                <ShieldCheck className="h-3.5 w-3.5 mr-1.5" />
              )}
              Verify Chain
            </Button>
          </div>
        </CardHeader>
        {verifyChain.data && (
          <CardContent className="pt-0">
            {verifyChain.data.valid ? (
              <Alert variant="success">
                <CheckCircle2 className="h-4 w-4" />
                <AlertTitle>Chain Valid</AlertTitle>
                <AlertDescription>
                  {verifyChain.data.message} ({verifyChain.data.checked_entries} entries verified)
                </AlertDescription>
              </Alert>
            ) : (
              <Alert variant="destructive">
                <XCircle className="h-4 w-4" />
                <AlertTitle>Chain Broken — Possible Tampering Detected</AlertTitle>
                <AlertDescription>
                  First invalid event: <code className="font-mono text-xs">{verifyChain.data.first_invalid_event_id}</code>
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        )}
      </Card>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <Select value={eventType || "all"} onValueChange={(v) => { setEventType(v === "all" ? "" : v); setPage(1) }}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Event type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All events</SelectItem>
            {EVENT_TYPE_OPTIONS.filter(o => o.value).map((o) => (
              <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={result || "all"} onValueChange={(v) => { setResult(v === "all" ? "" : v); setPage(1) }}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Result" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All results</SelectItem>
            <SelectItem value="success">Success</SelectItem>
            <SelectItem value="failure">Failure</SelectItem>
            <SelectItem value="denied">Denied</SelectItem>
          </SelectContent>
        </Select>
        <Input
          placeholder="Filter by actor…"
          value={actorSearch}
          onChange={(e) => setActorSearch(e.target.value)}
          className="w-44"
        />
        <Button variant="ghost" size="icon" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4" />
        </Button>
        <span className="text-xs text-muted-foreground ml-auto">
          {data?.total ?? 0} total events
        </span>
      </div>

      {/* Log table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left">
                {["Event", "Actor", "Resource", "Result", "IP", "Time"].map((h) => (
                  <th key={h} className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading
                ? Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 6 }).map((_, j) => (
                      <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-full" /></td>
                    ))}
                  </tr>
                ))
                : filtered.length === 0
                ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-16 text-center">
                      <Activity className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" />
                      <p className="text-sm text-muted-foreground">No audit events match your filters</p>
                    </td>
                  </tr>
                )
                : filtered.map((log) => (
                  <tr key={log.id} className="hover:bg-muted/20 transition-colors group">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <EventTypeDot eventType={log.event_type} />
                        <span className="font-mono text-xs">{log.event_type}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {log.actor_username ?? <span className="text-muted-foreground italic">system</span>}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-muted-foreground">{log.resource_type}</span>
                      {log.resource_id && (
                        <p className="font-mono text-[10px] text-muted-foreground/60 truncate max-w-[120px]">
                          {log.resource_id.slice(0, 8)}…
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className={`text-xs ${AUDIT_RESULT_COLORS[log.result]}`}>
                        {log.result}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                      {log.ip_address ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                      {formatDateTime(log.timestamp)}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-border px-4 py-3">
            <p className="text-xs text-muted-foreground">Page {page} of {totalPages}</p>
            <div className="flex gap-1">
              <Button size="sm" variant="outline" disabled={page === 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
              <Button size="sm" variant="outline" disabled={page === totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}
