"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import {
  Plus, Search, Eye, EyeOff, Pencil, Trash2, Clock, RefreshCw,
  KeyRound, AlertTriangle, Copy, Check,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  useSecrets, useCreateSecret, useUpdateSecret, useDeleteSecret,
  useSecret, useSecretVersions, useRollbackSecret,
} from "@/hooks/use-secrets"
import { useAuth } from "@/contexts/auth-context"
import { formatRelative, formatDateTime, SECRET_TYPE_COLORS, ROLE_COLORS } from "@/lib/utils"
import type { SecretListItem } from "@/types"

// ── Create/Edit form ─────────────────────────────────────────────────────────
const secretSchema = z.object({
  name: z.string().min(1).regex(/^[a-zA-Z0-9_\-./]+$/, "Only letters, numbers, _ - . / allowed"),
  namespace: z.string().min(1).regex(/^[a-zA-Z0-9_-]+$/, "Only letters, numbers, _ - allowed"),
  secret_type: z.enum(["kv", "json", "binary"]),
  value: z.string().min(1, "Value is required"),
  description: z.string().optional(),
})
type SecretForm = z.infer<typeof secretSchema>

function CreateSecretDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateSecret()
  const { register, handleSubmit, reset, setValue, watch, formState: { errors, isSubmitting } } = useForm<SecretForm>({
    resolver: zodResolver(secretSchema),
    defaultValues: { namespace: "default", secret_type: "kv" },
  })

  const onSubmit = async (data: SecretForm) => {
    let value: string | Record<string, unknown> = data.value
    if (data.secret_type === "json") {
      try { value = JSON.parse(data.value) } catch {
        return
      }
    }
    await create.mutateAsync({
      name: data.name,
      namespace: data.namespace,
      secret_type: data.secret_type,
      value,
      description: data.description,
    })
    reset()
    onClose()
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) { reset(); onClose() } }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create Secret</DialogTitle>
          <DialogDescription>Add a new encrypted secret to your vault.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Name</Label>
              <Input placeholder="prod/db/password" {...register("name")} />
              {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
            </div>
            <div className="space-y-1.5">
              <Label>Namespace</Label>
              <Input placeholder="default" {...register("namespace")} />
              {errors.namespace && <p className="text-xs text-destructive">{errors.namespace.message}</p>}
            </div>
          </div>
          <div className="space-y-1.5">
            <Label>Type</Label>
            <Select defaultValue="kv" onValueChange={(v) => setValue("secret_type", v as "kv" | "json" | "binary")}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="kv">Key-Value (string)</SelectItem>
                <SelectItem value="json">JSON object</SelectItem>
                <SelectItem value="binary">Binary (base64)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Value</Label>
            {watch("secret_type") === "json" ? (
              <Textarea
                placeholder='{"host": "db.internal", "port": 5432}'
                rows={4}
                className="font-mono text-xs"
                {...register("value")}
              />
            ) : (
              <Input type="password" placeholder="••••••••••••••" {...register("value")} />
            )}
            {errors.value && <p className="text-xs text-destructive">{errors.value.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label>Description <span className="text-muted-foreground">(optional)</span></Label>
            <Input placeholder="What is this secret for?" {...register("description")} />
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => { reset(); onClose() }}>Cancel</Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Creating…" : "Create Secret"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ── Secret Detail Drawer (as Dialog) ─────────────────────────────────────────
function SecretDetailDialog({ secretId, onClose }: { secretId: string; onClose: () => void }) {
  const [showValue, setShowValue] = useState(false)
  const [copied, setCopied] = useState(false)
  const { data: secret, isLoading } = useSecret(secretId)
  const { data: versions } = useSecretVersions(secretId)
  const rollback = useRollbackSecret()
  const update = useUpdateSecret()
  const { canWriteSecrets, canDeleteSecrets } = useAuth()
  const [editValue, setEditValue] = useState("")
  const [editing, setEditing] = useState(false)

  const valueStr = secret?.value
    ? typeof secret.value === "object"
      ? JSON.stringify(secret.value, null, 2)
      : String(secret.value)
    : ""

  const handleCopy = async () => {
    await navigator.clipboard.writeText(valueStr)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleUpdate = async () => {
    if (!secret) return
    await update.mutateAsync({ id: secret.id, payload: { value: editValue } })
    setEditing(false)
  }

  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-2xl">
        {isLoading || !secret ? (
          <div className="space-y-3 py-4">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-24 w-full" />
          </div>
        ) : (
          <>
            <DialogHeader>
              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/20">
                  <KeyRound className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <DialogTitle className="font-mono text-base">{secret.name}</DialogTitle>
                  <div className="mt-1 flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">{secret.namespace}</Badge>
                    <Badge variant="outline" className={`text-xs ${SECRET_TYPE_COLORS[secret.secret_type]}`}>
                      {secret.secret_type}
                    </Badge>
                    <span className="text-xs text-muted-foreground">v{secret.current_version}</span>
                  </div>
                </div>
              </div>
            </DialogHeader>

            <Tabs defaultValue="value">
              <TabsList className="w-full">
                <TabsTrigger value="value" className="flex-1">Value</TabsTrigger>
                <TabsTrigger value="versions" className="flex-1">Versions ({versions?.length ?? 0})</TabsTrigger>
                <TabsTrigger value="meta" className="flex-1">Metadata</TabsTrigger>
              </TabsList>

              <TabsContent value="value" className="space-y-3">
                <div className="relative rounded-lg border border-border bg-muted/30 p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Secret Value</span>
                    <div className="flex items-center gap-1">
                      <Button variant="ghost" size="icon" className="h-7 w-7" onClick={handleCopy}>
                        {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      </Button>
                      <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setShowValue((v) => !v)}>
                        {showValue ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                      </Button>
                    </div>
                  </div>
                  {editing ? (
                    <div className="space-y-2">
                      <Textarea
                        value={editValue}
                        onChange={(e) => setEditValue(e.target.value)}
                        className="min-h-[100px] font-mono text-xs"
                        autoFocus
                      />
                      <div className="flex gap-2">
                        <Button size="sm" onClick={handleUpdate} disabled={update.isPending}>
                          {update.isPending ? "Saving…" : "Save (new version)"}
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
                      </div>
                    </div>
                  ) : (
                    <pre className={`text-sm font-mono break-all whitespace-pre-wrap ${!showValue ? "select-none" : ""}`}>
                      {showValue ? valueStr : "•".repeat(Math.min(valueStr.length, 32))}
                    </pre>
                  )}
                </div>
                {canWriteSecrets && !editing && (
                  <Button variant="outline" size="sm" onClick={() => { setEditValue(valueStr); setEditing(true) }}>
                    <Pencil className="h-3.5 w-3.5 mr-1.5" /> Update Value
                  </Button>
                )}
              </TabsContent>

              <TabsContent value="versions" className="space-y-2">
                {versions?.map((v) => (
                  <div key={v.id} className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-bold ${v.is_current ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"}`}>
                        v{v.version}
                      </div>
                      <div>
                        <p className="text-sm font-medium">{v.is_current ? "Current" : `Version ${v.version}`}</p>
                        <p className="text-xs text-muted-foreground">{formatDateTime(v.created_at)}</p>
                      </div>
                    </div>
                    {!v.is_current && canWriteSecrets && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => rollback.mutate({ id: secretId, version: v.version })}
                        disabled={rollback.isPending}
                      >
                        <RefreshCw className="h-3 w-3 mr-1.5" />
                        Rollback
                      </Button>
                    )}
                  </div>
                ))}
              </TabsContent>

              <TabsContent value="meta" className="space-y-3 text-sm">
                <div className="rounded-lg border border-border divide-y divide-border">
                  {[
                    ["ID", secret.id],
                    ["Created", formatDateTime(secret.created_at)],
                    ["Updated", formatDateTime(secret.updated_at)],
                    ["Description", secret.description ?? "—"],
                    ["Current Version", String(secret.current_version)],
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between px-4 py-2.5">
                      <span className="text-muted-foreground">{k}</span>
                      <span className="font-mono text-xs max-w-[60%] truncate text-right">{v}</span>
                    </div>
                  ))}
                </div>
              </TabsContent>
            </Tabs>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function SecretsPage() {
  const [search, setSearch] = useState("")
  const [namespace, setNamespace] = useState("")
  const [page, setPage] = useState(1)
  const [createOpen, setCreateOpen] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)

  const { canWriteSecrets, canDeleteSecrets } = useAuth()
  const deleteSecret = useDeleteSecret()

  const { data, isLoading } = useSecrets({
    page,
    page_size: 20,
    namespace: namespace || undefined,
  })

  const filtered = data?.items.filter((s) =>
    !search || s.name.toLowerCase().includes(search.toLowerCase())
  ) ?? []

  const totalPages = Math.ceil((data?.total ?? 0) / 20)

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Toolbar */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search secrets…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
          <Input
            placeholder="Namespace filter…"
            value={namespace}
            onChange={(e) => { setNamespace(e.target.value); setPage(1) }}
            className="w-40"
          />
        </div>
        {canWriteSecrets && (
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4 mr-1.5" />
            New Secret
          </Button>
        )}
      </div>

      {/* Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">Name</th>
                <th className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">Namespace</th>
                <th className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">Type</th>
                <th className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">Version</th>
                <th className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">Updated</th>
                <th className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading
                ? Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 6 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <Skeleton className="h-4 w-full" />
                      </td>
                    ))}
                  </tr>
                ))
                : filtered.length === 0
                ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-16 text-center">
                      <KeyRound className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" />
                      <p className="text-sm text-muted-foreground">No secrets found</p>
                      {canWriteSecrets && (
                        <Button variant="link" className="mt-2" onClick={() => setCreateOpen(true)}>
                          Create your first secret
                        </Button>
                      )}
                    </td>
                  </tr>
                )
                : filtered.map((secret) => (
                  <tr
                    key={secret.id}
                    className="group hover:bg-muted/30 cursor-pointer transition-colors"
                    onClick={() => setSelectedId(secret.id)}
                  >
                    <td className="px-4 py-3">
                      <span className="font-mono text-sm font-medium">{secret.name}</span>
                      {secret.description && (
                        <p className="text-xs text-muted-foreground mt-0.5 truncate max-w-[200px]">{secret.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className="text-xs">{secret.namespace}</Badge>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className={`text-xs ${SECRET_TYPE_COLORS[secret.secret_type]}`}>
                        {secret.secret_type}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      v{secret.current_version}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {formatRelative(secret.updated_at)}
                    </td>
                    <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setSelectedId(secret.id)}>
                          <Eye className="h-3.5 w-3.5" />
                        </Button>
                        {canDeleteSecrets && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 text-red-400 hover:text-red-400 hover:bg-red-400/10"
                            onClick={() => setDeleteId(secret.id)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-border px-4 py-3">
            <p className="text-xs text-muted-foreground">
              {data?.total} secrets · Page {page} of {totalPages}
            </p>
            <div className="flex gap-1">
              <Button size="sm" variant="outline" disabled={page === 1} onClick={() => setPage((p) => p - 1)}>
                Previous
              </Button>
              <Button size="sm" variant="outline" disabled={page === totalPages} onClick={() => setPage((p) => p + 1)}>
                Next
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* Create dialog */}
      <CreateSecretDialog open={createOpen} onClose={() => setCreateOpen(false)} />

      {/* Detail dialog */}
      {selectedId && (
        <SecretDetailDialog secretId={selectedId} onClose={() => setSelectedId(null)} />
      )}

      {/* Delete confirm */}
      {deleteId && (
        <Dialog open onOpenChange={(v) => { if (!v) setDeleteId(null) }}>
          <DialogContent className="max-w-sm">
            <DialogHeader>
              <DialogTitle>Delete Secret?</DialogTitle>
              <DialogDescription>
                This will soft-delete the secret and all its versions. This action cannot be easily undone.
              </DialogDescription>
            </DialogHeader>
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>All versions will be marked inactive.</AlertDescription>
            </Alert>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
              <Button
                variant="destructive"
                onClick={async () => {
                  await deleteSecret.mutateAsync(deleteId)
                  setDeleteId(null)
                }}
                disabled={deleteSecret.isPending}
              >
                {deleteSecret.isPending ? "Deleting…" : "Delete"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}
