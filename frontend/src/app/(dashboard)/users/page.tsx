"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Plus, Users, UserCheck, UserX, Shield } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"
import { useUsers, useCreateUser, useUpdateUser } from "@/hooks/use-users"
import { useAuth } from "@/contexts/auth-context"
import { formatRelative, ROLE_COLORS, ROLE_LABELS, getInitials } from "@/lib/utils"
import type { UserResponse, UserRole } from "@/types"

const createSchema = z.object({
  username: z.string().min(3).max(100).regex(/^[a-zA-Z0-9_.-]+$/),
  email: z.string().email(),
  password: z.string().min(16, "Min 16 characters")
    .regex(/[A-Z]/, "Must contain uppercase")
    .regex(/[a-z]/, "Must contain lowercase")
    .regex(/[0-9]/, "Must contain digit")
    .regex(/[^a-zA-Z0-9]/, "Must contain special character"),
  role: z.enum(["readonly", "developer", "admin", "super_admin"]),
})
type CreateForm = z.infer<typeof createSchema>

function CreateUserDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateUser()
  const { user } = useAuth()
  const { register, handleSubmit, reset, setValue, formState: { errors, isSubmitting } } = useForm<CreateForm>({
    resolver: zodResolver(createSchema),
    defaultValues: { role: "readonly" },
  })

  const onSubmit = async (data: CreateForm) => {
    await create.mutateAsync(data)
    reset()
    onClose()
  }

  const allowedRoles: UserRole[] =
    user?.role === "super_admin"
      ? ["readonly", "developer", "admin", "super_admin"]
      : ["readonly", "developer", "admin"]

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) { reset(); onClose() } }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create User</DialogTitle>
          <DialogDescription>Add a new user to the system.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-1.5">
            <Label>Username</Label>
            <Input placeholder="john.doe" {...register("username")} />
            {errors.username && <p className="text-xs text-destructive">{errors.username.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label>Email</Label>
            <Input type="email" placeholder="john@company.com" {...register("email")} />
            {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label>Password</Label>
            <Input type="password" placeholder="Min 16 chars with mixed case + symbol" {...register("password")} />
            {errors.password && <p className="text-xs text-destructive">{errors.password.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label>Role</Label>
            <Select defaultValue="readonly" onValueChange={(v) => setValue("role", v as UserRole)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {allowedRoles.map((r) => (
                  <SelectItem key={r} value={r}>{ROLE_LABELS[r]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => { reset(); onClose() }}>Cancel</Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Creating…" : "Create User"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function RoleBadge({ role }: { role: UserRole }) {
  return (
    <Badge variant="outline" className={`text-xs ${ROLE_COLORS[role]}`}>
      {ROLE_LABELS[role]}
    </Badge>
  )
}

export default function UsersPage() {
  const [createOpen, setCreateOpen] = useState(false)
  const [page, setPage] = useState(1)
  const { data, isLoading } = useUsers({ page, page_size: 20 })
  const updateUser = useUpdateUser()
  const { user: currentUser } = useAuth()

  const totalPages = Math.ceil((data?.total ?? 0) / 20)

  const toggleActive = async (u: UserResponse) => {
    await updateUser.mutateAsync({ id: u.id, payload: { is_active: !u.is_active } })
  }

  const toggleLock = async (u: UserResponse) => {
    await updateUser.mutateAsync({ id: u.id, payload: { is_locked: !u.is_locked } })
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">{data?.total ?? 0} total users</p>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />
          New User
        </Button>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left">
                {["User", "Role", "Status", "Last Login", "Actions"].map((h) => (
                  <th key={h} className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading
                ? Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 5 }).map((_, j) => (
                      <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-full" /></td>
                    ))}
                  </tr>
                ))
                : data?.items.map((u) => (
                  <tr key={u.id} className="group hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <Avatar className="h-8 w-8">
                          <AvatarFallback className="text-xs bg-primary/20 text-primary">
                            {getInitials(u.username)}
                          </AvatarFallback>
                        </Avatar>
                        <div>
                          <p className="text-sm font-medium">{u.username}</p>
                          <p className="text-xs text-muted-foreground">{u.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3"><RoleBadge role={u.role} /></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        {u.is_active ? (
                          <Badge variant="success" className="gap-1 text-xs">
                            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 inline-block" />
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-muted-foreground text-xs">Inactive</Badge>
                        )}
                        {u.is_locked && (
                          <Badge variant="error" className="text-xs">Locked</Badge>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {u.last_login_at ? formatRelative(u.last_login_at) : "Never"}
                    </td>
                    <td className="px-4 py-3">
                      {u.id !== currentUser?.id && (
                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => toggleActive(u)}
                            disabled={updateUser.isPending}
                          >
                            {u.is_active ? <UserX className="h-3 w-3 mr-1" /> : <UserCheck className="h-3 w-3 mr-1" />}
                            {u.is_active ? "Deactivate" : "Activate"}
                          </Button>
                          {u.is_locked && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 text-xs"
                              onClick={() => toggleLock(u)}
                              disabled={updateUser.isPending}
                            >
                              <Shield className="h-3 w-3 mr-1" /> Unlock
                            </Button>
                          )}
                        </div>
                      )}
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

      <CreateUserDialog open={createOpen} onClose={() => setCreateOpen(false)} />
    </div>
  )
}
