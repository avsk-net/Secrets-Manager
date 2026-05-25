"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  LayoutDashboard,
  KeyRound,
  Users,
  ScrollText,
  ShieldCheck,
  ChevronRight,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { useAuth } from "@/contexts/auth-context"

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, always: true },
  { href: "/secrets", label: "Secrets", icon: KeyRound, always: true },
  { href: "/users", label: "Users", icon: Users, adminOnly: true },
  { href: "/audit", label: "Audit Log", icon: ScrollText, adminOnly: true },
]

export function Sidebar() {
  const pathname = usePathname()
  const { canManageUsers, canViewAudit } = useAuth()

  const visible = navItems.filter(
    (item) => item.always || (item.adminOnly && (canManageUsers || canViewAudit))
  )

  return (
    <aside className="flex h-full w-60 flex-col border-r border-border bg-card">
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b border-border px-6">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/20 ring-1 ring-primary/40">
          <ShieldCheck className="h-4 w-4 text-primary" />
        </div>
        <div>
          <p className="text-sm font-semibold leading-none">SecretManager</p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">Vault · v1.0</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-1 p-3">
        <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Navigation
        </p>
        {visible.map((item) => {
          const active = pathname === item.href || pathname.startsWith(item.href + "/")
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all",
                active
                  ? "bg-primary/15 text-primary ring-1 ring-primary/20"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              )}
            >
              <item.icon className={cn("h-4 w-4 shrink-0", active ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
              <span className="flex-1">{item.label}</span>
              {active && <ChevronRight className="h-3 w-3 text-primary" />}
            </Link>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-border p-3">
        <div className="rounded-lg bg-primary/5 px-3 py-2 ring-1 ring-primary/10">
          <p className="text-[10px] font-medium text-primary">AES-256-GCM Encrypted</p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">All secrets at rest</p>
        </div>
      </div>
    </aside>
  )
}
