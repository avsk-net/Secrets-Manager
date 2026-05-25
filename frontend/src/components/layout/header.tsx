"use client"

import { usePathname } from "next/navigation"
import { LogOut, User, KeyRound, ChevronDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Badge } from "@/components/ui/badge"
import { useAuth } from "@/contexts/auth-context"
import { getInitials, ROLE_COLORS, ROLE_LABELS } from "@/lib/utils"

const PAGE_TITLES: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/secrets": "Secrets",
  "/users": "Users",
  "/audit": "Audit Log",
}

export function Header() {
  const pathname = usePathname()
  const { user, logout } = useAuth()

  const title = Object.entries(PAGE_TITLES).find(([path]) =>
    pathname === path || pathname.startsWith(path + "/")
  )?.[1] ?? "SecretManager"

  return (
    <header className="flex h-16 items-center justify-between border-b border-border bg-card px-6">
      <div>
        <h1 className="text-lg font-semibold">{title}</h1>
      </div>

      <div className="flex items-center gap-3">
        {user && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="flex items-center gap-2 px-2">
                <Avatar className="h-7 w-7">
                  <AvatarFallback className="text-[10px] bg-primary/20 text-primary">
                    {getInitials(user.username)}
                  </AvatarFallback>
                </Avatar>
                <div className="flex flex-col items-start">
                  <span className="text-sm font-medium leading-none">{user.username}</span>
                  <span className="mt-0.5 text-[10px] text-muted-foreground">{user.email}</span>
                </div>
                <ChevronDown className="h-3 w-3 text-muted-foreground" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-52">
              <DropdownMenuLabel className="font-normal">
                <div className="flex flex-col gap-1">
                  <p className="text-sm font-medium">{user.username}</p>
                  <Badge className={ROLE_COLORS[user.role]} variant="outline">
                    {ROLE_LABELS[user.role]}
                  </Badge>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="gap-2 text-muted-foreground">
                <User className="h-4 w-4" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem className="gap-2 text-muted-foreground">
                <KeyRound className="h-4 w-4" />
                Change Password
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={logout}
                className="gap-2 text-red-400 focus:bg-red-400/10 focus:text-red-400"
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    </header>
  )
}
