import { Link } from "@tanstack/react-router"
import { useTheme } from "@/components/theme-provider"
import { cn } from "@/lib/utils"
import logo from "/assets/images/sofiatech.png"
import logoLight from "/assets/images/sofiatech.png"

interface LogoProps {
  className?: string
  asLink?: boolean
}

export function Logo({
  className,
  asLink = true,
}: LogoProps) {
  const { resolvedTheme } = useTheme()
  const isDark = resolvedTheme === "dark"
  const fullLogo = isDark ? logoLight : logo

  const content = (
    <img
      src={fullLogo}
      alt="SofiaTech"
      className={cn("h-6 w-auto group-data-[collapsible=icon]:hidden", className)}
    />
  )

  if (!asLink) {
    return content
  }

  return <Link to="/">{content}</Link>
}