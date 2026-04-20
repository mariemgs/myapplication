import { ColumnDef } from "@tanstack/react-table"
import { cn } from "@/lib/utils"
export const columns: ColumnDef<any>[] = [
  {
    accessorKey: "name",
    header: "Agent",
    cell: ({ row }) => (
      <div className="flex items-center gap-3">
        <span className="text-xl">{row.original.icon}</span>
        <span className="font-medium">{row.original.name}</span>
      </div>
    ),
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const { status } = row.original
      const isFailure = status === "failure"

      return (
        <span
          className={cn(
            "px-2 py-1 rounded-full text-xs font-semibold border",
            isFailure
              ? "bg-red-50 text-red-700 border-red-200"
              : "bg-green-50 text-green-700 border-green-200"
          )}
        >
          {status}
        </span>
      )
    },
  },
  {
    accessorKey: "conclusion",
    header: "Conclusion",
    cell: ({ row }) => {
      const { conclusion } = row.original
      const isFailure = conclusion === "failure"
      const isSkipped = conclusion === "skipped"


      return (
        <span
          className={cn(
            "px-2 py-1 rounded-full text-xs font-semibold border",
            isFailure
              ? "bg-red-50 text-red-700 border-red-200" :
              isSkipped
                ? "bg-gray-100 text-gray-600 border-gray-200"
                : "bg-green-50 text-green-700 border-green-200"
          )}
        >
          {conclusion}
        </span>
      )
    },
  },
  {
    accessorKey: "last_run",
    header: "Last Run",
    cell: ({ row }) => {
      const lastRun = row.original.last_run
      return (
        <div className="text-sm">
          <div>{lastRun}</div>
          <div className="text-xs text-muted-foreground">Run #{row.original.run_number}</div>
        </div>
      )
    },
  },
  {
    accessorKey: "description",
    header: "Description",
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground block max-w-[200px] truncate">
        {row.original.description}
      </span>
    ),
  },
  {
    id: "actions",
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => (
      <div className="flex justify-end gap-2">
        {row.original.last_run_url && (
          <a
            href={row.original.last_run_url}
            target="_blank"
            rel="noreferrer"
            className="text-xs text-muted-foreground hover:text-foreground hover:underline"
          >
            Logs
          </a>
        )}
        {/* Placeholder for your trigger/retry logic */}
        <button className="text-xs font-medium text-indigo-600 hover:text-indigo-800">
          Retry
        </button>
      </div>
    ),
  },
]