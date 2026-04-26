import { ColumnDef } from "@tanstack/react-table"

export const columns: ColumnDef<any>[] = [
  {
    accessorKey: "type",
    header: "Type",
    cell: ({ row }) => <span className="capitalize">{row.getValue("type")}</span>,
  },
  {
    accessorKey: "body",
    header: "Report Summary",
    cell: ({ row }) => <div className="max-w-[300px] truncate">{row.getValue("body")}</div>,
  },
  {
    accessorKey: "commit_id",
    header: "Commit",
    cell: ({ row }) => <code className="bg-muted px-1 rounded">{row.getValue("commit_id")}</code>,
  },
  {
    accessorKey: "created_at",
    header: "Time",
  },
  {
    id: "actions",
    cell: ({ row }) => (
      <a href={row.original.url} target="_blank" className="text-blue-600 hover:underline">
        View
      </a>
    ),
  },
]