const COLORS = {
  critical: 'text-critical border-critical/40 bg-critical/10',
  high: 'text-high border-high/40 bg-high/10',
  medium: 'text-medium border-medium/40 bg-medium/10',
  low: 'text-low border-low/40 bg-low/10',
  info: 'text-muted border-border bg-panel2',
}

export default function SeverityBadge({ severity }) {
  const cls = COLORS[severity] || COLORS.info
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-mono uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  )
}
