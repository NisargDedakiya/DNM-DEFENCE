const bandColor = (score) => {
  if (score >= 60) return '#E5484D' // critical
  if (score >= 35) return '#F5793A' // high
  if (score >= 15) return '#F0C808' // medium
  return '#33C481' // good
}

const bandLabel = (score) => {
  if (score >= 60) return 'Critical exposure'
  if (score >= 35) return 'Elevated risk'
  if (score >= 15) return 'Moderate risk'
  return 'Healthy posture'
}

export default function RiskScoreRadial({ score = 0, size = 168 }) {
  const radius = (size - 16) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - Math.min(score, 100) / 100)
  const color = bandColor(score)

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={radius} stroke="#232A38" strokeWidth="10" fill="none" />
          <circle
            cx={size / 2} cy={size / 2} r={radius}
            stroke={color} strokeWidth="10" fill="none" strokeLinecap="round"
            strokeDasharray={circumference} strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 0.6s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-4xl font-semibold" style={{ color }}>{score}</span>
          <span className="text-[10px] text-muted font-mono">/ 100</span>
        </div>
      </div>
      <span className="mt-3 text-sm font-medium" style={{ color }}>{bandLabel(score)}</span>
    </div>
  )
}
