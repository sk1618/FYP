// components/SeverityChart.jsx
// Pure SVG grouped bar chart — alert severity counts over the last 7 days.
// No chart library dependency; colours pulled from the design token palette.
import React, { useMemo } from "react";

const W    = 600;
const H    = 200;
const PAD  = { top: 16, right: 20, bottom: 40, left: 36 };
const IW   = W - PAD.left - PAD.right;
const IH   = H - PAD.top  - PAD.bottom;
const DAYS = 7;

const SEVERITIES = ["high", "medium", "low"];
const COLORS     = { high: "#f87171", medium: "#fbbf24", low: "#34d399" };

function getLast7Days() {
  return Array.from({ length: DAYS }, (_, i) => {
    const d = new Date();
    d.setDate(d.getDate() - (DAYS - 1 - i));
    return d.toISOString().slice(0, 10);
  });
}

function shortDay(dateStr) {
  return new Date(dateStr + "T00:00:00").toLocaleDateString([], { weekday: "short" });
}

export default function SeverityChart({ alerts }) {
  const days = useMemo(() => getLast7Days(), []);

  const counts = useMemo(() =>
    days.map((day) => {
      const dayAlerts = (alerts || []).filter(
        (a) => a.timestamp && new Date(a.timestamp).toISOString().slice(0, 10) === day
      );
      return {
        day,
        high:   dayAlerts.filter((a) => a.severity?.toLowerCase() === "high").length,
        medium: dayAlerts.filter((a) => a.severity?.toLowerCase() === "medium").length,
        low:    dayAlerts.filter((a) => a.severity?.toLowerCase() === "low").length,
      };
    }), [alerts, days]
  );

  const maxCount = useMemo(() => {
    const all = counts.flatMap((d) => [d.high, d.medium, d.low]);
    return Math.max(...all, 1);
  }, [counts]);

  const groupW = IW / DAYS;
  const barW   = Math.max(Math.floor((groupW - 10) / 3), 4);

  return (
    <div className="chart-container">
      <div className="chart-header">
        <span className="chart-title">Alert Trend — Last 7 Days</span>
        <div className="chart-legend">
          {SEVERITIES.map((s) => (
            <span key={s} className="chart-legend-item">
              <span className="chart-legend-dot" style={{ background: COLORS[s] }} />
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </span>
          ))}
        </div>
      </div>

      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="xMidYMid meet"
        style={{ width: "100%", height: "auto", display: "block" }}
        aria-label="Alert severity trend chart"
      >
        {/* Y-axis gridlines + labels */}
        {[0, 0.25, 0.5, 0.75, 1].map((pct) => {
          const y   = PAD.top + IH * (1 - pct);
          const val = Math.round(maxCount * pct);
          return (
            <g key={pct}>
              <line
                x1={PAD.left} y1={y} x2={PAD.left + IW} y2={y}
                stroke="rgba(255,255,255,0.06)" strokeWidth="1"
              />
              <text x={PAD.left - 6} y={y + 4} textAnchor="end" fontSize="9" fill="rgba(148,163,184,0.7)">
                {val}
              </text>
            </g>
          );
        })}

        {/* Bars + x-axis labels */}
        {counts.map((d, i) => {
          const groupX = PAD.left + i * groupW + 5;
          return (
            <g key={d.day}>
              {SEVERITIES.map((s, si) => {
                if (d[s] === 0) return null;
                const barH = (d[s] / maxCount) * IH;
                const x    = groupX + si * (barW + 2);
                const y    = PAD.top + IH - barH;
                return (
                  <rect key={s} x={x} y={y} width={barW} height={barH}
                    fill={COLORS[s]} opacity="0.85" rx="2">
                    <title>{`${s}: ${d[s]} on ${d.day}`}</title>
                  </rect>
                );
              })}
              <text
                x={groupX + (groupW - 10) / 2}
                y={PAD.top + IH + 16}
                textAnchor="middle" fontSize="9" fill="rgba(148,163,184,0.7)"
              >
                {shortDay(d.day)}
              </text>
            </g>
          );
        })}

        {/* Axes */}
        <line x1={PAD.left} y1={PAD.top} x2={PAD.left} y2={PAD.top + IH}
          stroke="rgba(255,255,255,0.12)" strokeWidth="1" />
        <line x1={PAD.left} y1={PAD.top + IH} x2={PAD.left + IW} y2={PAD.top + IH}
          stroke="rgba(255,255,255,0.12)" strokeWidth="1" />
      </svg>
    </div>
  );
}
