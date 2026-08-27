import type { CSSProperties, ReactNode } from 'react';

// Adapted from mdrbx/nerv-ui at 2b05d2a. See LICENSE in this directory.

export type NervTone = 'green' | 'orange' | 'red' | 'cyan' | 'muted';

export type NavigationTab = { id: string; label: string };

export function NavigationTabs({ tabs, activeTab, onTabChange }: {
  tabs: NavigationTab[];
  activeTab: string;
  onTabChange: (id: string) => void;
}) {
  return <nav className="nerv-navigation-tabs" role="tablist">
    {tabs.map((tab, index) => <button
      key={tab.id}
      type="button"
      role="tab"
      aria-selected={activeTab === tab.id}
      className={activeTab === tab.id ? 'active' : ''}
      onClick={() => onTabChange(tab.id)}
    ><small>{String(index + 1).padStart(2, '0')}</small><span>{tab.label}</span><i /></button>)}
  </nav>;
}

export type StatusZone = { start: number; end: number; color: string; label?: string };

export function GradientStatusBar({ value, min = 0, max = 100, zones, label, detail }: {
  value: number;
  min?: number;
  max?: number;
  zones: StatusZone[];
  label: string;
  detail: string;
}) {
  const range = Math.max(1, max - min);
  const pct = Math.max(0, Math.min(100, ((value - min) / range) * 100));
  const stop = (input: number) => Math.max(0, Math.min(100, ((input - min) / range) * 100));
  return <div className="nerv-gradient-status">
    <header><strong>{label}</strong><span>{detail}</span></header>
    <div className="nerv-gradient-labels">{zones.map((zone) => zone.label ? <span key={zone.label} style={{ left: `${stop(zone.start)}%` }}>{zone.label}</span> : null)}</div>
    <div className="nerv-gradient-track" role="meter" aria-label={label} aria-valuenow={value} aria-valuemin={min} aria-valuemax={max}>
      {zones.map((zone) => <i key={`${zone.start}-${zone.end}`} style={{ left: `${stop(zone.start)}%`, width: `${stop(zone.end) - stop(zone.start)}%`, background: zone.color }} />)}
      <span style={{ width: `${pct}%` }} />
      <b style={{ left: `${pct}%` }} />
    </div>
    <footer><span>{min}</span><span>{Math.round(min + range / 2)}</span><span>{max}</span></footer>
  </div>;
}

const toneColors: Record<NervTone, string> = {
  green: '#1bd98a', orange: '#ff9f1a', red: '#ff4d3d', cyan: '#22d3ee', muted: '#8290a3',
};

export function Gauge({ value, min = 0, max = 100, label, unit, tone = 'cyan', threshold }: {
  value: number | null;
  min?: number;
  max?: number;
  label: string;
  unit: string;
  tone?: NervTone;
  threshold?: number;
}) {
  const safeValue = value ?? min;
  const pct = Math.max(0, Math.min(1, (safeValue - min) / Math.max(1, max - min)));
  const activeTone: NervTone = value !== null && threshold !== undefined && value > threshold ? 'red' : tone;
  const color = toneColors[activeTone];
  const radius = 34;
  const circumference = Math.PI * radius;
  const style = { '--nerv-gauge-color': color } as CSSProperties;
  return <div className={`nerv-gauge ${value === null ? 'empty' : ''}`} style={style}>
    <span>{label}</span>
    <svg viewBox="0 0 100 66" role="img" aria-label={`${label}: ${value === null ? '无数据' : `${value}${unit}`}`}>
      <path d="M 16 54 A 34 34 0 0 1 84 54" pathLength={circumference} className="track" />
      <path d="M 16 54 A 34 34 0 0 1 84 54" pathLength={circumference} className="value" style={{ strokeDasharray: `${pct * circumference} ${circumference}` }} />
      <line x1="50" y1="54" x2="50" y2="22" transform={`rotate(${-90 + pct * 180} 50 54)`} />
      <circle cx="50" cy="54" r="3" />
    </svg>
    <strong>{value === null ? '—' : value}<small>{value === null ? '' : unit}</small></strong>
    <footer><span>{min}</span><span>{max}</span></footer>
  </div>;
}

export type PhaseItem = { label: string; value: string; status: 'ok' | 'warning' | 'danger' | 'inactive' };

export function PhaseStatusStack({ title, phases }: { title: string; phases: PhaseItem[] }) {
  return <div className="nerv-phase-stack">
    <header>{title}</header>
    <div>{phases.map((phase) => <section className={phase.status} key={phase.label} title={`${phase.label}: ${phase.value}`}>
      <span>{phase.label}</span><i /><strong>{phase.value}</strong>
    </section>)}</div>
  </div>;
}

export type BarChartBar = { label: string; value: number; color?: string; detail?: string };

export function BarChart({ title, bars, max, unit, emptyText = '暂无性能样本' }: {
  title: string;
  bars: BarChartBar[];
  max?: number;
  unit: string;
  emptyText?: string;
}) {
  const ceiling = Math.max(max ?? 0, ...bars.map((bar) => bar.value), 1);
  return <div className="nerv-bar-chart">
    <header><strong>{title}</strong><span>{bars.length} 个数据源</span></header>
    {bars.length === 0 ? <div className="nerv-chart-empty">{emptyText}</div> : <div className="nerv-bar-rows">{bars.map((bar) => <div key={bar.label} title={bar.detail}>
      <span>{bar.label}</span>
      <div><i style={{ width: `${Math.max(1, bar.value / ceiling * 100)}%`, background: bar.color ?? '#22d3ee' }} /></div>
      <strong>{formatChartValue(bar.value)} {unit}</strong>
    </div>)}</div>}
  </div>;
}

function formatChartValue(value: number): string {
  if (value >= 100) return Math.round(value).toString();
  if (value >= 10) return value.toFixed(1);
  return value.toFixed(2);
}

export function NervPanel({ label, title, action, children, className = '' }: {
  label: string;
  title: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return <section className={`nerv-panel ${className}`}>
    <header><div><small>{label}</small><strong>{title}</strong></div>{action}</header>
    <div className="nerv-panel-body">{children}</div>
  </section>;
}
