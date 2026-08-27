import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { BarChart, Gauge, GradientStatusBar, NavigationTabs } from '.';

describe('local NERV UI adapters', () => {
  it('switches dashboard views through accessible tabs', () => {
    const onTabChange = vi.fn();
    render(<NavigationTabs
      tabs={[{ id: 'network', label: '全网态势' }, { id: 'nodes', label: '节点与性能' }]}
      activeTab="network"
      onTabChange={onTabChange}
    />);

    expect(screen.getByRole('tab', { name: /全网态势/ })).toHaveAttribute('aria-selected', 'true');
    fireEvent.click(screen.getByRole('tab', { name: /节点与性能/ }));
    expect(onTabChange).toHaveBeenCalledWith('nodes');
  });

  it('keeps missing gauge data visibly distinct from a real zero', () => {
    const { rerender } = render(<Gauge label="平均 RTT" value={null} unit="ms" />);
    expect(screen.getByText('—')).toBeInTheDocument();
    expect(screen.getByRole('img')).toHaveAttribute('aria-label', '平均 RTT: 无数据');

    rerender(<Gauge label="平均 RTT" value={0} unit="ms" />);
    expect(screen.getByRole('img')).toHaveAttribute('aria-label', '平均 RTT: 0ms');
  });

  it('renders the performance empty state without synthesizing bars', () => {
    render(<BarChart title="节点实时吞吐" bars={[]} unit="Mbps" />);
    expect(screen.getByText('暂无性能样本')).toBeInTheDocument();
    expect(screen.getByText('0 个数据源')).toBeInTheDocument();
  });

  it('exposes status coverage as a meter', () => {
    render(<GradientStatusBar
      value={75}
      label="节点健康覆盖"
      detail="3 / 4 个节点正常"
      zones={[{ start: 0, end: 60, color: '#f00' }, { start: 60, end: 100, color: '#0f0' }]}
    />);
    const meter = screen.getByRole('meter', { name: '节点健康覆盖' });
    expect(meter).toHaveAttribute('aria-valuenow', '75');
    expect(meter).toHaveAttribute('aria-valuemin', '0');
    expect(meter).toHaveAttribute('aria-valuemax', '100');
  });
});
