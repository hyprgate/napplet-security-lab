import { describe, expect, it } from 'vitest';
import { filterProbes, runVerdict, type FilterableProbe } from './probe-filter';

const probe = (id: string, status: FilterableProbe['status'], extra: Partial<FilterableProbe> = {}): FilterableProbe => ({
  id,
  status,
  level: 'baseline',
  category: 'Network',
  probe: `Probe ${id}`,
  expected: 'Denied',
  observed: 'Denied',
  evidence: 'TypeError: Failed to fetch',
  ownerArea: 'CSP',
  severity: 'high',
  ...extra,
});
const counts = (patch: Partial<Record<FilterableProbe['status'], number>>) => ({ pending: 0, running: 0, pass: 0, fail: 0, warning: 0, skipped: 0, ...patch });

describe('filterProbes', () => {
  const rows = [
    probe('a', 'fail'),
    probe('b', 'pass', { level: 'safe-adversarial' }),
    probe('c', 'warning', { category: 'Storage', evidence: 'quota exceeded' }),
  ];
  const ids = (filters: Partial<{ status: 'all' | 'fail' | 'warning' | 'pass' | 'skipped'; level: string; query: string }>) =>
    filterProbes(rows, { status: 'all', level: 'all', query: '', ...filters }).map((row) => row.id);

  it('narrows to one result, which is the point of a run', () => {
    expect(ids({})).toEqual(['a', 'b', 'c']);
    expect(ids({ status: 'fail' })).toEqual(['a']);
    expect(ids({ status: 'skipped' })).toEqual([]);
  });

  it('combines level and search, and searches evidence', () => {
    expect(ids({ level: 'safe-adversarial' })).toEqual(['b']);
    expect(ids({ query: 'QUOTA' })).toEqual(['c']);
    expect(ids({ status: 'pass', query: 'quota' })).toEqual([]);
  });
});

describe('runVerdict', () => {
  it('reports progress while probes run', () => {
    expect(runVerdict(counts({ pass: 3, running: 1, pending: 6 }))).toEqual({ tone: 'running', text: 'Running: 3 of 10 probes done.' });
  });

  it('leads with failures, and never counts skipped probes as passes', () => {
    expect(runVerdict(counts({ pass: 8, fail: 1, warning: 2 })).tone).toBe('fail');
    expect(runVerdict(counts({ pass: 8, fail: 1, warning: 2 })).text).toBe('1 of 11 probes crossed a boundary, and 2 warnings to check.');
    expect(runVerdict(counts({ pass: 8, warning: 1 })).text).toBe('No boundary failures, but 1 warning to check.');
    expect(runVerdict(counts({ pass: 8, skipped: 2 })).text).toBe('All 8 probes that ran held their boundary, 2 skipped.');
  });
});
