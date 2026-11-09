// Pure filtering and verdict logic for the probe table, so it can be tested without
// running any probes.

import type { ProbeStatus } from './probe-result';

export type StatusFilter = 'all' | 'fail' | 'warning' | 'pass' | 'skipped';

export interface FilterableProbe {
  id: string;
  level: string;
  category: string;
  probe: string;
  expected: string;
  observed: string;
  evidence: string;
  ownerArea: string;
  severity: string;
  status: ProbeStatus;
}

export interface ProbeFilters {
  status: StatusFilter;
  level: string;
  query: string;
}

export function filterProbes<T extends FilterableProbe>(rows: T[], filters: ProbeFilters): T[] {
  const needle = filters.query.trim().toLowerCase();
  return rows.filter((row) => {
    if (filters.status !== 'all' && row.status !== filters.status) return false;
    if (filters.level !== 'all' && row.level !== filters.level) return false;
    if (!needle) return true;
    return [row.id, row.category, row.probe, row.expected, row.observed, row.evidence, row.ownerArea, row.severity]
      .some((value) => value.toLowerCase().includes(needle));
  });
}

export interface RunVerdict {
  tone: 'running' | 'fail' | 'warning' | 'pass' | 'idle';
  text: string;
}

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;

/** One sentence on how the run went. Skipped probes never count as passing. */
export function runVerdict(counts: Record<ProbeStatus, number>): RunVerdict {
  const unfinished = counts.pending + counts.running;
  const total = unfinished + counts.pass + counts.fail + counts.warning + counts.skipped;
  if (counts.running > 0 || (unfinished > 0 && unfinished < total)) {
    return { tone: 'running', text: `Running: ${total - unfinished} of ${total} probes done.` };
  }
  if (unfinished > 0) return { tone: 'idle', text: `${plural(total, 'probe')} not run yet.` };
  const notes = counts.skipped > 0 ? `, ${counts.skipped} skipped` : '';
  if (counts.fail > 0) {
    return { tone: 'fail', text: `${counts.fail} of ${total} probes crossed a boundary${counts.warning > 0 ? `, and ${plural(counts.warning, 'warning')} to check` : ''}${notes}.` };
  }
  if (counts.warning > 0) {
    return { tone: 'warning', text: `No boundary failures, but ${plural(counts.warning, 'warning')} to check${notes}.` };
  }
  return { tone: 'pass', text: `All ${counts.pass} probes that ran held their boundary${notes}.` };
}
