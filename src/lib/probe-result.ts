// napps/security-lab/src/lib/probe-result.ts
// Pure probe-result builders and formatting helpers, extracted from App.svelte so
// they can be unit-tested without mounting the Svelte component (NAPP-01 test floor).

export type ProbeStatus = 'pending' | 'running' | 'pass' | 'fail' | 'warning' | 'skipped';

export interface ProbeResult {
  observed: string;
  status: ProbeStatus;
  evidence: string;
}

export function pass(observed: string, evidence: string): ProbeResult {
  return { observed, evidence, status: 'pass' };
}

export function fail(observed: string, evidence: string): ProbeResult {
  return { observed, evidence, status: 'fail' };
}

export function warning(observed: string, evidence: string): ProbeResult {
  return { observed, evidence, status: 'warning' };
}

export function skipped(evidence: string): ProbeResult {
  return { observed: 'Deferred', evidence, status: 'skipped' };
}

export function errorText(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

export function short(value: unknown): string {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (!text) return String(value);
  return text.length > 160 ? `${text.slice(0, 157)}...` : text;
}
