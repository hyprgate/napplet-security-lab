// napplets/security-lab/src/lib/security-lab-smoke.test.ts
// Minimal smoke coverage for the security-lab probe-result builders (NAPP-01 test floor).
// Asserts the deterministic ProbeResult shape the probe catalog depends on, without
// touching network/sandbox behavior.

import { describe, it, expect } from 'vitest';
import { pass, fail, warning, skipped, errorText, short } from './probe-result';

describe('security-lab probe-result builders', () => {
  it('pass produces a pass status carrying observed + evidence', () => {
    expect(pass('Allowed', 'no direct channel')).toEqual({
      observed: 'Allowed',
      evidence: 'no direct channel',
      status: 'pass',
    });
  });

  it('fail/warning tag their status correctly', () => {
    expect(fail('Leaked', 'reached origin').status).toBe('fail');
    expect(warning('Unavailable', 'runtime denied').status).toBe('warning');
  });

  it('skipped marks deferred probes', () => {
    const result = skipped('not applicable in jsdom');
    expect(result.status).toBe('skipped');
    expect(result.observed).toBe('Deferred');
  });
});

describe('security-lab formatting helpers', () => {
  it('errorText renders Error name + message, stringifies non-errors', () => {
    expect(errorText(new TypeError('boom'))).toBe('TypeError: boom');
    expect(errorText('plain')).toBe('plain');
  });

  it('short truncates strings over 160 chars with an ellipsis', () => {
    const long = 'x'.repeat(200);
    const out = short(long);
    expect(out.length).toBe(160);
    expect(out.endsWith('...')).toBe(true);
  });

  it('short leaves short strings intact', () => {
    expect(short('tiny')).toBe('tiny');
  });
});
