<script lang="ts">
  import { onMount } from 'svelte';
  import { inc, identity, relay, resource, storage } from '@napplet/sdk';
  import {
    pass,
    fail,
    warning,
    skipped,
    errorText,
    short,
    type ProbeStatus,
    type ProbeResult,
  } from './lib/probe-result';

  type ProbeLevel = 'baseline' | 'runtime-mediated' | 'safe-adversarial';
  type ExpectedResult = 'denied' | 'absent' | 'unusable' | 'opaque' | 'allowed-via-runtime';
  type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
  type OwnerArea = 'Runtime' | 'CSP' | 'sandbox' | 'launcher' | 'SDK' | 'future-work';

  interface ProbeDefinition {
    id: string;
    level: ProbeLevel;
    category: string;
    probe: string;
    expected: string;
    expectedResult: ExpectedResult;
    severity: Severity;
    ownerArea: OwnerArea;
    run: () => Promise<ProbeResult>;
  }

  type ProbeRow = ProbeDefinition & ProbeResult & { lastRun: string };

  const externalUrl = 'https://example.invalid/hyprgate-security-lab-probe';
  const sameOriginAssetPath = ['', '__hyprgate', 'napplets', 'security-lab', 'assets', 'unexpected.js'].join('/');
  const sameOriginAssetUrl = `${location.origin}${sameOriginAssetPath}`;

  function timeout<T>(promise: Promise<T>, ms = 900): Promise<T | 'timeout'> {
    return new Promise((resolve, reject) => {
      const id = window.setTimeout(() => resolve('timeout'), ms);
      promise.then((value) => {
        window.clearTimeout(id);
        resolve(value);
      }).catch((err) => {
        window.clearTimeout(id);
        reject(err);
      });
    });
  }

  async function expectDenied(action: () => Promise<unknown> | unknown): Promise<ProbeResult> {
    try {
      const result = await timeout(Promise.resolve().then(action));
      if (result === 'timeout') return pass('Timed out / unusable', 'No successful result before timeout');
      return fail('Unexpected success', short(result));
    } catch (err) {
      return pass('Denied', errorText(err));
    }
  }

  async function expectElementBlocked(create: () => HTMLElement): Promise<ProbeResult> {
    const element = create();
    element.style.position = 'fixed';
    element.style.left = '-9999px';
    element.style.width = '1px';
    element.style.height = '1px';

    return new Promise((resolve) => {
      let settled = false;
      const done = (result: ProbeResult) => {
        if (settled) return;
        settled = true;
        element.remove();
        resolve(result);
      };

      element.addEventListener('load', () => done(fail('Unexpected load', `${element.tagName.toLowerCase()} load event fired`)), { once: true });
      element.addEventListener('error', () => done(pass('Denied', `${element.tagName.toLowerCase()} error event fired`)), { once: true });
      document.body.append(element);
      window.setTimeout(() => done(pass('No load', 'No successful load before timeout')), 900);
    });
  }

  async function expectNoReplyToParentMessage(payload: Record<string, unknown>): Promise<ProbeResult> {
    const id = String(payload.id ?? `security-lab-${crypto.randomUUID()}`);
    const message = { ...payload, id };
    return new Promise((resolve) => {
      let settled = false;
      const finish = (result: ProbeResult) => {
        if (settled) return;
        settled = true;
        window.removeEventListener('message', onMessage);
        resolve(result);
      };
      const onMessage = (event: MessageEvent) => {
        const data = event.data as { id?: unknown; type?: unknown } | null;
        if (data?.id === id) {
          finish(fail('Unexpected reply', `Received ${String(data.type ?? 'unknown')} for forged id`));
        }
      };
      window.addEventListener('message', onMessage);
      window.parent.postMessage(message, '*');
      window.setTimeout(() => finish(pass('Ignored', `No reply for forged message id=${id}`)), 350);
    });
  }

  async function expectParentInaccessible(read: () => unknown): Promise<ProbeResult> {
    try {
      const value = read();
      return fail('Parent/top readable', short(value));
    } catch (err) {
      return pass('Denied', errorText(err));
    }
  }

  function getAmbientNostr(): Record<string, unknown> | undefined {
    const key = ['nos', 'tr'].join('');
    const value = Reflect.get(window as unknown as object, key);
    return value && typeof value === 'object'
      ? value as Record<string, unknown>
      : undefined;
  }

  async function expectAmbientNostrAbsent(method: string): Promise<ProbeResult> {
    const ambientLabel = ['window', 'nostr'].join('.');
    const nostr = getAmbientNostr();
    if (!nostr) return pass('Absent', `${ambientLabel} is not present`);
    const value = method.split('.').reduce<unknown>((current, part) => {
      if (!current || typeof current !== 'object') return undefined;
      return (current as Record<string, unknown>)[part];
    }, nostr);
    return typeof value === 'function'
      ? fail('Ambient method present', `${ambientLabel}.${method} is callable`)
      : pass('Method absent', `${ambientLabel} exists but ${method} is not callable`);
  }

  const definitions: ProbeDefinition[] = [
    {
      id: 'origin.null',
      level: 'baseline',
      category: 'Sandbox',
      probe: 'Opaque origin reports null',
      expected: 'Class-1 iframe has an opaque origin without same-origin privilege',
      expectedResult: 'opaque',
      severity: 'critical',
      ownerArea: 'sandbox',
      run: async () => window.origin === 'null'
        ? pass('origin=null', 'window.origin is null')
        : fail(`origin=${window.origin}`, 'window.origin was not null'),
    },
    {
      id: 'storage.local',
      level: 'baseline',
      category: 'Storage',
      probe: 'Direct localStorage access',
      expected: 'Browser localStorage is unavailable in the opaque-origin iframe',
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'sandbox',
      run: () => expectDenied(() => localStorage.setItem('security-lab-direct', '1')),
    },
    {
      id: 'storage.session',
      level: 'baseline',
      category: 'Storage',
      probe: 'Direct sessionStorage access',
      expected: 'Browser sessionStorage is unavailable in the opaque-origin iframe',
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'sandbox',
      run: () => expectDenied(() => sessionStorage.setItem('security-lab-direct', '1')),
    },
    {
      id: 'storage.indexeddb',
      level: 'baseline',
      category: 'Storage',
      probe: 'Direct indexedDB.open()',
      expected: 'IndexedDB is denied or unusable in the opaque-origin iframe',
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'sandbox',
      run: () => expectDenied(() => new Promise((resolve, reject) => {
        const request = indexedDB.open('security-lab-direct');
        request.onsuccess = () => resolve('indexedDB opened');
        request.onerror = () => reject(request.error ?? new Error('indexedDB error'));
        request.onblocked = () => reject(new Error('indexedDB blocked'));
      })),
    },
    {
      id: 'storage.serviceworker',
      level: 'baseline',
      category: 'Storage',
      probe: 'Service worker registration',
      expected: 'Service workers cannot be registered from the sandbox',
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'sandbox',
      run: () => expectDenied(() => navigator.serviceWorker.register('/security-lab-sw.js')),
    },
    {
      id: 'network.fetch.external',
      level: 'baseline',
      category: 'Network',
      probe: 'Direct external fetch',
      expected: "Direct fetch is blocked by connect-src 'none'",
      expectedResult: 'denied',
      severity: 'critical',
      ownerArea: 'CSP',
      run: () => expectDenied(() => fetch(externalUrl, { mode: 'no-cors' })),
    },
    {
      id: 'network.xhr.external',
      level: 'baseline',
      category: 'Network',
      probe: 'Direct external XMLHttpRequest',
      expected: "Direct XHR is blocked by connect-src 'none'",
      expectedResult: 'denied',
      severity: 'critical',
      ownerArea: 'CSP',
      run: () => expectDenied(() => new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('GET', externalUrl);
        xhr.onload = () => resolve(`status=${xhr.status}`);
        xhr.onerror = () => reject(new Error('XHR error'));
        xhr.ontimeout = () => reject(new Error('XHR timeout'));
        xhr.timeout = 800;
        xhr.send();
      })),
    },
    {
      id: 'network.websocket.external',
      level: 'baseline',
      category: 'Network',
      probe: 'Direct external WebSocket',
      expected: "Direct WebSocket is blocked by connect-src 'none'",
      expectedResult: 'denied',
      severity: 'critical',
      ownerArea: 'CSP',
      run: () => expectDenied(() => new Promise((resolve, reject) => {
        const ws = new WebSocket('wss://example.invalid/hyprgate-security-lab');
        ws.onopen = () => resolve('websocket opened');
        ws.onerror = () => reject(new Error('WebSocket error'));
        window.setTimeout(() => reject(new Error('WebSocket timeout')), 800);
      })),
    },
    {
      id: 'network.eventsource.external',
      level: 'baseline',
      category: 'Network',
      probe: 'Direct external EventSource',
      expected: "Direct EventSource is blocked by connect-src 'none'",
      expectedResult: 'denied',
      severity: 'critical',
      ownerArea: 'CSP',
      run: () => expectDenied(() => new Promise((resolve, reject) => {
        const es = new EventSource(externalUrl);
        es.onopen = () => resolve('eventsource opened');
        es.onerror = () => {
          es.close();
          reject(new Error('EventSource error'));
        };
        window.setTimeout(() => {
          es.close();
          reject(new Error('EventSource timeout'));
        }, 800);
      })),
    },
    {
      id: 'resource.image.external',
      level: 'baseline',
      category: 'Resource',
      probe: 'External image element load',
      expected: 'External image loads fail under Class-1 resource policy',
      expectedResult: 'denied',
      severity: 'medium',
      ownerArea: 'CSP',
      run: () => expectElementBlocked(() => {
        const img = document.createElement('img');
        img.src = `${externalUrl}.png`;
        return img;
      }),
    },
    {
      id: 'resource.script.external',
      level: 'baseline',
      category: 'Resource',
      probe: 'External script element load',
      expected: 'External scripts fail under Class-1 script policy',
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'CSP',
      run: () => expectElementBlocked(() => {
        const script = document.createElement('script');
        script.src = `${externalUrl}.js`;
        return script;
      }),
    },
    {
      id: 'resource.style.external',
      level: 'baseline',
      category: 'Resource',
      probe: 'External stylesheet load',
      expected: 'External stylesheets fail under Class-1 style policy',
      expectedResult: 'denied',
      severity: 'medium',
      ownerArea: 'CSP',
      run: () => expectElementBlocked(() => {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = `${externalUrl}.css`;
        return link;
      }),
    },
    {
      id: 'resource.font.external',
      level: 'baseline',
      category: 'Resource',
      probe: 'External font load',
      expected: 'External fonts fail under Class-1 font policy',
      expectedResult: 'denied',
      severity: 'medium',
      ownerArea: 'CSP',
      run: () => expectDenied(() => new FontFace('SecurityLabProbe', `url(${externalUrl}.woff2)`).load()),
    },
    {
      id: 'resource.asset.sameorigin',
      level: 'baseline',
      category: 'Resource',
      probe: 'Unexpected shell-owned runtime asset path',
      expected: 'Built-in delivery refuses unexpected same-origin asset paths',
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'launcher',
      run: () => expectElementBlocked(() => {
        const script = document.createElement('script');
        script.src = sameOriginAssetUrl;
        return script;
      }),
    },
    {
      id: 'worker.blob',
      level: 'baseline',
      category: 'Worker',
      probe: 'Blob worker construction',
      expected: "Workers fail under worker-src 'none'",
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'CSP',
      // `new Worker(blobUrl)` does NOT throw synchronously under worker-src 'none';
      // the constructor succeeds and the block surfaces asynchronously. So we don't
      // assert on construction — we assert the worker never *executes* attacker code.
      // Ground truth is the CSP violation report; the worker `message`/`error`
      // events and a no-execution timeout corroborate it.
      run: () => new Promise<ProbeResult>((resolve) => {
        let settled = false;
        let objectUrl: string | null = null;
        let worker: Worker | null = null;
        const onViolation = (event: SecurityPolicyViolationEvent) => {
          if (event.effectiveDirective === 'worker-src' || event.violatedDirective === 'worker-src') {
            done(pass('Denied', `CSP worker-src violation reported (blocked ${short(event.blockedURI)})`));
          }
        };
        function done(result: ProbeResult) {
          if (settled) return;
          settled = true;
          document.removeEventListener('securitypolicyviolation', onViolation);
          worker?.terminate();
          if (objectUrl) URL.revokeObjectURL(objectUrl);
          resolve(result);
        }
        document.addEventListener('securitypolicyviolation', onViolation);
        try {
          const blob = new Blob(['postMessage("opened")'], { type: 'text/javascript' });
          objectUrl = URL.createObjectURL(blob);
          worker = new Worker(objectUrl);
          // A blob worker runs immediately on start; a `message` is the only proof
          // its code executed (i.e. the block failed).
          worker.addEventListener('message', (event) =>
            done(fail('Unexpected success', `worker executed and posted ${short(event.data)}`)));
          worker.addEventListener('error', () =>
            done(pass('Denied', 'worker failed to start (error event fired)')));
        } catch (err) {
          // Some engines reject worker construction synchronously under CSP.
          done(pass('Denied', errorText(err)));
          return;
        }
        // No message before the deadline means the worker code never ran.
        window.setTimeout(() => done(pass('Denied', 'worker never executed before timeout')), 900);
      }),
    },
    {
      id: 'frame.child',
      level: 'baseline',
      category: 'Frame',
      probe: 'Child iframe external navigation',
      expected: "Child frames fail under frame-src 'none'",
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'CSP',
      // An <iframe> fires `load` (never `error`) even when its navigation is
      // CSP-blocked or fails — so a load event is NOT proof the external doc
      // loaded. Ground truth is the CSP violation report; we corroborate by
      // checking whether the frame actually committed the external navigation.
      run: () => new Promise<ProbeResult>((resolve) => {
        let settled = false;
        const frame = document.createElement('iframe');
        frame.style.position = 'fixed';
        frame.style.left = '-9999px';
        frame.style.width = '1px';
        frame.style.height = '1px';
        frame.src = `${externalUrl}.html`;
        const onViolation = (event: SecurityPolicyViolationEvent) => {
          if (event.effectiveDirective === 'frame-src' || event.violatedDirective === 'frame-src') {
            done(pass('Denied', `CSP frame-src violation reported (blocked ${short(event.blockedURI)})`));
          }
        };
        function done(result: ProbeResult) {
          if (settled) return;
          settled = true;
          document.removeEventListener('securitypolicyviolation', onViolation);
          frame.remove();
          resolve(result);
        }
        document.addEventListener('securitypolicyviolation', onViolation);
        frame.addEventListener('load', () => {
          // Defer one tick so a synchronous CSP violation report settles first.
          window.setTimeout(() => {
            if (settled) return;
            try {
              const href = frame.contentWindow?.location?.href ?? '';
              if (href.startsWith(externalUrl)) {
                done(fail('Unexpected load', `frame committed navigation to ${href}`));
              } else {
                // A blocked frame stays on its initial empty document.
                done(pass('Denied', `frame did not load external content (stayed on ${href || 'empty document'})`));
              }
            } catch (err) {
              // Reading location threw: a cross-origin document committed, which
              // only happens if the external navigation actually succeeded.
              done(fail('Unexpected load', `frame committed a cross-origin document — frame-src did not block (${errorText(err)})`));
            }
          }, 0);
        });
        document.body.append(frame);
        window.setTimeout(() => done(pass('Denied', 'no frame navigation committed before timeout')), 900);
      }),
    },
    {
      id: 'form.submit',
      level: 'baseline',
      category: 'Form',
      probe: 'Direct form submission',
      expected: "Form submission fails under form-action 'none'",
      expectedResult: 'denied',
      severity: 'medium',
      ownerArea: 'CSP',
      run: async () => {
        const before = location.href;
        const form = document.createElement('form');
        form.action = externalUrl;
        form.method = 'post';
        form.style.display = 'none';
        document.body.append(form);
        try {
          form.submit();
          await new Promise((resolve) => window.setTimeout(resolve, 150));
          return location.href === before
            ? pass('No navigation', 'Location unchanged after form.submit()')
            : fail('Unexpected navigation', `Location changed to ${location.href}`);
        } catch (err) {
          return pass('Denied', errorText(err));
        } finally {
          form.remove();
        }
      },
    },
    {
      id: 'media.audio',
      level: 'baseline',
      category: 'Media',
      probe: 'Direct audio media load',
      expected: "Media loads fail under media-src 'none'",
      expectedResult: 'denied',
      severity: 'medium',
      ownerArea: 'CSP',
      run: () => expectElementBlocked(() => {
        const audio = document.createElement('audio');
        audio.src = `${externalUrl}.mp3`;
        return audio;
      }),
    },
    {
      id: 'object.embed',
      level: 'baseline',
      category: 'Object',
      probe: 'Object/embed external load',
      expected: "Object and embed loads fail under object-src 'none'",
      expectedResult: 'denied',
      severity: 'high',
      ownerArea: 'CSP',
      run: () => expectElementBlocked(() => {
        const object = document.createElement('object');
        object.data = `${externalUrl}.html`;
        return object;
      }),
    },
    {
      id: 'nip07.window',
      level: 'baseline',
      category: 'NIP-07',
      probe: 'NIP-07 ambient global',
      expected: 'NIP-07 ambient signer global is absent',
      expectedResult: 'absent',
      severity: 'critical',
      ownerArea: 'Runtime',
      run: async () => {
        const ambientLabel = ['window', 'nostr'].join('.');
        return getAmbientNostr()
          ? fail('Ambient signer present', 'Ambient NIP-07 surface is reachable')
          : pass('Absent', `${ambientLabel} is not present`);
      },
    },
    {
      id: 'runtime.class',
      level: 'runtime-mediated',
      category: 'Runtime',
      probe: 'No ambient class surface on @napplet/sdk',
      expected: 'The legacy nub "class" surface is removed; the SDK exposes no class accessor',
      expectedResult: 'absent',
      severity: 'medium',
      ownerArea: 'SDK',
      run: async () => {
        // The @napplet/nub `class` domain (getClass/installClassShim) was removed
        // in the @napplet/core+nap unification. Its absence is the desired security
        // property: a napplet has no ambient way to read a shell-assigned class.
        const sdk = (await import('@napplet/sdk')) as Record<string, unknown>;
        return 'getClass' in sdk
          ? fail('class accessor present', 'Unexpected ambient class surface re-appeared on @napplet/sdk')
          : pass('Absent', 'No class accessor exported by @napplet/sdk (legacy nub class surface removed)');
      },
    },
    {
      id: 'runtime.identity.get',
      level: 'runtime-mediated',
      category: 'Runtime',
      probe: 'Shell-mediated identity request',
      expected: 'Identity may succeed only through the declared runtime capability',
      expectedResult: 'allowed-via-runtime',
      severity: 'medium',
      ownerArea: 'SDK',
      run: async () => {
        try {
          const pubkey = await timeout(identity.getPublicKey(), 1200);
          return pubkey === 'timeout'
            ? warning('Timed out', 'identity.getPublicKey did not resolve before timeout')
            : pass('Allowed via runtime', `pubkey=${String(pubkey).slice(0, 12)}...`);
        } catch (err) {
          return warning('Runtime denied/unavailable', errorText(err));
        }
      },
    },
    {
      id: 'runtime.relay.query',
      level: 'runtime-mediated',
      category: 'Runtime',
      probe: 'Shell-mediated relay query',
      expected: 'Relay query may succeed only through the declared runtime capability',
      expectedResult: 'allowed-via-runtime',
      severity: 'medium',
      ownerArea: 'SDK',
      run: async () => {
        try {
          const events = await timeout(relay.query([{ kinds: [0], limit: 1 }]), 1600);
          return events === 'timeout'
            ? warning('Timed out', 'relay.query did not resolve before timeout')
            : pass('Allowed via runtime', `${events.length} event(s) returned`);
        } catch (err) {
          return warning('Runtime denied/unavailable', errorText(err));
        }
      },
    },
    {
      id: 'runtime.ifc.emit',
      level: 'runtime-mediated',
      category: 'Runtime',
      probe: 'Shell-mediated IFC emit',
      expected: 'IFC emits only through the declared runtime capability',
      expectedResult: 'allowed-via-runtime',
      severity: 'low',
      ownerArea: 'SDK',
      run: async () => {
        try {
          inc.emit('security-lab:phase63-probe', [['probe', 'runtime.ifc.emit']], JSON.stringify({ inert: true }));
          return pass('Allowed via runtime', 'ifc.emit returned without direct browser channel access');
        } catch (err) {
          return warning('Runtime denied/unavailable', errorText(err));
        }
      },
    },
    {
      id: 'runtime.storage',
      level: 'runtime-mediated',
      category: 'Runtime',
      probe: 'Shell-mediated napplet storage',
      expected: 'Storage may succeed only through the declared runtime capability',
      expectedResult: 'allowed-via-runtime',
      severity: 'medium',
      ownerArea: 'SDK',
      run: async () => {
        // Storage round-trips through NUB-STORAGE only when the shell registers the
        // napplet in the runtime sessionRegistry. Two upstream gaps affect this path:
        //   - kehto/web#15: @kehto/shell never populates sessionRegistry, so the
        //     state handler returns "not registered". Worked around shell-side in
        //     NappletFrame.svelte (registerIframeIdentity).
        //   - kehto/web#14: storage errors are sent as `storage.*.error`, a type the
        //     shim ignores, so any failure surfaces as a 5s timeout, not a reason.
        // A genuine round-trip = pass; a blocked/timed-out path = skipped (deferred
        // to upstream), NOT a warning — we can't draw a security conclusion from it.
        try {
          const key = 'security-lab-runtime-probe';
          await storage.setItem(key, 'ok');
          const value = await storage.getItem(key);
          await storage.removeItem(key);
          return value === 'ok'
            ? pass('Allowed via runtime', 'storage set/get/remove round-tripped through NUB-STORAGE')
            : skipped(`Storage returned an unexpected value (${String(value)}) — deferred to kehto/web#14, #15`);
        } catch (err) {
          return skipped(`Storage unavailable (${errorText(err)}) — deferred to kehto/web#14 (error envelope) + #15 (sessionRegistry)`);
        }
      },
    },
    {
      id: 'runtime.resource.request',
      level: 'runtime-mediated',
      category: 'Runtime',
      probe: 'Shell-mediated resource request',
      expected: 'Bytes for an unfetchable https URL arrive via NUB-RESOURCE (direct fetch is CSP-blocked)',
      expectedResult: 'allowed-via-runtime',
      severity: 'high',
      ownerArea: 'SDK',
      run: async () => {
        // Must be a URL the napplet itself CANNOT fetch (connect-src 'none' blocks
        // all direct fetch) but the shell can resolve over the network. A `data:`
        // URL would defeat the test: the SDK short-circuits `data:` to a direct
        // fetch() and never touches NUB-RESOURCE. With a public https URL, a
        // returned Blob is positive proof the runtime mediated the request — the
        // napplet has no other way to obtain those bytes. (example.com is the
        // IANA reserved-for-documentation host: stable, tiny, neutral.)
        const runtimeResourceUrl = 'https://example.com/';
        try {
          const blob = await timeout(resource.bytes(runtimeResourceUrl), 8000);
          return blob === 'timeout'
            ? warning('Timed out', `resource.bytes did not resolve ${runtimeResourceUrl} before timeout`)
            : pass('Allowed via runtime', `runtime delivered ${blob.size} bytes (type=${blob.type || 'unknown'}) — direct fetch is CSP-blocked`);
        } catch (err) {
          return warning('Runtime denied/unavailable', errorText(err));
        }
      },
    },
    {
      id: 'msg.forge.envelope',
      level: 'safe-adversarial',
      category: 'Message',
      probe: 'Forged service envelope',
      expected: 'Forged service envelopes do not bypass runtime validation',
      expectedResult: 'unusable',
      severity: 'critical',
      ownerArea: 'Runtime',
      run: () => expectNoReplyToParentMessage({
        type: 'relay.query.result',
        id: 'security-lab-forged-relay-result',
        events: [{ id: 'inert', kind: 1, content: 'security-lab-marker', tags: [] }],
      }),
    },
    {
      id: 'msg.forge.class',
      level: 'safe-adversarial',
      category: 'Message',
      probe: 'Forged class assignment message',
      expected: 'A forged class message has no class surface to mutate (legacy nub class removed)',
      expectedResult: 'unusable',
      severity: 'high',
      ownerArea: 'Runtime',
      run: async () => {
        // There is no longer a `getClass()` accessor to read, so a forged
        // `class.assigned` message has nothing to mutate. Verify the SDK still
        // exposes no class accessor after the forged message is delivered.
        window.parent.postMessage({ type: 'class.assigned', id: 'security-lab-forged-class', class: 999 }, '*');
        await new Promise((resolve) => window.setTimeout(resolve, 250));
        const sdk = (await import('@napplet/sdk')) as Record<string, unknown>;
        return 'getClass' in sdk
          ? fail('class surface present', 'Forged message exposed an ambient class accessor')
          : pass('Unusable', 'No class accessor exists for a forged class message to mutate');
      },
    },
    {
      id: 'msg.replay.window',
      level: 'safe-adversarial',
      category: 'Message',
      probe: 'Replay/cross-window id marker',
      expected: 'Replayed or cross-window ids do not gain privileges',
      expectedResult: 'unusable',
      severity: 'critical',
      ownerArea: 'Runtime',
      run: () => expectNoReplyToParentMessage({
        type: 'identity.getPublicKey',
        id: 'security-lab-replay-id',
        windowId: 'forged-window-id',
      }),
    },
    {
      id: 'parent.location',
      level: 'safe-adversarial',
      category: 'Parent',
      probe: 'Parent/top traversal',
      expected: 'Parent and top privileged DOM/state are not readable',
      expectedResult: 'denied',
      severity: 'critical',
      ownerArea: 'sandbox',
      run: () => expectParentInaccessible(() => window.top?.document?.location?.href ?? window.parent.location.href),
    },
    {
      id: 'proto.pollute.local',
      level: 'safe-adversarial',
      category: 'DOM',
      probe: 'Local prototype pollution marker',
      expected: 'Local prototype mutation cannot affect parent/runtime state',
      expectedResult: 'unusable',
      severity: 'medium',
      ownerArea: 'sandbox',
      run: async () => {
        const key = '__securityLabPrototypeMarker';
        try {
          (Object.prototype as Record<string, unknown>)[key] = 'inert-marker';
          return await expectParentInaccessible(() => (window.parent as unknown as Record<string, unknown>)[key]);
        } finally {
          delete (Object.prototype as Record<string, unknown>)[key];
        }
      },
    },
    {
      id: 'dom.inject.inert',
      level: 'safe-adversarial',
      category: 'DOM',
      probe: 'Inert DOM script injection marker',
      expected: 'Injected script markup does not execute or escape the iframe',
      expectedResult: 'unusable',
      severity: 'medium',
      ownerArea: 'CSP',
      run: async () => {
        const marker = '__securityLabInjected';
        delete (window as unknown as Record<string, unknown>)[marker];
        const container = document.createElement('div');
        container.innerHTML = `<script>window.${marker}=true;<\/script><span>inert</span>`;
        document.body.append(container);
        await new Promise((resolve) => window.setTimeout(resolve, 100));
        const executed = Boolean((window as unknown as Record<string, unknown>)[marker]);
        container.remove();
        delete (window as unknown as Record<string, unknown>)[marker];
        return executed
          ? fail('Executed', 'Injected script marker changed window state')
          : pass('Inert', 'Injected script markup did not execute');
      },
    },
    {
      id: 'nostr.sign.ambient',
      level: 'safe-adversarial',
      category: 'NIP-07',
      probe: 'Ambient signing method',
      expected: 'Ambient signing is absent/unreachable',
      expectedResult: 'absent',
      severity: 'critical',
      ownerArea: 'Runtime',
      run: () => expectAmbientNostrAbsent('signEvent'),
    },
    {
      id: 'nostr.encrypt.ambient',
      level: 'safe-adversarial',
      category: 'NIP-07',
      probe: 'Ambient encryption methods',
      expected: 'Ambient encryption/decryption is absent/unreachable',
      expectedResult: 'absent',
      severity: 'critical',
      ownerArea: 'Runtime',
      run: async () => {
        const nip04 = await expectAmbientNostrAbsent('nip04.encrypt');
        const nip44 = await expectAmbientNostrAbsent('nip44.encrypt');
        return nip04.status === 'fail' || nip44.status === 'fail'
          ? fail('Ambient method present', `${nip04.evidence}; ${nip44.evidence}`)
          : pass('Absent', `${nip04.evidence}; ${nip44.evidence}`);
      },
    },
    {
      id: 'nostr.publish.ambient',
      level: 'safe-adversarial',
      category: 'NIP-07',
      probe: 'Ambient publish method',
      expected: 'Ambient publish is absent/unreachable',
      expectedResult: 'absent',
      severity: 'critical',
      ownerArea: 'Runtime',
      run: () => expectAmbientNostrAbsent('publish'),
    },
    {
      id: 'nostr.encrypted-note.canary',
      level: 'safe-adversarial',
      category: 'NIP-07',
      probe: 'Encrypted-note-shaped ambient payload',
      expected: 'Encrypted-note-shaped payload cannot publish through ambient surfaces',
      expectedResult: 'unusable',
      severity: 'critical',
      ownerArea: 'Runtime',
      run: async () => {
        const ambientLabel = ['window', 'nostr'].join('.');
        const nostr = getAmbientNostr();
        return nostr
          ? fail('Ambient NIP-07 present', 'Refusing to invoke encrypted-note-shaped canary because ambient signer exists')
          : pass('No ambient path', `No ${ambientLabel} surface for encrypted-note-shaped payload`);
      },
    },
  ];

  let rows = $state<ProbeRow[]>(definitions.map((definition) => ({
    ...definition,
    observed: 'Not run',
    evidence: 'Click rerun or run all',
    status: 'pending',
    lastRun: '-',
  })));
  let runningAll = $state(false);

  const levelLabels: Record<ProbeLevel, string> = {
    'baseline': 'Baseline',
    'runtime-mediated': 'Runtime mediated',
    'safe-adversarial': 'Safe adversarial',
  };

  function updateRow(id: string, patch: Partial<ProbeRow>): void {
    rows = rows.map((row) => row.id === id ? { ...row, ...patch } : row);
  }

  async function runProbe(id: string): Promise<void> {
    const row = rows.find((candidate) => candidate.id === id);
    if (!row || row.status === 'running') return;
    updateRow(id, { status: 'running', observed: 'Running', evidence: 'Probe in progress' });
    const started = performance.now();
    try {
      const result = await row.run();
      updateRow(id, {
        ...result,
        lastRun: `${new Date().toLocaleTimeString()} / ${(performance.now() - started).toFixed(0)}ms`,
      });
    } catch (err) {
      updateRow(id, {
        observed: 'Probe error',
        evidence: errorText(err),
        status: 'warning',
        lastRun: `${new Date().toLocaleTimeString()} / ${(performance.now() - started).toFixed(0)}ms`,
      });
    }
  }

  async function runAll(): Promise<void> {
    if (runningAll) return;
    runningAll = true;
    for (const row of rows) {
      await runProbe(row.id);
    }
    runningAll = false;
  }

  const counts = $derived(rows.reduce<Record<ProbeStatus, number>>((acc, row) => {
    acc[row.status] += 1;
    return acc;
  }, { pending: 0, running: 0, pass: 0, fail: 0, warning: 0, skipped: 0 }));

  const levelCounts = $derived(rows.reduce<Record<ProbeLevel, number>>((acc, row) => {
    acc[row.level] += 1;
    return acc;
  }, { 'baseline': 0, 'runtime-mediated': 0, 'safe-adversarial': 0 }));

  onMount(() => {
    void runAll();
  });
</script>

<main data-testid="security-lab">
  <header class="mast">
    <div class="actions">
      <div class="levels" aria-label="Probe levels">
        {#each Object.entries(levelCounts) as [level, count]}
          <span><b>{count}</b>{levelLabels[level as ProbeLevel]}</span>
        {/each}
      </div>
      <button onclick={runAll} disabled={runningAll} data-testid="run-all-probes">
        {runningAll ? 'running' : 'run all'}
      </button>
    </div>
  </header>

  <section class="summary" aria-label="Probe status summary">
    <span class="status-pass"><b>{counts.pass}</b> pass</span>
    <span class="status-fail"><b>{counts.fail}</b> fail</span>
    <span class="status-warning"><b>{counts.warning}</b> warning</span>
    <span class="status-skipped"><b>{counts.skipped}</b> skipped</span>
    <span class="status-pending"><b>{counts.pending + counts.running}</b> pending/running</span>
  </section>

  <section class="table-shell" aria-label="Security boundary probe table">
    <table>
      <thead>
        <tr>
          <th>Level</th>
          <th>Category</th>
          <th>Probe</th>
          <th>Expected Boundary</th>
          <th>Expected</th>
          <th>Observed</th>
          <th>Status</th>
          <th>Evidence / Error</th>
          <th>Severity</th>
          <th>Owner</th>
          <th>Last Run</th>
          <th>Run</th>
        </tr>
      </thead>
      <tbody>
        {#each rows as row}
          <tr data-testid="probe-row" data-probe-id={row.id} data-status={row.status}>
            <td><span class="level level-{row.level}">{levelLabels[row.level]}</span></td>
            <td>{row.category}</td>
            <td>{row.probe}</td>
            <td>{row.expected}</td>
            <td>{row.expectedResult}</td>
            <td>{row.observed}</td>
            <td><span class="status status-{row.status}">{row.status}</span></td>
            <td>{row.evidence}</td>
            <td><span class="severity severity-{row.severity}">{row.severity}</span></td>
            <td>{row.ownerArea}</td>
            <td>{row.lastRun}</td>
            <td><button class="row-run" onclick={() => runProbe(row.id)} disabled={row.status === 'running'} data-testid="run-probe-{row.id}">run</button></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    background: var(--hg-bg-base);
    color: var(--hg-text-primary);
    font: 12px/1.45 var(--hg-font-body, 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace);
  }

  main {
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    gap: 10px;
    min-height: 100vh;
    padding: 12px;
  }

  .mast {
    align-items: end;
    border-bottom: 1px solid var(--hg-border-muted);
    display: flex;
    gap: 12px;
    justify-content: space-between;
    padding-bottom: 6px;
  }

  .actions {
    align-items: center;
    display: flex;
    flex-direction: row;
    flex-wrap: wrap;
    gap: 8px;
    justify-content: space-between;
    width: 100%;
  }

  .levels,
  .summary {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    justify-content: flex-end;
  }

  .levels span,
  .summary span {
    border: 1px solid var(--hg-border-muted);
    color: var(--hg-text-muted);
    display: inline-flex;
    gap: 6px;
    padding: 3px 6px;
  }

  .levels b,
  .summary b {
    color: var(--hg-accent-primary);
  }

  button {
    background: var(--hg-bg-elevated);
    border: 1px solid var(--hg-border-accent);
    color: var(--hg-accent-primary);
    cursor: pointer;
    font: inherit;
    padding: 4px 8px;
  }

  button:disabled {
    border-color: var(--hg-border-muted);
    color: var(--hg-text-muted);
    cursor: default;
  }

  .table-shell {
    flex: 1;
    min-height: 0;
    overflow: auto;
  }

  table {
    border-collapse: collapse;
    min-width: 1500px;
    width: 100%;
  }

  th,
  td {
    border-bottom: 1px solid var(--hg-border-muted);
    padding: 7px 8px;
    text-align: left;
    vertical-align: top;
  }

  th {
    background: var(--hg-bg-elevated);
    color: var(--hg-text-muted);
    font-weight: 600;
    position: sticky;
    top: 0;
    z-index: 1;
  }

  td {
    color: var(--hg-text-primary);
  }

  tr:hover td {
    background: var(--hg-bg-elevated);
  }

  .level,
  .status,
  .severity {
    border: 1px solid var(--hg-border-muted);
    display: inline-block;
    padding: 1px 5px;
    white-space: nowrap;
  }

  .row-run {
    min-width: 42px;
    padding: 2px 6px;
  }

  .level-baseline,
  .status-pass,
  .severity-info {
    color: var(--hg-accent-primary);
  }

  .level-runtime-mediated,
  .status-running {
    color: var(--hg-text-primary);
  }

  .level-safe-adversarial,
  .status-fail,
  .severity-critical {
    color: var(--hg-danger, #ff6b6b);
  }

  .status-warning,
  .severity-high {
    color: var(--hg-accent-warning);
  }

  .status-pending,
  .status-skipped,
  .severity-medium,
  .severity-low {
    color: var(--hg-text-muted);
  }

  @media (max-width: 720px) {
    .mast {
      align-items: stretch;
      flex-direction: column;
    }

    .actions {
      align-items: flex-start;
    }

    .levels,
    .summary {
      justify-content: flex-start;
    }
  }
</style>
