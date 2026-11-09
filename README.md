<!-- HYPRGATE NAPPLET MIRROR NOTICE:START -->
> This repository is a read-only mirror of the `security-lab` napplet from `hyprgate/gui`.
> Open issues and pull requests in https://github.com/hyprgate/gui.
> Do not push commits to this standalone napplet repository; direct changes are overwritten by Hyprgate's mirror workflow.
<!-- HYPRGATE NAPPLET MIRROR NOTICE:END -->

# Security Lab

Sandboxed NIP-5D napplet packaged as `@hyprgate/napp-security-lab`.

Security Lab intentionally runs as a napplet so it can test the sandboxed
environment provided by the Hyprgate runtime. It is not a rapplet: rapplets are
Hyprgate-owned runtime applets and are not sandboxed.

The app is tracked in this repo at `napplets/security-lab`; the standalone repository
is a generated, read-only mirror. Probes run when it opens. The verdict line says how
the run went, the result buttons filter the table, and each row expands to its full
evidence.

Run it against the real sandbox when you trust the result. Test harnesses that mock
`WebSocket` bypass CSP, so a direct-socket probe can report a connection the browser
would refuse.

## Commands

```bash
pnpm --filter ./napplets/security-lab test
pnpm --filter ./napplets/security-lab build
```
## Paja runtime

```bash
pnpm --filter ./napplets/security-lab paja
```

This starts Kehto Paja and the napplet's Vite dev server together, using
the port configured in `vite.config.ts`.
