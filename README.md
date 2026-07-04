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

## Parent Checkout

```bash
pnpm --filter @hyprgate/napp-security-lab test
pnpm --filter @hyprgate/napp-security-lab build
```
## Paja runtime

```bash
pnpm --filter @hyprgate/napp-security-lab paja
```

This starts Kehto Paja and the napplet's Vite dev server together, using
the port configured in `vite.config.ts`.
