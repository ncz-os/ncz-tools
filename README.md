# ncz-tools

## ⚠️ Status: Alpha / experimental

> This project is part of the nclawzero claw-family experimental set
> (alongside [zterm](https://gitlab.com/perlowja/zterm),
> [ncz-tools](https://gitlab.com/nclawzero/ncz-tools), and
> [zcon](https://gitlab.com/nclawzero/zcon)). It is **unfinished and
> not yet recommended for production use**. Interfaces, file formats,
> and behavior may change without notice.

---

Operator tooling for the nclawzero edge fleet. Cargo workspace housing the
Rust binaries that get installed on every nclawzero device and on the
operator workstations that drive them.

## Members

| Crate | Role |
|---|---|
| [`ncz/`](./ncz) | On-device umbrella CLI (status, set-agent, logs, providers, sandbox, integrity, update, channel, health, inspect, ...). Replaces the bash dispatcher previously shipped from `pi-gen-nclawzero` stage `06-install-ncz-cli`. |
| [`zterm/`](./zterm) | Light, thin, fast terminal REPL for the claw-family agentic daemons. Back to the 1970s. |

## Build

```bash
cargo build --release            # build all members
cargo build --release -p ncz     # ncz only
cargo build --release -p zterm   # zterm only
cargo test --workspace
```

## Distribution

`ncz` ships as a `.deb` in the `nclawzero-internal` apt repo on ARGOS and
is installed by `pi-gen-nclawzero` stage `06-install-ncz-cli`.

`zterm` is a developer/operator tool, installed via `cargo install`.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).


## Build infrastructure & partners

Continuous integration and package distribution for this project are generously
supported by our open-source infrastructure partners:

- **[GitLab](https://gitlab.com/)** — canonical source hosting and CI pipelines
  (format / lint / test gates), via the
  [GitLab for Open Source](https://about.gitlab.com/solutions/open-source/) program.
- **[Buildkite](https://buildkite.com/)** — CI/CD orchestration with hosted macOS
  and Linux agents, and our APT package registry host
  (`packages.buildkite.com/ncz-os/ncz`), via the
  [Buildkite Open Source](https://buildkite.com/pricing) program.

Thank you to both for backing open-source software.
