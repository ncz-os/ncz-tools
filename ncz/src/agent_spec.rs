//! Agent stack specification — type-safe profile / variant / sandbox shapes
//! shared by the `ncz agent` CLI subcommand and the eventual `ncz-deploy`
//! SSH wrapper.
//!
//! Compiled-in profiles + variants give the type system authority over what
//! deployments are valid. Adding a new device target or sandbox kind is an
//! enum-variant-and-impl change, not a YAML drop. The escape valve for
//! field-testing unreleased hardware is `--profile-override path/to/file.toml`
//! which deserializes into the same `AgentSpec` shape — V1.1+ work.
//!
//! Pattern precedent: GRAEAE consult v1.0 recommended this shape over
//! arbitrary user-provided profiles for a fleet of <10 known device types.

use serde::{Deserialize, Serialize};

/// One of the three nclawzero agents. Each carries an OCI image reference
/// per sandbox kind (resolved at install time from the catalog).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Agent {
    Zeroclaw,
    Openclaw,
    Hermes,
}

impl Agent {
    /// Stable lower-kebab tag used for paths, env files, and quadlet names.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Zeroclaw => "zeroclaw",
            Self::Openclaw => "openclaw",
            Self::Hermes => "hermes",
        }
    }

    /// Default forward port for the agent's gateway endpoint.
    /// (Operators can override at install time but these are the canonical
    /// fleet bindings.)
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Zeroclaw => 42617,
            Self::Openclaw => 18789,
            Self::Hermes => 8642,
        }
    }
}

/// Sandbox runtime under which the agent process executes. Naked is the
/// baseline (Podman default runc). OpenShell is the NemoClaw-pattern wrapped
/// image with Landlock + network-allowlist policy enforcement.
///
/// V1.1 will add `Bwrap` and `GVisor` (runtime-level flips, no new OCI
/// images). V2 will add `KataContainers` and `Firecracker` once cixmini
/// hardware lands and microVM-class isolation becomes testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SandboxKind {
    Naked,
    OpenShell,
}

impl SandboxKind {
    /// Stable lower-kebab tag for catalog lookups + log lines.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Naked => "naked",
            Self::OpenShell => "openshell",
        }
    }
}

/// Pre-defined deployment shapes. `Single` deploys one agent; `Triple`
/// deploys all three. Custom mixes (e.g. zeroclaw + hermes only) live behind
/// the `Custom` variant in V1.1+.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Variant {
    /// Single-agent deployment, default zeroclaw.
    Single { agent: Agent },
    /// All three agents deployed together (the bigpi reference shape).
    Triple,
}

impl Variant {
    /// Enumerate the agents a variant activates.
    pub fn agents(&self) -> Vec<Agent> {
        match self {
            Self::Single { agent } => vec![*agent],
            Self::Triple => vec![Agent::Zeroclaw, Agent::Openclaw, Agent::Hermes],
        }
    }
}

/// Hardware / runtime target for a deployment. The set is intentionally
/// closed for V1.0 — the architectural escape valve for unreleased boards
/// (e.g., cixmini before it lands) is an explicit `ProfileOverride` variant
/// that V1.1 wires in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProfileTarget {
    /// Raspberry Pi 5 16GB — the bigpi reference profile.
    Rpi5_16gb,
    /// x86_64 Linux generic (TYPHON shape, dev demos, cloud VMs).
    LinuxAmd64Generic,
    /// macOS arm64 with Docker Desktop / OrbStack / Colima — operator dev loop.
    MacosArm64Docker,
}

impl ProfileTarget {
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Rpi5_16gb => "rpi5-16gb",
            Self::LinuxAmd64Generic => "linux-amd64-generic",
            Self::MacosArm64Docker => "macos-arm64-docker",
        }
    }

    /// Whether the target supports a given sandbox kind. Used at
    /// `ncz agent install` time to refuse incompatible combos before any
    /// laydown.
    pub fn supports_sandbox(&self, sandbox: SandboxKind) -> bool {
        match (self, sandbox) {
            // V1.0: all 3 profiles support both Naked and OpenShell.
            (_, SandboxKind::Naked | SandboxKind::OpenShell) => true,
        }
    }

    /// Whether the target supports a given variant. Memory-constrained
    /// profiles refuse `Triple` here. (rpi5-16gb / linux-amd64-generic /
    /// macos-arm64-docker all have headroom for triple in V1.0.)
    pub fn supports_variant(&self, _variant: &Variant) -> bool {
        match self {
            Self::Rpi5_16gb | Self::LinuxAmd64Generic | Self::MacosArm64Docker => true,
        }
    }

    /// Container runtime expected on this target. macOS goes through Docker
    /// Desktop / OrbStack; Linux profiles use Podman+systemd-quadlets;
    /// linux-amd64-generic supports either (operator picks).
    pub fn default_runtime(&self) -> ContainerRuntime {
        match self {
            Self::Rpi5_16gb => ContainerRuntime::Podman,
            Self::LinuxAmd64Generic => ContainerRuntime::Podman,
            Self::MacosArm64Docker => ContainerRuntime::Docker,
        }
    }
}

/// Container runtime — selects between Podman (with systemd quadlets) and
/// Docker (with `docker run` + manual lifecycle on Mac).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ContainerRuntime {
    Podman,
    Docker,
}

/// Where to source the OCI image tarballs from. Per GRAEAE-validated
/// architecture: Registry is the default for V1.0; FleetCache becomes the
/// canonical source once a refresh discipline is established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ImageSource {
    /// Pull from registry (ghcr.io / docker.io). Default V1.0.
    #[default]
    Registry,
    /// Pull from a known fleet-cache directory (e.g., NFS mount of
    /// /mnt/argonas/agent-images/). Faster on LAN, requires a refresh step.
    FleetCache { path: std::path::PathBuf },
    /// Single tarball file on disk — for air-gap commissioning via USB key.
    Tarball { path: std::path::PathBuf },
}

/// Full deployment specification — what ncz agent install consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSpec {
    pub profile: ProfileTarget,
    pub variant: Variant,
    pub sandbox: SandboxKind,
    #[serde(default)]
    pub image_source: ImageSource,
}

impl AgentSpec {
    /// Validate the spec against compiled-in compatibility tables. Returns
    /// the first incompatibility found, or Ok if the spec is deployable.
    pub fn validate(&self) -> Result<(), SpecError> {
        if !self.profile.supports_sandbox(self.sandbox) {
            return Err(SpecError::ProfileSandboxMismatch {
                profile: self.profile,
                sandbox: self.sandbox,
            });
        }
        if !self.profile.supports_variant(&self.variant) {
            return Err(SpecError::ProfileVariantMismatch {
                profile: self.profile,
                variant: self.variant.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error("profile {profile:?} does not support sandbox {sandbox:?}")]
    ProfileSandboxMismatch {
        profile: ProfileTarget,
        sandbox: SandboxKind,
    },
    #[error("profile {profile:?} does not support variant {variant:?}")]
    ProfileVariantMismatch {
        profile: ProfileTarget,
        variant: Variant,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_slugs_are_stable() {
        assert_eq!(Agent::Zeroclaw.slug(), "zeroclaw");
        assert_eq!(Agent::Openclaw.slug(), "openclaw");
        assert_eq!(Agent::Hermes.slug(), "hermes");
    }

    #[test]
    fn sandbox_slugs_are_stable() {
        assert_eq!(SandboxKind::Naked.slug(), "naked");
        assert_eq!(SandboxKind::OpenShell.slug(), "openshell");
    }

    #[test]
    fn triple_variant_yields_all_three_agents() {
        let agents = Variant::Triple.agents();
        assert_eq!(agents.len(), 3);
        assert!(agents.contains(&Agent::Zeroclaw));
        assert!(agents.contains(&Agent::Openclaw));
        assert!(agents.contains(&Agent::Hermes));
    }

    #[test]
    fn single_variant_yields_just_named_agent() {
        let agents = Variant::Single {
            agent: Agent::Zeroclaw,
        }
        .agents();
        assert_eq!(agents, vec![Agent::Zeroclaw]);
    }

    #[test]
    fn rpi5_supports_both_sandboxes() {
        assert!(ProfileTarget::Rpi5_16gb.supports_sandbox(SandboxKind::Naked));
        assert!(ProfileTarget::Rpi5_16gb.supports_sandbox(SandboxKind::OpenShell));
    }

    #[test]
    fn macos_uses_docker_runtime() {
        assert_eq!(
            ProfileTarget::MacosArm64Docker.default_runtime(),
            ContainerRuntime::Docker
        );
    }

    #[test]
    fn linux_uses_podman_runtime() {
        assert_eq!(
            ProfileTarget::Rpi5_16gb.default_runtime(),
            ContainerRuntime::Podman
        );
        assert_eq!(
            ProfileTarget::LinuxAmd64Generic.default_runtime(),
            ContainerRuntime::Podman
        );
    }

    #[test]
    fn valid_spec_roundtrips_through_serde() {
        let spec = AgentSpec {
            profile: ProfileTarget::Rpi5_16gb,
            variant: Variant::Triple,
            sandbox: SandboxKind::OpenShell,
            image_source: ImageSource::default(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let parsed: AgentSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, spec);
        spec.validate().unwrap();
    }

    #[test]
    fn image_source_defaults_to_registry() {
        let src: ImageSource = serde_json::from_str("null").unwrap_or_default();
        assert!(matches!(src, ImageSource::Registry));
    }
}
