//! agent — install / enable / disable / lint / uninstall agents on the
//! local sandbox stack.
//!
//! V1.0 scope (per GRAEAE consult of 2026-04-29): in-place mode only,
//! 3 profiles (rpi5-16gb, linux-amd64-generic, macos-arm64-docker),
//! Naked + OpenShell sandboxes, Triple + Single variants. Hard refusal
//! on `agents/INVARIANTS.md` violations — no override flag; use
//! `ncz agent lint` to diagnose without installing.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use serde::{ser::SerializeStruct, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::agent_spec::{
    Agent, AgentSpec, ContainerRuntime, ImageSource, ProfileTarget, SandboxKind, SpecError, Variant,
};
use crate::cli::{AgentAction, AgentName, Context};
use crate::cmd::common;
use crate::error::NczError;
use crate::output::{self, Render};
use crate::state::agent_install_metadata::{self, AgentInstallMetadata, PENDING_IMAGE_DIGEST};
use crate::state::{self, Paths};

#[derive(Debug, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum AgentReport {
    Install(AgentInstallReport),
    Enable(AgentMutationReport),
    Disable(AgentMutationReport),
    Reload(AgentMutationReport),
    Status(AgentStatusReport),
    Lint(AgentLintReport),
    Uninstall(AgentMutationReport),
}

impl Render for AgentReport {
    fn render_text(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Install(r) => r.render_text(w),
            Self::Enable(r) | Self::Disable(r) | Self::Reload(r) | Self::Uninstall(r) => {
                r.render_text(w)
            }
            Self::Status(r) => r.render_text(w),
            Self::Lint(r) => r.render_text(w),
        }
    }
}

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AgentInstallReport {
    pub schema_version: u32,
    pub spec: AgentSpec,
    pub planned_steps: Vec<String>,
    pub applied: bool,
    pub dry_run: bool,
}

impl Render for AgentInstallReport {
    fn render_text(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(
            w,
            "agent install: profile={} variant={:?} sandbox={} dry_run={}",
            self.spec.profile.slug(),
            self.spec.variant,
            self.spec.sandbox.slug(),
            self.dry_run
        )?;
        writeln!(w, "planned steps:")?;
        for step in &self.planned_steps {
            writeln!(w, "  - {step}")?;
        }
        writeln!(w, "applied: {}", self.applied)
    }
}

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AgentMutationReport {
    pub schema_version: u32,
    pub action: String,
    pub agents: Vec<String>,
    pub planned_steps: Vec<String>,
    pub applied: bool,
}

impl Render for AgentMutationReport {
    fn render_text(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(
            w,
            "agent {}: agents={:?} applied={}",
            self.action, self.agents, self.applied
        )?;
        if !self.planned_steps.is_empty() {
            writeln!(w, "planned steps:")?;
            for step in &self.planned_steps {
                writeln!(w, "  - {step}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AgentStatusReport {
    pub schema_version: u32,
    pub planned_steps: Vec<String>,
    pub agents: Vec<AgentStatusEntry>,
}

impl Render for AgentStatusReport {
    fn render_text(&self, w: &mut dyn Write) -> io::Result<()> {
        if !self.planned_steps.is_empty() {
            writeln!(w, "planned steps:")?;
            for step in &self.planned_steps {
                writeln!(w, "  - {step}")?;
            }
        }
        writeln!(w, "{:14} {:10} {:10} PORT", "AGENT", "SANDBOX", "STATE")?;
        for entry in &self.agents {
            writeln!(
                w,
                "{:14} {:10} {:10} {}",
                entry.agent, entry.sandbox, entry.state, entry.port
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct AgentStatusEntry {
    pub agent: String,
    pub sandbox: String,
    pub state: String,
    pub port: u16,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct AgentLintReport {
    pub schema_version: u32,
    pub bundle_path: String,
    pub invariants_checked: u32,
    pub invariants_passed: u32,
    pub results: Vec<InvariantResult>,
}

impl Serialize for AgentLintReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AgentLintReport", 7)?;
        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("bundle_path", &self.bundle_path)?;
        state.serialize_field("invariants_checked", &self.invariants_checked)?;
        state.serialize_field("invariants_passed", &self.invariants_passed)?;
        state.serialize_field("results", &self.results)?;
        state.serialize_field("overall", &self.overall())?;
        state.serialize_field("overall_message", &self.overall_message())?;
        state.end()
    }
}

impl Render for AgentLintReport {
    fn render_text(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(w, "agent lint: {}", self.bundle_path)?;
        writeln!(
            w,
            "  invariants: {}/{} passed",
            self.invariants_passed, self.invariants_checked
        )?;
        writeln!(
            w,
            "{:<10} {:<6} {:<48} EVIDENCE",
            "ID", "STATUS", "STATEMENT"
        )?;
        for result in &self.results {
            writeln!(
                w,
                "{:<10} {:<6} {:<48} {}",
                result.invariant_id,
                result.status,
                result.statement,
                result.evidence.as_deref().unwrap_or("-")
            )?;
        }
        match self.overall_message() {
            Some(message) => writeln!(w, "verdict: {} ({message})", self.overall()),
            None => writeln!(w, "verdict: {}", self.overall()),
        }
    }
}

impl AgentLintReport {
    pub fn from_results(bundle_path: String, results: Vec<InvariantResult>) -> Self {
        let invariants_checked = results.len() as u32;
        let invariants_passed = results
            .iter()
            .filter(|result| result.status == InvariantStatus::Pass)
            .count() as u32;
        Self {
            schema_version: common::SCHEMA_VERSION,
            bundle_path,
            invariants_checked,
            invariants_passed,
            results,
        }
    }

    pub fn overall(&self) -> Verdict {
        Self::verdict_for_results(&self.results)
    }

    pub fn overall_message(&self) -> Option<&'static str> {
        Self::verdict_message_for_results(&self.results)
    }

    pub fn verdict_for_results(results: &[InvariantResult]) -> Verdict {
        if results.is_empty() {
            return Verdict::Incomplete;
        }
        if results
            .iter()
            .any(|result| result.status == InvariantStatus::Fail)
        {
            Verdict::Reject
        } else if results
            .iter()
            .any(|result| result.status == InvariantStatus::Warn)
        {
            Verdict::Warn
        } else {
            Verdict::Approve
        }
    }

    pub fn verdict_message_for_results(results: &[InvariantResult]) -> Option<&'static str> {
        if results.is_empty() {
            Some("no invariants checked - parser failed or invariant set missing")
        } else {
            None
        }
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct InvariantResult {
    pub invariant_id: String,
    pub status: InvariantStatus,
    pub statement: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InvariantStatus {
    Pass,
    Skip,
    Warn,
    Fail,
}

impl fmt::Display for InvariantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Pass => "pass",
            Self::Skip => "skip",
            Self::Warn => "warn",
            Self::Fail => "fail",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Approve,
    Warn,
    Reject,
    Incomplete,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Approve => "approve",
            Self::Warn => "warn",
            Self::Reject => "reject",
            Self::Incomplete => "incomplete",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentSelector {
    All,
    One(Agent),
}

impl AgentSelector {
    fn from_optional(agent: Option<AgentName>) -> Self {
        match agent {
            Some(agent) => Self::One(agent.into_agent()),
            None => Self::All,
        }
    }
}

pub fn run(ctx: &Context, action: AgentAction) -> Result<i32, NczError> {
    let paths = Paths::default();
    run_with_paths(ctx, &paths, action)
}

pub fn run_with_paths(ctx: &Context, paths: &Paths, action: AgentAction) -> Result<i32, NczError> {
    let report = match action {
        AgentAction::Install {
            profile,
            variant,
            sandbox,
            from,
            dry_run,
        } => install(
            ctx,
            paths,
            profile.as_deref(),
            &variant,
            &sandbox,
            &from,
            dry_run,
        )?,
        AgentAction::Enable { agent } => {
            mutate(ctx, paths, "enable", AgentSelector::One(agent.into_agent()))?
        }
        AgentAction::Disable { agent } => mutate(
            ctx,
            paths,
            "disable",
            AgentSelector::One(agent.into_agent()),
        )?,
        AgentAction::Reload { agent } => {
            mutate(ctx, paths, "reload", AgentSelector::from_optional(agent))?
        }
        AgentAction::Status => status(ctx, paths)?,
        AgentAction::Lint { bundle } => lint(ctx, paths, bundle.as_deref())?,
        AgentAction::Uninstall { agent, full } => {
            uninstall(ctx, paths, AgentSelector::from_optional(agent), full)?
        }
    };
    let code = match &report {
        AgentReport::Lint(r) if r.overall() != Verdict::Approve => 4,
        _ => 0,
    };
    output::emit(&report, ctx.json)?;
    Ok(code)
}

/// Build the V1.0 install contract. The planned-step shape intentionally
/// differs by runtime: Podman profiles load images into Podman and lay down
/// systemd quadlets, while Docker profiles load images into Docker and use
/// Docker restart policy / labels without systemd.
fn install(
    _ctx: &Context,
    paths: &Paths,
    profile: Option<&str>,
    variant: &str,
    sandbox: &str,
    from: &str,
    dry_run: bool,
) -> Result<AgentReport, NczError> {
    let profile = parse_profile(profile)?;
    let variant = parse_variant(variant)?;
    let sandbox = parse_sandbox(sandbox)?;
    let image_source = parse_image_source(from)?;
    let spec = AgentSpec {
        profile,
        variant: variant.clone(),
        sandbox,
        image_source,
    };
    spec.validate()
        .map_err(|e: SpecError| NczError::Precondition(e.to_string()))?;

    // V1.0 scaffold: planned-steps emission + dry-run support; the actual
    // OCI-pull / runtime-specific laydown / enable cycle is the next
    // implementation slice. Install metadata is still persisted so later
    // lifecycle operations keep the same Podman-vs-Docker split selected at
    // install time.
    let planned_steps = planned_steps_for(&spec);
    if !dry_run {
        let _lock = state::acquire_lock(&paths.lock_path)?;
        persist_install_metadata(paths, &spec)?;
    }

    Ok(AgentReport::Install(AgentInstallReport {
        schema_version: common::SCHEMA_VERSION,
        spec,
        planned_steps,
        applied: !dry_run,
        dry_run,
    }))
}

fn mutate(
    _ctx: &Context,
    paths: &Paths,
    action: &str,
    selector: AgentSelector,
) -> Result<AgentReport, NczError> {
    let _lock = state::acquire_lock(&paths.lock_path)?;
    let metadata = load_metadata_for_selector(paths, selector)?;
    let planned_steps = lifecycle_planned_steps(action, &metadata);
    let agents = metadata_agents(&metadata);
    Err(NczError::Precondition(format!(
        "agent {action} scaffold — bodies pending. agents={agents:?} planned={planned_steps:?}"
    )))
}

fn status(_ctx: &Context, paths: &Paths) -> Result<AgentReport, NczError> {
    let _lock = state::acquire_lock(&paths.lock_path)?;
    let metadata = load_metadata_for_selector(paths, AgentSelector::All)?;
    let planned_steps = status_planned_steps(&metadata);
    Err(NczError::Precondition(format!(
        "agent status scaffold — bodies pending. planned={planned_steps:?}"
    )))
}

fn lint(
    _ctx: &Context,
    _paths: &Paths,
    bundle: Option<&std::path::Path>,
) -> Result<AgentReport, NczError> {
    let path = bundle
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(active bundle)".to_string());
    Err(NczError::Precondition(format!(
        "agent lint — bodies pending. bundle={path}"
    )))
}

fn uninstall(
    _ctx: &Context,
    paths: &Paths,
    selector: AgentSelector,
    full: bool,
) -> Result<AgentReport, NczError> {
    let _lock = state::acquire_lock(&paths.lock_path)?;
    let metadata = load_metadata_for_selector(paths, selector)?;
    let planned_steps = uninstall_planned_steps(&metadata, full);
    let agents = metadata_agents(&metadata);
    Err(NczError::Precondition(format!(
        "agent uninstall scaffold — bodies pending. agents={agents:?} full={full} planned={planned_steps:?}"
    )))
}

fn persist_install_metadata(paths: &Paths, spec: &AgentSpec) -> Result<(), NczError> {
    let installed_at = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|err| {
        NczError::Precondition(format!("could not format install timestamp: {err}"))
    })?;
    for agent in spec.variant.agents() {
        agent_install_metadata::write(
            paths,
            &AgentInstallMetadata {
                agent,
                profile: spec.profile,
                runtime: spec.profile.default_runtime(),
                sandbox: spec.sandbox,
                installed_at: installed_at.clone(),
                image_digest: PENDING_IMAGE_DIGEST.to_string(),
            },
        )?;
    }
    Ok(())
}

fn load_metadata_for_selector(
    paths: &Paths,
    selector: AgentSelector,
) -> Result<Vec<AgentInstallMetadata>, NczError> {
    match selector {
        AgentSelector::All => agent_install_metadata::read_all_installed(paths),
        AgentSelector::One(agent) => agent_install_metadata::read(paths, agent).map(|m| vec![m]),
    }
}

fn metadata_agents(metadata: &[AgentInstallMetadata]) -> Vec<String> {
    metadata
        .iter()
        .map(|entry| entry.agent.slug().to_string())
        .collect()
}

fn planned_steps_for(spec: &AgentSpec) -> Vec<String> {
    let agent_count = spec.variant.agents().len();
    let mut steps = vec![
        "acquire mutation lock (per F-3 + cross-cmd-mutex)".to_string(),
        format!(
            "verify image catalog matches sandbox={} for {} agent(s)",
            spec.sandbox.slug(),
            agent_count
        ),
        image_source_step(&spec.image_source),
    ];

    match spec.profile.default_runtime() {
        ContainerRuntime::Podman => {
            steps.push(format!("podman load: {agent_count} image(s)"));
            steps.push(format!(
                "render quadlets: {agent_count} unit(s) into /etc/containers/systemd/"
            ));
            steps.push("systemctl daemon-reload + enable units (per F-2)".to_string());
        }
        ContainerRuntime::Docker => {
            // macos-arm64-docker stays in V1.0 scope, but its lifecycle is
            // Docker-native: no Podman quadlets and no systemd dependency.
            steps.push(format!("docker load: {agent_count} image(s)"));
            steps.push(format!(
                "docker run: {agent_count} container(s) with --label nclawzero.agent and --restart=unless-stopped (no systemd)"
            ));
        }
    }
    steps.push("convergent verify: skip writes for unchanged artifacts (per F-3)".to_string());
    steps.push(format!(
        "metadata-write: persist install metadata for {agent_count} agent(s) under agents/<agent>/install-metadata.toml"
    ));
    steps
}

fn lifecycle_planned_steps(action: &str, metadata: &[AgentInstallMetadata]) -> Vec<String> {
    let mut steps = metadata_load_steps(metadata);
    for entry in metadata {
        steps.push(match (action, entry.runtime) {
            ("enable", ContainerRuntime::Podman) => {
                format!("systemctl enable --now {}", service_name(entry.agent))
            }
            ("enable", ContainerRuntime::Docker) => {
                format!("docker start {}", docker_container_name(entry.agent))
            }
            ("disable", ContainerRuntime::Podman) => {
                format!("systemctl stop + mask {}", service_name(entry.agent))
            }
            ("disable", ContainerRuntime::Docker) => {
                format!("docker stop {}", docker_container_name(entry.agent))
            }
            ("reload", ContainerRuntime::Podman) => {
                format!(
                    "podman image refresh + systemctl restart {}",
                    service_name(entry.agent)
                )
            }
            ("reload", ContainerRuntime::Docker) => {
                format!(
                    "docker image refresh + docker restart {}",
                    docker_container_name(entry.agent)
                )
            }
            (other, runtime) => {
                format!("unsupported lifecycle action {other} for runtime {runtime:?}")
            }
        });
    }
    steps
}

fn uninstall_planned_steps(metadata: &[AgentInstallMetadata], full: bool) -> Vec<String> {
    let mut steps = metadata_load_steps(metadata);
    for entry in metadata {
        steps.push(match entry.runtime {
            ContainerRuntime::Podman => format!(
                "systemctl stop {} + remove quadlet + podman rm",
                service_name(entry.agent)
            ),
            ContainerRuntime::Docker => {
                format!("docker rm -f {}", docker_container_name(entry.agent))
            }
        });
        steps.push(format!(
            "metadata-remove: agents/{}/install-metadata.toml",
            entry.agent.slug()
        ));
    }
    if full {
        steps.push("full uninstall: remove shared agent-env and provider data dirs".to_string());
    }
    steps
}

fn status_planned_steps(metadata: &[AgentInstallMetadata]) -> Vec<String> {
    let mut steps = metadata_load_steps(metadata);
    for entry in metadata {
        steps.push(match entry.runtime {
            ContainerRuntime::Podman => {
                format!("systemctl is-active {}", service_name(entry.agent))
            }
            ContainerRuntime::Docker => format!(
                "docker container inspect --format {{{{.State.Status}}}} {}",
                docker_container_name(entry.agent)
            ),
        });
    }
    steps
}

fn metadata_load_steps(metadata: &[AgentInstallMetadata]) -> Vec<String> {
    metadata
        .iter()
        .map(|entry| {
            format!(
                "metadata-load: agents/{}/install-metadata.toml",
                entry.agent.slug()
            )
        })
        .collect()
}

fn service_name(agent: Agent) -> String {
    format!("{}.service", agent.slug())
}

fn docker_container_name(agent: Agent) -> String {
    format!("ncz-{}", agent.slug())
}

fn image_source_step(source: &ImageSource) -> String {
    match source {
        ImageSource::Registry => "fetch + hash-verify OCI images from registry (per F-1)".into(),
        ImageSource::FleetCache { path } => format!(
            "fetch + hash-verify OCI tarballs from fleet cache {} (per F-1)",
            path.display()
        ),
        ImageSource::Tarball { path } => format!(
            "load + hash-verify OCI tarball {} (per F-1)",
            path.display()
        ),
    }
}

fn parse_profile(s: Option<&str>) -> Result<ProfileTarget, NczError> {
    match s {
        Some("rpi5-16gb") => Ok(ProfileTarget::Rpi5_16gb),
        Some("linux-amd64-generic") => Ok(ProfileTarget::LinuxAmd64Generic),
        Some("macos-arm64-docker") => Ok(ProfileTarget::MacosArm64Docker),
        Some(other) => Err(NczError::Usage(format!(
            "unknown profile '{other}'; expected one of: rpi5-16gb, linux-amd64-generic, macos-arm64-docker"
        ))),
        None => Err(NczError::Precondition(
            "auto-detect profile — pending; pass --profile explicitly".to_string(),
        )),
    }
}

fn parse_variant(s: &str) -> Result<Variant, NczError> {
    if s == "triple" {
        return Ok(Variant::Triple);
    }
    if let Some(name) = s.strip_prefix("single=") {
        common::validate_agent(name)?;
        let agent = Agent::from_slug(name).ok_or_else(|| {
            NczError::Usage(format!(
                "unknown agent '{name}'; expected one of: zeroclaw, openclaw, hermes"
            ))
        })?;
        return Ok(Variant::Single { agent });
    }
    Err(NczError::Usage(format!(
        "unknown variant '{s}'; expected 'triple' or 'single=<agent>'"
    )))
}

fn parse_image_source(s: &str) -> Result<ImageSource, NczError> {
    match s {
        "registry" => Ok(ImageSource::Registry),
        _ => {
            if let Some(path) = s.strip_prefix("fleet-cache=") {
                if path.is_empty() {
                    Err(invalid_image_source(s))
                } else {
                    Ok(ImageSource::FleetCache {
                        path: PathBuf::from(path),
                    })
                }
            } else if let Some(path) = s.strip_prefix("tarball=") {
                if path.is_empty() {
                    Err(invalid_image_source(s))
                } else {
                    Ok(ImageSource::Tarball {
                        path: PathBuf::from(path),
                    })
                }
            } else {
                Err(invalid_image_source(s))
            }
        }
    }
}

fn invalid_image_source(s: &str) -> NczError {
    NczError::Usage(format!(
        "unknown image source '{s}'; expected 'registry', 'fleet-cache=<path>', or 'tarball=<path>'"
    ))
}

fn parse_sandbox(s: &str) -> Result<SandboxKind, NczError> {
    match s {
        "naked" => Ok(SandboxKind::Naked),
        "openshell" => Ok(SandboxKind::OpenShell),
        other => Err(NczError::Usage(format!(
            "unknown sandbox '{other}'; expected one of: naked, openshell"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::Context;
    use crate::cmd::common::test_paths;
    use crate::sys::fake::FakeRunner;

    use super::*;

    fn ctx<'a>(runner: &'a FakeRunner) -> Context<'a> {
        Context {
            json: false,
            show_secrets: false,
            runner,
        }
    }

    fn test_spec(profile: ProfileTarget) -> AgentSpec {
        AgentSpec {
            profile,
            variant: Variant::Triple,
            sandbox: SandboxKind::OpenShell,
            image_source: ImageSource::Registry,
        }
    }

    fn invariant(status: InvariantStatus) -> InvariantResult {
        InvariantResult {
            invariant_id: "I-1".to_string(),
            status,
            statement: "test invariant".to_string(),
            evidence: Some("test evidence".to_string()),
        }
    }

    fn test_metadata(agent: Agent, runtime: ContainerRuntime) -> AgentInstallMetadata {
        AgentInstallMetadata {
            agent,
            profile: match runtime {
                ContainerRuntime::Podman => ProfileTarget::Rpi5_16gb,
                ContainerRuntime::Docker => ProfileTarget::MacosArm64Docker,
            },
            runtime,
            sandbox: SandboxKind::OpenShell,
            installed_at: "2026-04-30T00:00:00Z".to_string(),
            image_digest: PENDING_IMAGE_DIGEST.to_string(),
        }
    }

    fn write_test_metadata(paths: &Paths, agent: Agent, runtime: ContainerRuntime) {
        agent_install_metadata::write(paths, &test_metadata(agent, runtime)).unwrap();
    }

    #[test]
    fn parses_known_profiles() {
        assert!(matches!(
            parse_profile(Some("rpi5-16gb")).unwrap(),
            ProfileTarget::Rpi5_16gb
        ));
        assert!(matches!(
            parse_profile(Some("linux-amd64-generic")).unwrap(),
            ProfileTarget::LinuxAmd64Generic
        ));
        assert!(matches!(
            parse_profile(Some("macos-arm64-docker")).unwrap(),
            ProfileTarget::MacosArm64Docker
        ));
    }

    #[test]
    fn rejects_unknown_profile() {
        let err = parse_profile(Some("rpi3")).unwrap_err();
        assert!(matches!(err, NczError::Usage(_)));
    }

    #[test]
    fn parses_triple_variant() {
        assert_eq!(parse_variant("triple").unwrap(), Variant::Triple);
    }

    #[test]
    fn parses_single_variant_for_each_agent() {
        for (name, agent) in [
            ("zeroclaw", Agent::Zeroclaw),
            ("openclaw", Agent::Openclaw),
            ("hermes", Agent::Hermes),
        ] {
            let v = parse_variant(&format!("single={name}")).unwrap();
            assert_eq!(v, Variant::Single { agent });
        }
    }

    #[test]
    fn rejects_malformed_variant() {
        assert!(parse_variant("triple-debug").is_err());
        assert!(parse_variant("single=").is_err());
        assert!(parse_variant("single=hermes2").is_err());
    }

    #[test]
    fn parses_image_sources() {
        assert_eq!(
            parse_image_source("registry").unwrap(),
            ImageSource::Registry
        );
        assert_eq!(
            parse_image_source("fleet-cache=/mnt/argonas/agent-images").unwrap(),
            ImageSource::FleetCache {
                path: PathBuf::from("/mnt/argonas/agent-images"),
            }
        );
        assert_eq!(
            parse_image_source("fleet-cache=relative/cache").unwrap(),
            ImageSource::FleetCache {
                path: PathBuf::from("relative/cache"),
            }
        );
        assert_eq!(
            parse_image_source("tarball=/tmp/agent.tar").unwrap(),
            ImageSource::Tarball {
                path: PathBuf::from("/tmp/agent.tar"),
            }
        );
    }

    #[test]
    fn rejects_malformed_image_sources() {
        for source in ["", "fleet-cache=", "tarball=", "registry=/tmp/cache"] {
            let err = parse_image_source(source).unwrap_err();
            assert!(matches!(err, NczError::Usage(_)));
        }
    }

    #[test]
    fn install_uses_parsed_image_source_in_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();

        let report = install(
            &ctx(&runner),
            &paths,
            Some("macos-arm64-docker"),
            "single=hermes",
            "naked",
            "tarball=/tmp/hermes.tar",
            true,
        )
        .unwrap();

        match report {
            AgentReport::Install(report) => {
                assert_eq!(
                    report.spec.image_source,
                    ImageSource::Tarball {
                        path: PathBuf::from("/tmp/hermes.tar")
                    }
                );
                assert!(!report.applied);
                assert!(report.dry_run);
            }
            other => panic!("expected install report, got {other:?}"),
        }
    }

    #[test]
    fn podman_install_plan_uses_quadlets_and_systemd() {
        let spec = test_spec(ProfileTarget::Rpi5_16gb);
        let steps = planned_steps_for(&spec);

        assert_eq!(
            steps.first().unwrap(),
            "acquire mutation lock (per F-3 + cross-cmd-mutex)"
        );
        assert!(steps.iter().any(|step| step.starts_with("podman load:")));
        assert!(steps
            .iter()
            .any(|step| step.contains("/etc/containers/systemd/")));
        assert!(steps
            .iter()
            .any(|step| step.starts_with("systemctl daemon-reload")));
        assert!(!steps.iter().any(|step| step.starts_with("docker run:")));
        assert!(steps
            .iter()
            .any(|step| step.starts_with("convergent verify:")));
        assert!(steps.last().unwrap().starts_with("metadata-write:"));
    }

    #[test]
    fn docker_install_plan_uses_docker_lifecycle_without_systemd() {
        let spec = test_spec(ProfileTarget::MacosArm64Docker);
        let steps = planned_steps_for(&spec);

        assert_eq!(
            steps.first().unwrap(),
            "acquire mutation lock (per F-3 + cross-cmd-mutex)"
        );
        assert!(steps.iter().any(|step| step.starts_with("docker load:")));
        assert!(steps.iter().any(|step| {
            step.starts_with("docker run:")
                && step.contains("--label")
                && step.contains("--restart=unless-stopped")
                && step.contains("no systemd")
        }));
        assert!(!steps.iter().any(|step| step.starts_with("podman load:")));
        assert!(!steps
            .iter()
            .any(|step| step.starts_with("systemctl daemon-reload")));
        assert!(steps
            .iter()
            .any(|step| step.starts_with("convergent verify:")));
        assert!(steps.last().unwrap().starts_with("metadata-write:"));
    }

    #[test]
    fn install_plan_writes_metadata_as_final_step() {
        let spec = test_spec(ProfileTarget::LinuxAmd64Generic);
        let steps = planned_steps_for(&spec);

        assert!(steps.last().unwrap().contains("metadata-write"));
        assert!(steps
            .last()
            .unwrap()
            .contains("agents/<agent>/install-metadata.toml"));
    }

    #[test]
    fn parses_known_sandboxes() {
        assert!(matches!(
            parse_sandbox("naked").unwrap(),
            SandboxKind::Naked
        ));
        assert!(matches!(
            parse_sandbox("openshell").unwrap(),
            SandboxKind::OpenShell
        ));
    }

    #[test]
    fn rejects_unknown_sandbox() {
        assert!(parse_sandbox("gvisor").is_err());
        assert!(parse_sandbox("bwrap").is_err());
    }

    #[test]
    fn install_dry_run_does_not_acquire_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();

        let report = install(
            &ctx(&runner),
            &paths,
            Some("rpi5-16gb"),
            "triple",
            "openshell",
            "registry",
            true,
        )
        .unwrap();

        assert!(matches!(
            report,
            AgentReport::Install(AgentInstallReport {
                applied: false,
                dry_run: true,
                ..
            })
        ));
        assert!(!paths.lock_path.exists());
        assert!(!paths.lock_path.parent().unwrap().exists());
        assert!(!paths.agent_install_metadata(Agent::Zeroclaw).exists());
    }

    #[test]
    fn install_persists_metadata_after_planning_when_not_dry_run() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();

        let report = install(
            &ctx(&runner),
            &paths,
            Some("macos-arm64-docker"),
            "single=hermes",
            "naked",
            "registry",
            false,
        )
        .unwrap();

        assert!(matches!(
            report,
            AgentReport::Install(AgentInstallReport {
                applied: true,
                dry_run: false,
                ..
            })
        ));
        assert!(paths.lock_path.exists());
        let metadata = agent_install_metadata::read(&paths, Agent::Hermes).unwrap();
        assert_eq!(
            metadata,
            AgentInstallMetadata {
                agent: Agent::Hermes,
                profile: ProfileTarget::MacosArm64Docker,
                runtime: ContainerRuntime::Docker,
                sandbox: SandboxKind::Naked,
                installed_at: metadata.installed_at.clone(),
                image_digest: PENDING_IMAGE_DIGEST.to_string(),
            }
        );
        assert!(metadata.installed_at.ends_with('Z'));
    }

    #[test]
    fn mutating_agent_actions_acquire_lock() {
        for action in [
            AgentAction::Enable {
                agent: AgentName::from(Agent::Zeroclaw),
            },
            AgentAction::Disable {
                agent: AgentName::from(Agent::Zeroclaw),
            },
            AgentAction::Reload {
                agent: Some(AgentName::from(Agent::Zeroclaw)),
            },
            AgentAction::Uninstall {
                agent: Some(AgentName::from(Agent::Zeroclaw)),
                full: false,
            },
            AgentAction::Status,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let paths = test_paths(tmp.path());
            let runner = FakeRunner::new();

            let err = run_with_paths(&ctx(&runner), &paths, action).unwrap_err();

            assert!(matches!(err, NczError::Precondition(_)));
            assert!(paths.lock_path.exists());
        }
    }

    #[test]
    fn install_non_dry_run_acquires_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();

        let report = install(
            &ctx(&runner),
            &paths,
            Some("rpi5-16gb"),
            "triple",
            "openshell",
            "registry",
            false,
        )
        .unwrap();

        assert!(matches!(
            report,
            AgentReport::Install(AgentInstallReport {
                applied: true,
                dry_run: false,
                ..
            })
        ));
        assert!(paths.lock_path.exists());
    }

    #[test]
    fn lint_does_not_acquire_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();

        let err =
            run_with_paths(&ctx(&runner), &paths, AgentAction::Lint { bundle: None }).unwrap_err();

        assert!(matches!(err, NczError::Precondition(_)));
        assert!(!paths.lock_path.exists());
        assert!(!paths.lock_path.parent().unwrap().exists());
    }

    #[test]
    fn lifecycle_single_selector_fails_cleanly_when_metadata_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();

        let err = run_with_paths(
            &ctx(&runner),
            &paths,
            AgentAction::Enable {
                agent: AgentName::from(Agent::Zeroclaw),
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("missing install metadata for zeroclaw")
                    && message.contains("reinstall with `ncz agent install`")
        ));
        assert!(paths.lock_path.exists());
    }

    #[test]
    fn lifecycle_all_selector_fails_cleanly_when_no_metadata_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();

        let err =
            run_with_paths(&ctx(&runner), &paths, AgentAction::Reload { agent: None }).unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("no agent install metadata found")
                    && message.contains("reinstall with `ncz agent install`")
        ));
        assert!(paths.lock_path.exists());
    }

    #[test]
    fn all_selector_loads_installed_metadata_while_single_loads_one_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_metadata(&paths, Agent::Zeroclaw, ContainerRuntime::Docker);
        write_test_metadata(&paths, Agent::Hermes, ContainerRuntime::Podman);

        let single = load_metadata_for_selector(&paths, AgentSelector::One(Agent::Hermes)).unwrap();
        assert_eq!(metadata_agents(&single), vec!["hermes"]);

        let all = load_metadata_for_selector(&paths, AgentSelector::All).unwrap();
        assert_eq!(metadata_agents(&all), vec!["zeroclaw", "hermes"]);
    }

    #[test]
    fn docker_profile_lifecycle_uses_docker_branch_from_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        write_test_metadata(&paths, Agent::Hermes, ContainerRuntime::Docker);

        let err = run_with_paths(
            &ctx(&runner),
            &paths,
            AgentAction::Disable {
                agent: AgentName::from(Agent::Hermes),
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("metadata-load: agents/hermes/install-metadata.toml")
                    && message.contains("docker stop ncz-hermes")
                    && !message.contains("systemctl stop")
        ));
    }

    #[test]
    fn all_selector_lifecycle_branches_per_agent_metadata_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        write_test_metadata(&paths, Agent::Zeroclaw, ContainerRuntime::Docker);
        write_test_metadata(&paths, Agent::Hermes, ContainerRuntime::Podman);

        let err =
            run_with_paths(&ctx(&runner), &paths, AgentAction::Reload { agent: None }).unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("docker restart ncz-zeroclaw")
                    && message.contains("systemctl restart hermes.service")
        ));
    }

    #[test]
    fn status_loads_metadata_under_lock_and_uses_docker_status_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        write_test_metadata(&paths, Agent::Openclaw, ContainerRuntime::Docker);

        let err = run_with_paths(&ctx(&runner), &paths, AgentAction::Status).unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("metadata-load: agents/openclaw/install-metadata.toml")
                    && message.contains("docker container inspect")
        ));
        assert!(paths.lock_path.exists());
    }

    #[test]
    fn lint_verdict_approves_when_all_invariants_pass() {
        let report = AgentLintReport::from_results(
            "bundle".to_string(),
            vec![
                invariant(InvariantStatus::Pass),
                invariant(InvariantStatus::Pass),
            ],
        );

        assert_eq!(report.overall(), Verdict::Approve);
        assert_eq!(report.invariants_checked, 2);
        assert_eq!(report.invariants_passed, 2);
    }

    #[test]
    fn lint_verdict_incomplete_when_no_invariants_checked() {
        let report = AgentLintReport::from_results("bundle".to_string(), vec![]);

        assert_eq!(report.overall(), Verdict::Incomplete);
        assert_eq!(
            report.overall_message(),
            Some("no invariants checked - parser failed or invariant set missing")
        );
        assert_eq!(report.invariants_checked, 0);
        assert_eq!(report.invariants_passed, 0);
    }

    #[test]
    fn lint_verdict_approves_passes_with_skipped_invariants() {
        let report = AgentLintReport::from_results(
            "bundle".to_string(),
            vec![
                invariant(InvariantStatus::Pass),
                invariant(InvariantStatus::Skip),
                invariant(InvariantStatus::Pass),
            ],
        );

        assert_eq!(report.overall(), Verdict::Approve);
        assert_eq!(report.invariants_checked, 3);
        assert_eq!(report.invariants_passed, 2);
    }

    #[test]
    fn lint_verdict_warns_when_any_warning_and_no_failures() {
        let report = AgentLintReport::from_results(
            "bundle".to_string(),
            vec![
                invariant(InvariantStatus::Pass),
                invariant(InvariantStatus::Warn),
            ],
        );

        assert_eq!(report.overall(), Verdict::Warn);
        assert_eq!(report.invariants_checked, 2);
        assert_eq!(report.invariants_passed, 1);
    }

    #[test]
    fn lint_verdict_rejects_when_any_invariant_fails() {
        let report = AgentLintReport::from_results(
            "bundle".to_string(),
            vec![
                invariant(InvariantStatus::Warn),
                invariant(InvariantStatus::Fail),
            ],
        );

        assert_eq!(report.overall(), Verdict::Reject);
        assert_eq!(report.invariants_checked, 2);
        assert_eq!(report.invariants_passed, 0);
    }
}
