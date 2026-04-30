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

use crate::agent_spec::{
    Agent, AgentSpec, ContainerRuntime, ImageSource, ProfileTarget, SandboxKind, SpecError, Variant,
};
use crate::cli::{AgentAction, Context};
use crate::cmd::common;
use crate::error::NczError;
use crate::output::{self, Render};
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
    pub applied: bool,
}

impl Render for AgentMutationReport {
    fn render_text(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(
            w,
            "agent {}: agents={:?} applied={}",
            self.action, self.agents, self.applied
        )
    }
}

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AgentStatusReport {
    pub schema_version: u32,
    pub agents: Vec<AgentStatusEntry>,
}

impl Render for AgentStatusReport {
    fn render_text(&self, w: &mut dyn Write) -> io::Result<()> {
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
        let mut state = serializer.serialize_struct("AgentLintReport", 6)?;
        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("bundle_path", &self.bundle_path)?;
        state.serialize_field("invariants_checked", &self.invariants_checked)?;
        state.serialize_field("invariants_passed", &self.invariants_passed)?;
        state.serialize_field("results", &self.results)?;
        state.serialize_field("overall", &self.overall())?;
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
        writeln!(w, "verdict: {}", self.overall())
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

    pub fn verdict_for_results(results: &[InvariantResult]) -> Verdict {
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
    Warn,
    Fail,
}

impl fmt::Display for InvariantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Pass => "pass",
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
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Approve => "approve",
            Self::Warn => "warn",
            Self::Reject => "reject",
        };
        f.write_str(value)
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
        AgentAction::Enable { agent } => mutate(ctx, paths, "enable", &[agent])?,
        AgentAction::Disable { agent } => mutate(ctx, paths, "disable", &[agent])?,
        AgentAction::Reload { agent } => {
            let agents = agent.map(|a| vec![a]).unwrap_or_default();
            mutate(ctx, paths, "reload", &agents)?
        }
        AgentAction::Status => status(ctx, paths)?,
        AgentAction::Lint { bundle } => lint(ctx, paths, bundle.as_deref())?,
        AgentAction::Uninstall { agent, full } => {
            let agents = agent.map(|a| vec![a]).unwrap_or_default();
            uninstall(ctx, paths, &agents, full)?
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
    let _lock = if dry_run {
        None
    } else {
        Some(state::acquire_lock(&paths.lock_path)?)
    };

    // V1.0 scaffold: planned-steps emission + dry-run support; the actual
    // OCI-pull / runtime-specific laydown / enable cycle is the next
    // implementation slice. The shape (plan -> apply, convergent steps,
    // hash-verified images) is locked here; bodies fill in.
    let planned_steps = planned_steps_for(&spec);

    Err(NczError::Precondition(format!(
        "agent install scaffold — bodies pending. spec={spec:?} dry_run={dry_run} planned={planned_steps:?}"
    )))
}

fn mutate(
    _ctx: &Context,
    paths: &Paths,
    action: &str,
    agents: &[String],
) -> Result<AgentReport, NczError> {
    let _lock = state::acquire_lock(&paths.lock_path)?;
    Err(NczError::Precondition(format!(
        "agent {action} — bodies pending. agents={agents:?}"
    )))
}

fn status(_ctx: &Context, _paths: &Paths) -> Result<AgentReport, NczError> {
    Err(NczError::Precondition(
        "agent status — bodies pending".to_string(),
    ))
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
    agents: &[String],
    full: bool,
) -> Result<AgentReport, NczError> {
    let _lock = state::acquire_lock(&paths.lock_path)?;
    Err(NczError::Precondition(format!(
        "agent uninstall — bodies pending. agents={agents:?} full={full}"
    )))
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
    steps
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
        let agent = match name {
            "zeroclaw" => Agent::Zeroclaw,
            "openclaw" => Agent::Openclaw,
            "hermes" => Agent::Hermes,
            other => {
                return Err(NczError::Usage(format!(
                    "unknown agent '{other}'; expected one of: zeroclaw, openclaw, hermes"
                )));
            }
        };
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

        let err = install(
            &ctx(&runner),
            &paths,
            Some("macos-arm64-docker"),
            "single=hermes",
            "naked",
            "tarball=/tmp/hermes.tar",
            true,
        )
        .unwrap_err();

        match err {
            NczError::Precondition(message) => {
                assert!(message.contains("image_source: Tarball"));
                assert!(message.contains("/tmp/hermes.tar"));
            }
            other => panic!("expected precondition scaffold error, got {other:?}"),
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
        assert!(steps.last().unwrap().starts_with("convergent verify:"));
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
        assert!(steps.last().unwrap().starts_with("convergent verify:"));
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

        let err = run_with_paths(
            &ctx(&runner),
            &paths,
            AgentAction::Install {
                profile: Some("rpi5-16gb".to_string()),
                variant: "triple".to_string(),
                sandbox: "openshell".to_string(),
                from: "registry".to_string(),
                dry_run: true,
            },
        )
        .unwrap_err();

        assert!(matches!(err, NczError::Precondition(_)));
        assert!(!paths.lock_path.exists());
        assert!(!paths.lock_path.parent().unwrap().exists());
    }

    #[test]
    fn mutating_agent_actions_acquire_lock() {
        for action in [
            AgentAction::Install {
                profile: Some("rpi5-16gb".to_string()),
                variant: "triple".to_string(),
                sandbox: "openshell".to_string(),
                from: "registry".to_string(),
                dry_run: false,
            },
            AgentAction::Enable {
                agent: "zeroclaw".to_string(),
            },
            AgentAction::Disable {
                agent: "zeroclaw".to_string(),
            },
            AgentAction::Reload {
                agent: Some("zeroclaw".to_string()),
            },
            AgentAction::Uninstall {
                agent: Some("zeroclaw".to_string()),
                full: false,
            },
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
    fn read_only_agent_actions_do_not_acquire_lock() {
        for action in [AgentAction::Status, AgentAction::Lint { bundle: None }] {
            let tmp = tempfile::tempdir().unwrap();
            let paths = test_paths(tmp.path());
            let runner = FakeRunner::new();

            let err = run_with_paths(&ctx(&runner), &paths, action).unwrap_err();

            assert!(matches!(err, NczError::Precondition(_)));
            assert!(!paths.lock_path.exists());
            assert!(!paths.lock_path.parent().unwrap().exists());
        }
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
