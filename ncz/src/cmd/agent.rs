//! agent — install / enable / disable / lint / uninstall agents on the
//! local sandbox stack.
//!
//! V1.0 scope (per GRAEAE consult of 2026-04-29): in-place mode only,
//! 3 profiles (rpi5-16gb, linux-amd64-generic, macos-arm64-docker),
//! Naked + OpenShell sandboxes, Triple + Single variants. Hard refusal
//! on `agents/INVARIANTS.md` violations — no override flag; use
//! `ncz agent lint` to diagnose without installing.

use std::io::{self, Write};

use serde::Serialize;

use crate::agent_spec::{
    Agent, AgentSpec, ImageSource, ProfileTarget, SandboxKind, SpecError, Variant,
};
use crate::cli::{AgentAction, Context};
use crate::error::NczError;
use crate::output::{self, Render};

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

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AgentLintReport {
    pub schema_version: u32,
    pub bundle_path: String,
    pub invariants_checked: u32,
    pub invariants_passed: u32,
    pub findings: Vec<LintFinding>,
    pub overall: String,
}

impl Render for AgentLintReport {
    fn render_text(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(w, "agent lint: {}", self.bundle_path)?;
        writeln!(
            w,
            "  invariants: {}/{} passed",
            self.invariants_passed, self.invariants_checked
        )?;
        for f in &self.findings {
            writeln!(
                w,
                "  [{:8}] {} — {}",
                f.severity, f.invariant_id, f.statement
            )?;
        }
        writeln!(w, "verdict: {}", self.overall)
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub invariant_id: String,
    pub severity: String,
    pub statement: String,
}

pub fn run(ctx: &Context, action: AgentAction) -> Result<i32, NczError> {
    let report = match action {
        AgentAction::Install {
            profile,
            variant,
            sandbox,
            from,
            dry_run,
        } => install(ctx, profile.as_deref(), &variant, &sandbox, &from, dry_run)?,
        AgentAction::Enable { agent } => mutate(ctx, "enable", &[agent])?,
        AgentAction::Disable { agent } => mutate(ctx, "disable", &[agent])?,
        AgentAction::Reload { agent } => {
            let agents = agent.map(|a| vec![a]).unwrap_or_default();
            mutate(ctx, "reload", &agents)?
        }
        AgentAction::Status => status(ctx)?,
        AgentAction::Lint { bundle } => lint(ctx, bundle.as_deref())?,
        AgentAction::Uninstall { agent, full } => {
            let agents = agent.map(|a| vec![a]).unwrap_or_default();
            uninstall(ctx, &agents, full)?
        }
    };
    let code = match &report {
        AgentReport::Lint(r) if r.overall != "pass" => 4,
        _ => 0,
    };
    output::emit(&report, ctx.json)?;
    Ok(code)
}

fn install(
    _ctx: &Context,
    profile: Option<&str>,
    variant: &str,
    sandbox: &str,
    _from: &str,
    dry_run: bool,
) -> Result<AgentReport, NczError> {
    let profile = parse_profile(profile)?;
    let variant = parse_variant(variant)?;
    let sandbox = parse_sandbox(sandbox)?;
    let spec = AgentSpec {
        profile,
        variant: variant.clone(),
        sandbox,
        image_source: ImageSource::default(),
    };
    spec.validate()
        .map_err(|e: SpecError| NczError::Precondition(e.to_string()))?;

    // V1.0 scaffold: planned-steps emission + dry-run support; the actual
    // OCI-pull / quadlet-laydown / systemctl-enable cycle is the next
    // implementation slice. The shape (plan -> apply, convergent steps,
    // hash-verified images) is locked here; bodies fill in.
    let planned_steps = vec![
        format!(
            "verify image catalog matches sandbox={} for {} agent(s)",
            spec.sandbox.slug(),
            spec.variant.agents().len()
        ),
        "fetch + hash-verify OCI tarballs (per F-1)".to_string(),
        format!("podman load: {} image(s)", spec.variant.agents().len()),
        format!(
            "render quadlets: {} unit(s) into /etc/containers/systemd/",
            spec.variant.agents().len()
        ),
        "systemctl daemon-reload + enable units (per F-2)".to_string(),
        "convergent verify: skip writes for unchanged artifacts (per F-3)".to_string(),
    ];

    Err(NczError::Precondition(format!(
        "agent install scaffold — bodies pending. spec={spec:?} dry_run={dry_run} planned={planned_steps:?}"
    )))
}

fn mutate(_ctx: &Context, action: &str, agents: &[String]) -> Result<AgentReport, NczError> {
    Err(NczError::Precondition(format!(
        "agent {action} — bodies pending. agents={agents:?}"
    )))
}

fn status(_ctx: &Context) -> Result<AgentReport, NczError> {
    Err(NczError::Precondition(
        "agent status — bodies pending".to_string(),
    ))
}

fn lint(_ctx: &Context, bundle: Option<&std::path::Path>) -> Result<AgentReport, NczError> {
    let path = bundle
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(active bundle)".to_string());
    Err(NczError::Precondition(format!(
        "agent lint — bodies pending. bundle={path}"
    )))
}

fn uninstall(_ctx: &Context, agents: &[String], full: bool) -> Result<AgentReport, NczError> {
    Err(NczError::Precondition(format!(
        "agent uninstall — bodies pending. agents={agents:?} full={full}"
    )))
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
    use super::*;

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
}
