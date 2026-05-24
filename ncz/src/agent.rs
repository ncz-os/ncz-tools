//! agent — install / enable / disable / lint / uninstall agents on the
//! local sandbox stack.
//!
//! V1.0 scope (per GRAEAE consult of 2026-04-29): in-place mode only,
//! 3 profiles (rpi5-16gb, linux-amd64-generic, macos-arm64-docker),
//! Naked + OpenShell sandboxes, Triple + Single variants. Hard refusal
//! on `agents/INVARIANTS.md` violations — no override flag; use
//! `ncz agent lint` to diagnose without installing.

use std::fmt;
use std::fs;
use std::io::{self, Write};

use serde::{ser::SerializeStruct, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::agent_spec::{
    Agent, AgentSpec, ContainerRuntime, ImageSource, ProfileTarget, SandboxKind, SpecError, Variant,
};
use crate::cli::{AgentAction, AgentName, Context};
use crate::cmd::common;
use crate::error::NczError;
use crate::output::{self, Render};
use crate::state::agent_install_metadata::{
    self, AgentInstallMetadata, AGENT_INSTALL_METADATA_SCHEMA_VERSION, PENDING_IMAGE_DIGEST,
    PENDING_IMAGE_REFERENCE,
};
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

const NCZ_OWNERSHIP_LABEL_KEY: &str = "nclawzero";
const NCZ_OWNERSHIP_LABEL_VALUE: &str = "true";
const NCZ_OWNERSHIP_LABEL: &str = "nclawzero=true";

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
        } else if !results
            .iter()
            .any(|result| result.status == InvariantStatus::Pass)
        {
            Verdict::Incomplete
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
        } else if !results
            .iter()
            .any(|result| result.status == InvariantStatus::Pass)
            && !results
                .iter()
                .any(|result| result.status == InvariantStatus::Fail)
        {
            Some("no invariants passed - invariant set yielded no passing evidence")
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

    fn from_uninstall_args(all: bool, agent: Option<AgentName>) -> Self {
        if all {
            Self::All
        } else {
            Self::from_optional(agent)
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
        AgentAction::Uninstall {
            all,
            agent,
            full,
            force_recover_from_corrupt,
            destructive_recovery,
        } => uninstall(
            ctx,
            paths,
            AgentSelector::from_uninstall_args(all, agent),
            full,
            force_recover_from_corrupt,
            destructive_recovery,
        )?,
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
    _paths: &Paths,
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
        variant,
        sandbox,
        image_source,
    };
    spec.validate()
        .map_err(|e: SpecError| NczError::Precondition(e.to_string()))?;

    // V1.0 scaffold: planned-steps emission + dry-run support. Bodies
    // (OCI pull, runtime-specific laydown, enable cycle, invariant
    // validation) are not yet implemented — they land in the next slice.
    //
    // Until those bodies exist, non-dry-run install MUST refuse rather
    // than persist install-set.toml metadata. Persisting metadata for an
    // install that never deployed any images would mislead later
    // lifecycle/status ops into treating the host as installed when only
    // the metadata is present — making recovery and rollback harder.
    //
    // Per-finding round-6 (review-mol2a73y-4z6qhl): metadata persistence
    // moves to AFTER image load + laydown + enable + invariant validation
    // succeed, which is the next implementation slice. Until then,
    // non-dry-run is gated behind Precondition just like enable/disable/
    // reload/uninstall bodies.
    if !dry_run {
        return Err(NczError::Precondition(
            INSTALL_NON_DRY_RUN_PRECONDITION.to_string(),
        ));
    }

    Ok(AgentReport::Install(AgentInstallReport {
        schema_version: common::SCHEMA_VERSION,
        planned_steps: planned_steps_for(&spec),
        spec,
        applied: false,
        dry_run: true,
    }))
}

const INSTALL_NON_DRY_RUN_PRECONDITION: &str = concat!(
    "agent install bodies pending — only --dry-run is supported in V1.0 scaffold. ",
    "The install machinery (apply_install, persist_install_metadata) is tested separately; ",
    "the public install() will gain non-dry-run support when OCI pull / laydown / enable ",
    "bodies land in the next slice."
);

const CORRUPT_METADATA_PRESERVED_MESSAGE: &str = concat!(
    "metadata could not be parsed (possibly newer schema); ",
    "corrupt metadata preserved for retry. ",
    "To force-recover, run ncz agent uninstall --force-recover-from-corrupt."
);

const FORCE_RECOVER_FROM_CORRUPT_REQUIRES_ALL_MESSAGE: &str = concat!(
    "force-recover-from-corrupt requires --all selector to avoid orphaning non-selected agents. ",
    "Either run uninstall --all --force-recover-from-corrupt, or use ncz agent reinstall <agent> ",
    "if you only need to recover one agent."
);

#[cfg_attr(not(test), allow(dead_code))]
fn apply_install(paths: &Paths, spec: AgentSpec) -> Result<AgentInstallReport, NczError> {
    let planned_steps = planned_steps_for(&spec);
    let _lock = state::acquire_lock(&paths.lock_path)?;
    persist_install_metadata(paths, &spec)?;
    Ok(AgentInstallReport {
        schema_version: common::SCHEMA_VERSION,
        spec,
        planned_steps,
        applied: true,
        dry_run: false,
    })
}

fn mutate(
    _ctx: &Context,
    paths: &Paths,
    action: &str,
    selector: AgentSelector,
) -> Result<AgentReport, NczError> {
    let _lock = state::acquire_lock(&paths.lock_path)?;
    let metadata = load_metadata_for_selector(paths, selector)?;
    if action == "reload" {
        reject_tarball_reload_without_from(&metadata)?;
    }
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
    ctx: &Context,
    paths: &Paths,
    selector: AgentSelector,
    full: bool,
    force_recover_from_corrupt: bool,
    destructive_recovery: bool,
) -> Result<AgentReport, NczError> {
    let _lock = state::acquire_lock(&paths.lock_path)?;
    let plan = uninstall_plan(paths, selector, force_recover_from_corrupt)?;
    reject_unsafe_full_uninstall(full, selector, &plan.metadata)?;
    let mut planned_steps = uninstall_metadata_steps(&plan.metadata);
    cleanup_uninstall_artifacts(
        ctx,
        paths,
        &plan.targets,
        full,
        destructive_recovery,
        &mut planned_steps,
    )?;
    remove_uninstall_metadata(
        paths,
        selector,
        &plan.metadata,
        force_recover_from_corrupt,
        &mut planned_steps,
    )?;
    Ok(AgentReport::Uninstall(AgentMutationReport {
        schema_version: common::SCHEMA_VERSION,
        action: "uninstall".to_string(),
        agents: plan
            .targets
            .iter()
            .map(|target| target.agent.slug().to_string())
            .collect(),
        planned_steps,
        applied: true,
    }))
}

fn persist_install_metadata(paths: &Paths, spec: &AgentSpec) -> Result<(), NczError> {
    let installed_at = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|err| {
        NczError::Precondition(format!("could not format install timestamp: {err}"))
    })?;
    let metadata = spec
        .variant
        .agents()
        .into_iter()
        .map(|agent| AgentInstallMetadata {
            schema_version: AGENT_INSTALL_METADATA_SCHEMA_VERSION,
            agent,
            profile: spec.profile,
            runtime: spec.profile.default_runtime(),
            sandbox: spec.sandbox,
            installed_at: installed_at.clone(),
            image_source: spec.image_source.clone(),
            image_reference: PENDING_IMAGE_REFERENCE.to_string(),
            image_digest: PENDING_IMAGE_DIGEST.to_string(),
        })
        .collect();
    agent_install_metadata::write_install_set(paths, metadata)
}

fn reject_tarball_reload_without_from(metadata: &[AgentInstallMetadata]) -> Result<(), NczError> {
    for entry in metadata {
        if let ImageSource::Tarball { path } = &entry.image_source {
            return Err(NczError::Precondition(format!(
                "cannot reload {} from tarball {}: tarball is one-shot, re-run install with new --from",
                entry.agent,
                path.display()
            )));
        }
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

#[derive(Debug, Clone)]
struct UninstallPlan {
    metadata: OptionalInstallMetadata,
    targets: Vec<UninstallTarget>,
}

#[derive(Debug, Clone)]
struct UninstallTarget {
    agent: Agent,
    runtime_strategy: RuntimeCleanupStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeCleanupStrategy {
    Declared(ContainerRuntime),
    FallbackBothRuntimes,
}

#[derive(Debug, Clone)]
enum OptionalInstallMetadata {
    Loaded(Vec<AgentInstallMetadata>),
    Missing(String),
    Corrupt(String),
}

fn uninstall_plan(
    paths: &Paths,
    selector: AgentSelector,
    force_recover_from_corrupt: bool,
) -> Result<UninstallPlan, NczError> {
    if force_recover_from_corrupt && !matches!(selector, AgentSelector::All) {
        return Err(NczError::Usage(
            FORCE_RECOVER_FROM_CORRUPT_REQUIRES_ALL_MESSAGE.to_string(),
        ));
    }

    let metadata = load_optional_install_metadata(paths);
    if matches!(metadata, OptionalInstallMetadata::Corrupt(_)) && !force_recover_from_corrupt {
        return Err(corrupt_metadata_preserved_error());
    }
    let targets = uninstall_targets(selector, &metadata);
    Ok(UninstallPlan { metadata, targets })
}

fn corrupt_metadata_preserved_error() -> NczError {
    NczError::Inconsistent(CORRUPT_METADATA_PRESERVED_MESSAGE.to_string())
}

fn uninstall_targets(
    selector: AgentSelector,
    metadata: &OptionalInstallMetadata,
) -> Vec<UninstallTarget> {
    match metadata {
        OptionalInstallMetadata::Loaded(installed) => {
            selected_installed_metadata(selector, installed)
                .into_iter()
                .map(|entry| UninstallTarget {
                    agent: entry.agent,
                    runtime_strategy: RuntimeCleanupStrategy::Declared(entry.runtime),
                })
                .collect()
        }
        OptionalInstallMetadata::Missing(_) | OptionalInstallMetadata::Corrupt(_) => {
            selected_uninstall_agents(selector)
                .into_iter()
                .map(|agent| UninstallTarget {
                    agent,
                    runtime_strategy: RuntimeCleanupStrategy::FallbackBothRuntimes,
                })
                .collect()
        }
    }
}

fn selected_installed_metadata(
    selector: AgentSelector,
    installed: &[AgentInstallMetadata],
) -> Vec<AgentInstallMetadata> {
    match selector {
        AgentSelector::All => installed.to_vec(),
        AgentSelector::One(agent) => installed
            .iter()
            .filter(|entry| entry.agent == agent)
            .cloned()
            .collect(),
    }
}

fn selected_uninstall_agents(selector: AgentSelector) -> Vec<Agent> {
    match selector {
        AgentSelector::All => Agent::ALL.to_vec(),
        AgentSelector::One(agent) => vec![agent],
    }
}

fn reject_unsafe_full_uninstall(
    full: bool,
    selector: AgentSelector,
    metadata: &OptionalInstallMetadata,
) -> Result<(), NczError> {
    if !full || matches!(selector, AgentSelector::All) {
        return Ok(());
    }

    let retained = retained_metadata_agents_after_uninstall(selector, metadata);
    let retained_detail = if retained.is_empty() {
        "the request targets a single agent".to_string()
    } else {
        format!(
            "the request would retain installed agent(s): {}",
            retained
                .iter()
                .map(Agent::slug)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Err(NczError::Usage(format!(
        "--full is only allowed when uninstalling all agents because it removes shared /etc/nclawzero/agent-env and providers.d; {retained_detail}. Use `ncz agent uninstall --all --full` for a full wipe, or drop --full to uninstall only the selected agent."
    )))
}

fn retained_metadata_agents_after_uninstall(
    selector: AgentSelector,
    metadata: &OptionalInstallMetadata,
) -> Vec<Agent> {
    let selected = selected_uninstall_agents(selector);
    match metadata {
        OptionalInstallMetadata::Loaded(installed) => installed
            .iter()
            .filter(|entry| !selected.contains(&entry.agent))
            .map(|entry| entry.agent)
            .collect(),
        OptionalInstallMetadata::Missing(_) | OptionalInstallMetadata::Corrupt(_) => Vec::new(),
    }
}

fn load_optional_install_metadata(paths: &Paths) -> OptionalInstallMetadata {
    match agent_install_metadata::read_install_set(paths) {
        Ok(install_set) => OptionalInstallMetadata::Loaded(install_set.agents),
        Err(NczError::Precondition(message)) => OptionalInstallMetadata::Missing(message),
        Err(NczError::Inconsistent(message)) => OptionalInstallMetadata::Corrupt(message),
        Err(err) => OptionalInstallMetadata::Corrupt(err.to_string()),
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
                "podman volume create --label {NCZ_OWNERSHIP_LABEL}: {agent_count} volume(s)"
            ));
            steps.push(format!(
                "render quadlets: {agent_count} unit(s) into /etc/containers/systemd/ with Label={NCZ_OWNERSHIP_LABEL}"
            ));
            steps.push("systemctl daemon-reload + enable units (per F-2)".to_string());
        }
        ContainerRuntime::Docker => {
            // macos-arm64-docker stays in V1.0 scope, but its lifecycle is
            // Docker-native: no Podman quadlets and no systemd dependency.
            steps.push(format!("docker load: {agent_count} image(s)"));
            steps.push(format!(
                "docker volume create --label {NCZ_OWNERSHIP_LABEL}: {agent_count} volume(s)"
            ));
            steps.push(format!(
                "docker run: {agent_count} container(s) with --label {NCZ_OWNERSHIP_LABEL} and --restart=unless-stopped (no systemd)"
            ));
        }
    }
    steps.push("convergent verify: skip writes for unchanged artifacts (per F-3)".to_string());
    steps.push(format!(
        "metadata-write: atomically persist install set for {agent_count} agent(s) at agents/install-set.toml"
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
                    "{} + systemctl restart {}",
                    reload_image_source_step(entry),
                    service_name(entry.agent)
                )
            }
            ("reload", ContainerRuntime::Docker) => {
                format!(
                    "{} + docker restart {}",
                    reload_image_source_step(entry),
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

fn uninstall_metadata_steps(metadata: &OptionalInstallMetadata) -> Vec<String> {
    match metadata {
        OptionalInstallMetadata::Loaded(_) => {
            vec!["metadata-load: agents/install-set.toml".to_string()]
        }
        OptionalInstallMetadata::Missing(message) => vec![format!(
            "metadata-load: agents/install-set.toml missing; fallback cleanup without metadata ({message})"
        )],
        OptionalInstallMetadata::Corrupt(message) => vec![format!(
            "metadata-load: agents/install-set.toml corrupt; fallback cleanup without metadata ({message})"
        )],
    }
}

fn cleanup_uninstall_artifacts(
    ctx: &Context,
    paths: &Paths,
    targets: &[UninstallTarget],
    full: bool,
    destructive_recovery: bool,
    steps: &mut Vec<String>,
) -> Result<(), NczError> {
    let mut failures = Vec::new();
    for target in targets {
        match target.runtime_strategy {
            RuntimeCleanupStrategy::Declared(ContainerRuntime::Podman) => {
                cleanup_podman_artifacts(
                    ctx,
                    paths,
                    target.agent,
                    MissingToolBehavior::Fail,
                    VolumeDeletionPolicy::MetadataOwned,
                    steps,
                    &mut failures,
                );
            }
            RuntimeCleanupStrategy::Declared(ContainerRuntime::Docker) => {
                cleanup_docker_artifacts(
                    ctx,
                    target.agent,
                    MissingToolBehavior::Fail,
                    VolumeDeletionPolicy::MetadataOwned,
                    steps,
                    &mut failures,
                );
            }
            RuntimeCleanupStrategy::FallbackBothRuntimes => {
                cleanup_podman_artifacts(
                    ctx,
                    paths,
                    target.agent,
                    MissingToolBehavior::NotFound,
                    VolumeDeletionPolicy::RequireNczLabel {
                        destructive_recovery,
                    },
                    steps,
                    &mut failures,
                );
                cleanup_docker_artifacts(
                    ctx,
                    target.agent,
                    MissingToolBehavior::NotFound,
                    VolumeDeletionPolicy::RequireNczLabel {
                        destructive_recovery,
                    },
                    steps,
                    &mut failures,
                );
            }
        }
    }
    if !failures.is_empty() {
        return Err(cleanup_failure_error(&failures));
    }

    if full {
        cleanup_full_uninstall_paths(paths, steps, &mut failures);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(cleanup_failure_error(&failures))
    }
}

fn cleanup_podman_artifacts(
    ctx: &Context,
    paths: &Paths,
    agent: Agent,
    missing_tool_behavior: MissingToolBehavior,
    volume_policy: VolumeDeletionPolicy,
    steps: &mut Vec<String>,
    failures: &mut Vec<CleanupFailure>,
) {
    let unit = service_name(agent);
    let slug = agent.slug();
    let volume = volume_name(agent);

    match probe_command(ctx, "systemctl", &["cat", &unit], missing_tool_behavior) {
        CleanupProbe::Found => {
            record_cleanup_step(
                steps,
                failures,
                format!("podman service cleanup: {unit}"),
                cleanup_command(ctx, "sudo", &["systemctl", "stop", &unit]),
            );
            record_cleanup_step(
                steps,
                failures,
                format!("podman service disable: {unit}"),
                cleanup_command(ctx, "sudo", &["systemctl", "disable", &unit]),
            );
        }
        CleanupProbe::NotFound => record_cleanup_step(
            steps,
            failures,
            format!("podman service cleanup: {unit}"),
            CleanupOutcome::NotFound,
        ),
        CleanupProbe::Failed { reason } => record_cleanup_step(
            steps,
            failures,
            format!("podman service cleanup: {unit}"),
            probe_failed_outcome(reason),
        ),
    }

    let quadlet = paths.agent_quadlet(slug);
    match remove_path_if_present(&quadlet) {
        CleanupOutcome::Removed => {
            record_cleanup_step(
                steps,
                failures,
                format!("podman quadlet cleanup: {}", quadlet.display()),
                CleanupOutcome::Removed,
            );
            record_cleanup_step(
                steps,
                failures,
                "podman systemd reload",
                cleanup_command(ctx, "sudo", &["systemctl", "daemon-reload"]),
            );
        }
        outcome => record_cleanup_step(
            steps,
            failures,
            format!("podman quadlet cleanup: {}", quadlet.display()),
            outcome,
        ),
    }

    match probe_command(
        ctx,
        "podman",
        &["container", "exists", slug],
        missing_tool_behavior,
    ) {
        CleanupProbe::Found => record_cleanup_step(
            steps,
            failures,
            format!("podman container cleanup: {slug}"),
            cleanup_command(ctx, "podman", &["rm", "-f", slug]),
        ),
        CleanupProbe::NotFound => record_cleanup_step(
            steps,
            failures,
            format!("podman container cleanup: {slug}"),
            CleanupOutcome::NotFound,
        ),
        CleanupProbe::Failed { reason } => record_cleanup_step(
            steps,
            failures,
            format!("podman container cleanup: {slug}"),
            probe_failed_outcome(reason),
        ),
    }

    match probe_command(
        ctx,
        "podman",
        &["volume", "exists", &volume],
        missing_tool_behavior,
    ) {
        CleanupProbe::Found => record_cleanup_step(
            steps,
            failures,
            format!("podman volume cleanup: {volume}"),
            cleanup_podman_volume(ctx, &volume, volume_policy),
        ),
        CleanupProbe::NotFound => record_cleanup_step(
            steps,
            failures,
            format!("podman volume cleanup: {volume}"),
            CleanupOutcome::NotFound,
        ),
        CleanupProbe::Failed { reason } => record_cleanup_step(
            steps,
            failures,
            format!("podman volume cleanup: {volume}"),
            probe_failed_outcome(reason),
        ),
    }
}

fn cleanup_docker_artifacts(
    ctx: &Context,
    agent: Agent,
    missing_tool_behavior: MissingToolBehavior,
    volume_policy: VolumeDeletionPolicy,
    steps: &mut Vec<String>,
    failures: &mut Vec<CleanupFailure>,
) {
    let container = docker_container_name(agent);
    let volume = volume_name(agent);

    match probe_command(
        ctx,
        "docker",
        &["container", "inspect", &container],
        missing_tool_behavior,
    ) {
        CleanupProbe::Found => record_cleanup_step(
            steps,
            failures,
            format!("docker container cleanup: {container}"),
            cleanup_command(ctx, "docker", &["rm", "-f", &container]),
        ),
        CleanupProbe::NotFound => record_cleanup_step(
            steps,
            failures,
            format!("docker container cleanup: {container}"),
            CleanupOutcome::NotFound,
        ),
        CleanupProbe::Failed { reason } => record_cleanup_step(
            steps,
            failures,
            format!("docker container cleanup: {container}"),
            probe_failed_outcome(reason),
        ),
    }

    record_cleanup_step(
        steps,
        failures,
        format!("docker volume cleanup: {volume}"),
        cleanup_docker_volume(ctx, &volume, missing_tool_behavior, volume_policy),
    );
}

fn cleanup_full_uninstall_paths(
    paths: &Paths,
    steps: &mut Vec<String>,
    failures: &mut Vec<CleanupFailure>,
) {
    record_cleanup_step(
        steps,
        failures,
        format!(
            "full uninstall: remove shared agent-env {}",
            paths.agent_env().display()
        ),
        remove_path_if_present(&paths.agent_env()),
    );
    record_cleanup_step(
        steps,
        failures,
        format!(
            "full uninstall: remove provider data dir {}",
            paths.providers_dir().display()
        ),
        remove_dir_if_present(&paths.providers_dir()),
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CleanupProbe {
    Found,
    NotFound,
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CleanupOutcome {
    NotFound,
    Removed,
    Failed { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingToolBehavior {
    Fail,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VolumeDeletionPolicy {
    MetadataOwned,
    RequireNczLabel { destructive_recovery: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupFailure {
    step: String,
    reason: String,
}

fn cleanup_podman_volume(
    ctx: &Context,
    volume: &str,
    volume_policy: VolumeDeletionPolicy,
) -> CleanupOutcome {
    cleanup_existing_volume(ctx, "podman", volume, volume_policy)
}

fn cleanup_docker_volume(
    ctx: &Context,
    volume: &str,
    missing_tool_behavior: MissingToolBehavior,
    volume_policy: VolumeDeletionPolicy,
) -> CleanupOutcome {
    match volume_policy {
        VolumeDeletionPolicy::MetadataOwned => match probe_command(
            ctx,
            "docker",
            &["volume", "inspect", volume],
            missing_tool_behavior,
        ) {
            CleanupProbe::Found => cleanup_command(ctx, "docker", &["volume", "rm", "-f", volume]),
            CleanupProbe::NotFound => CleanupOutcome::NotFound,
            CleanupProbe::Failed { reason } => probe_failed_outcome(reason),
        },
        VolumeDeletionPolicy::RequireNczLabel { .. } => {
            match inspect_volume_for_ownership(ctx, "docker", volume, missing_tool_behavior) {
                VolumeInspectProbe::Found { ncz_labeled } => {
                    cleanup_inspected_volume(ctx, "docker", volume, ncz_labeled, volume_policy)
                }
                VolumeInspectProbe::NotFound => CleanupOutcome::NotFound,
                VolumeInspectProbe::Failed { reason } => probe_failed_outcome(reason),
            }
        }
    }
}

fn cleanup_existing_volume(
    ctx: &Context,
    runtime_cmd: &str,
    volume: &str,
    volume_policy: VolumeDeletionPolicy,
) -> CleanupOutcome {
    match volume_policy {
        VolumeDeletionPolicy::MetadataOwned => {
            cleanup_command(ctx, runtime_cmd, &["volume", "rm", "-f", volume])
        }
        VolumeDeletionPolicy::RequireNczLabel { .. } => {
            match inspect_volume_for_ownership(ctx, runtime_cmd, volume, MissingToolBehavior::Fail)
            {
                VolumeInspectProbe::Found { ncz_labeled } => {
                    cleanup_inspected_volume(ctx, runtime_cmd, volume, ncz_labeled, volume_policy)
                }
                VolumeInspectProbe::NotFound => CleanupOutcome::NotFound,
                VolumeInspectProbe::Failed { reason } => probe_failed_outcome(reason),
            }
        }
    }
}

fn cleanup_inspected_volume(
    ctx: &Context,
    runtime_cmd: &str,
    volume: &str,
    ncz_labeled: bool,
    volume_policy: VolumeDeletionPolicy,
) -> CleanupOutcome {
    match volume_policy {
        VolumeDeletionPolicy::MetadataOwned => {
            cleanup_command(ctx, runtime_cmd, &["volume", "rm", "-f", volume])
        }
        VolumeDeletionPolicy::RequireNczLabel {
            destructive_recovery,
        } => {
            if ncz_labeled || destructive_recovery {
                cleanup_command(ctx, runtime_cmd, &["volume", "rm", "-f", volume])
            } else {
                CleanupOutcome::Failed {
                    reason: ambiguous_unlabeled_artifact_message(volume),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VolumeInspectProbe {
    Found { ncz_labeled: bool },
    NotFound,
    Failed { reason: String },
}

fn inspect_volume_for_ownership(
    ctx: &Context,
    runtime_cmd: &str,
    volume: &str,
    missing_tool_behavior: MissingToolBehavior,
) -> VolumeInspectProbe {
    let args = ["volume", "inspect", volume];
    match ctx.runner.run(runtime_cmd, &args) {
        Ok(out) if out.ok() => match inspect_stdout_has_ncz_label(&out.stdout) {
            Ok(ncz_labeled) => VolumeInspectProbe::Found { ncz_labeled },
            Err(reason) => VolumeInspectProbe::Failed { reason },
        },
        Ok(out) => {
            let missing_tool = missing_tool_behavior == MissingToolBehavior::NotFound
                && probe_output_is_missing_tool(runtime_cmd, out.status, &out.stdout, &out.stderr);
            let not_found =
                probe_output_is_not_found(runtime_cmd, &args, out.status, &out.stdout, &out.stderr);
            if missing_tool || not_found {
                VolumeInspectProbe::NotFound
            } else {
                VolumeInspectProbe::Failed {
                    reason: cleanup_output_message(out.status, &out.stdout, &out.stderr),
                }
            }
        }
        Err(err) => {
            if missing_tool_behavior == MissingToolBehavior::NotFound
                && command_error_is_missing_tool(&err, runtime_cmd)
            {
                VolumeInspectProbe::NotFound
            } else {
                VolumeInspectProbe::Failed {
                    reason: err.to_string(),
                }
            }
        }
    }
}

fn inspect_stdout_has_ncz_label(stdout: &str) -> Result<bool, String> {
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).map_err(|err| {
        format!("could not parse volume inspect labels for {NCZ_OWNERSHIP_LABEL}: {err}")
    })?;
    Ok(volume_inspect_value_has_ncz_label(&value))
}

fn volume_inspect_value_has_ncz_label(value: &serde_json::Value) -> bool {
    let Some(object) = first_volume_inspect_object(value) else {
        return false;
    };
    let labels = object.get("Labels").or_else(|| object.get("labels"));
    let Some(labels) = labels.and_then(serde_json::Value::as_object) else {
        return false;
    };
    match labels.get(NCZ_OWNERSHIP_LABEL_KEY) {
        Some(serde_json::Value::String(value)) => value == NCZ_OWNERSHIP_LABEL_VALUE,
        Some(serde_json::Value::Bool(value)) => *value,
        _ => false,
    }
}

fn first_volume_inspect_object(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    if let Some(array) = value.as_array() {
        return array.first().and_then(serde_json::Value::as_object);
    }
    value.as_object()
}

fn ambiguous_unlabeled_artifact_message(name: &str) -> String {
    format!(
        "ambiguous artifact {name} not labeled {NCZ_OWNERSHIP_LABEL}; not deleting. Re-run with --destructive-recovery to force delete."
    )
}

fn probe_command(
    ctx: &Context,
    cmd: &str,
    args: &[&str],
    missing_tool_behavior: MissingToolBehavior,
) -> CleanupProbe {
    match ctx.runner.run(cmd, args) {
        Ok(out) if out.ok() => CleanupProbe::Found,
        Ok(out) => {
            let missing_tool = missing_tool_behavior == MissingToolBehavior::NotFound
                && probe_output_is_missing_tool(cmd, out.status, &out.stdout, &out.stderr);
            let not_found =
                probe_output_is_not_found(cmd, args, out.status, &out.stdout, &out.stderr);
            if missing_tool || not_found {
                CleanupProbe::NotFound
            } else {
                CleanupProbe::Failed {
                    reason: cleanup_output_message(out.status, &out.stdout, &out.stderr),
                }
            }
        }
        Err(err) => {
            if missing_tool_behavior == MissingToolBehavior::NotFound
                && command_error_is_missing_tool(&err, cmd)
            {
                CleanupProbe::NotFound
            } else {
                CleanupProbe::Failed {
                    reason: err.to_string(),
                }
            }
        }
    }
}

fn cleanup_command(ctx: &Context, cmd: &str, args: &[&str]) -> CleanupOutcome {
    match ctx.runner.run(cmd, args) {
        Ok(out) if out.ok() => CleanupOutcome::Removed,
        Ok(out) => CleanupOutcome::Failed {
            reason: cleanup_output_message(out.status, &out.stdout, &out.stderr),
        },
        Err(err) => CleanupOutcome::Failed {
            reason: err.to_string(),
        },
    }
}

fn probe_output_is_not_found(
    cmd: &str,
    args: &[&str],
    status: i32,
    stdout: &str,
    stderr: &str,
) -> bool {
    if status == 125 {
        return false;
    }
    if probe_output_is_missing_tool(cmd, status, stdout, stderr) {
        return false;
    }

    let output = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    if output.contains("permission denied")
        || output.contains("cannot connect")
        || output.contains("connection refused")
        || output.contains("daemon")
    {
        return false;
    }

    match (cmd, args) {
        ("systemctl", ["cat", _]) => {
            output.contains("not found")
                || output.contains("not-found")
                || output.contains("no files found")
                || output.contains("no such")
        }
        ("podman", ["container", "exists", _]) | ("podman", ["volume", "exists", _]) => status == 1,
        ("docker", ["container", "inspect", _]) | ("docker", ["volume", "inspect", _]) => {
            output.contains("not found") || output.contains("no such")
        }
        _ => false,
    }
}

fn probe_output_is_missing_tool(cmd: &str, status: i32, stdout: &str, stderr: &str) -> bool {
    if status != 126 && status != 127 {
        return false;
    }
    let output = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    output.contains("command not found")
        || output.contains("no such file or directory")
        || output.contains(&format!("{cmd}: not found"))
}

fn command_error_is_missing_tool(err: &NczError, expected_cmd: &str) -> bool {
    match err {
        NczError::Exec { cmd, msg } if cmd == expected_cmd => {
            let msg = msg.to_ascii_lowercase();
            msg.contains("no such file or directory") || msg.contains("os error 2")
        }
        _ => false,
    }
}

fn cleanup_output_message(status: i32, stdout: &str, stderr: &str) -> String {
    let message = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    if message.is_empty() {
        format!("exit status {status}")
    } else {
        message
    }
}

fn probe_failed_outcome(reason: String) -> CleanupOutcome {
    CleanupOutcome::Failed {
        reason: format!("probe failed: {reason}"),
    }
}

fn record_cleanup_step(
    steps: &mut Vec<String>,
    failures: &mut Vec<CleanupFailure>,
    label: impl Into<String>,
    outcome: CleanupOutcome,
) {
    let label = label.into();
    match outcome {
        CleanupOutcome::NotFound => steps.push(format!("{label} not found")),
        CleanupOutcome::Removed => steps.push(format!("{label} removed")),
        CleanupOutcome::Failed { reason } => {
            steps.push(format!("{label} failed: {reason}"));
            failures.push(CleanupFailure {
                step: label,
                reason,
            });
        }
    }
}

fn cleanup_failure_error(failures: &[CleanupFailure]) -> NczError {
    let details = failures
        .iter()
        .map(|failure| format!("{} ({})", failure.step, failure.reason))
        .collect::<Vec<_>>()
        .join("; ");
    NczError::Inconsistent(format!(
        "uninstall cleanup failed: {details}; metadata preserved for retry"
    ))
}

fn remove_path_if_present(path: &std::path::Path) -> CleanupOutcome {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => CleanupOutcome::Failed {
            reason: "path is a directory".to_string(),
        },
        Ok(_) => match state::remove_file_durable(path) {
            Ok(()) => CleanupOutcome::Removed,
            Err(err) => CleanupOutcome::Failed {
                reason: err.to_string(),
            },
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => CleanupOutcome::NotFound,
        Err(err) => CleanupOutcome::Failed {
            reason: err.to_string(),
        },
    }
}

fn remove_dir_if_present(path: &std::path::Path) -> CleanupOutcome {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => match fs::remove_dir_all(path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    if let Err(err) = std::fs::File::open(parent).and_then(|file| file.sync_all()) {
                        return CleanupOutcome::Failed {
                            reason: err.to_string(),
                        };
                    }
                }
                CleanupOutcome::Removed
            }
            Err(err) => CleanupOutcome::Failed {
                reason: err.to_string(),
            },
        },
        Ok(_) => CleanupOutcome::Failed {
            reason: "path is not a directory".to_string(),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => CleanupOutcome::NotFound,
        Err(err) => CleanupOutcome::Failed {
            reason: err.to_string(),
        },
    }
}

fn remove_uninstall_metadata(
    paths: &Paths,
    selector: AgentSelector,
    metadata: &OptionalInstallMetadata,
    force_recover_from_corrupt: bool,
    steps: &mut Vec<String>,
) -> Result<(), NczError> {
    let selected = selected_uninstall_agents(selector);
    match metadata {
        OptionalInstallMetadata::Loaded(installed) => {
            let retained: Vec<_> = installed
                .iter()
                .filter(|entry| !selected.contains(&entry.agent))
                .cloned()
                .collect();
            if retained.is_empty() {
                let removed = remove_install_set_path(paths)?;
                steps.push(if removed {
                    "metadata-remove: agents/install-set.toml deleted".to_string()
                } else {
                    "metadata-remove: agents/install-set.toml already absent".to_string()
                });
            } else if retained.len() == installed.len() {
                steps.push(
                    "metadata-remove: agents/install-set.toml unchanged; no selected agent entries"
                        .to_string(),
                );
            } else {
                agent_install_metadata::write_install_set(paths, retained)?;
                steps.push(format!(
                    "metadata-remove: agents/install-set.toml entry for {}",
                    selected
                        .iter()
                        .map(Agent::slug)
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
        }
        OptionalInstallMetadata::Missing(_) => {
            steps.push("metadata-remove: agents/install-set.toml already absent".to_string());
        }
        OptionalInstallMetadata::Corrupt(_) if force_recover_from_corrupt => {
            backup_and_remove_corrupt_install_metadata(paths, steps)?;
        }
        OptionalInstallMetadata::Corrupt(_) => {
            return Err(corrupt_metadata_preserved_error());
        }
    }
    Ok(())
}

fn backup_and_remove_corrupt_install_metadata(
    paths: &Paths,
    steps: &mut Vec<String>,
) -> Result<(), NczError> {
    let path = paths.agent_install_set();
    let metadata = match fs::metadata(&path) {
        Ok(metadata) if metadata.is_dir() => {
            return Err(NczError::Inconsistent(format!(
                "cannot force-recover corrupt install metadata at {}: path is a directory; corrupt metadata preserved for retry",
                path.display()
            )));
        }
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            steps.push("metadata-remove: agents/install-set.toml already absent".to_string());
            return Ok(());
        }
        Err(err) => {
            return Err(NczError::Inconsistent(format!(
                "cannot inspect corrupt install metadata at {}: {err}; corrupt metadata preserved for retry",
                path.display()
            )));
        }
    };

    let body = fs::read(&path).map_err(|err| {
        NczError::Inconsistent(format!(
            "cannot read corrupt install metadata at {}: {err}; corrupt metadata preserved for retry",
            path.display()
        ))
    })?;
    let backup_path = corrupt_install_metadata_backup_path(&path)?;
    state::atomic_write(&backup_path, &body, metadata_permissions(&metadata)).map_err(
        |err| {
            NczError::Inconsistent(format!(
                "cannot back up corrupt install metadata from {} to {}: {err}; corrupt metadata preserved for retry",
                path.display(),
                backup_path.display()
            ))
        },
    )?;
    state::remove_file_durable(&path).map_err(|err| {
        NczError::Inconsistent(format!(
            "cannot remove corrupt install metadata at {} after backup to {}: {err}; backup preserved for retry",
            path.display(),
            backup_path.display()
        ))
    })?;
    let backup_name = backup_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("install-set.toml.corrupt-backup");
    steps.push(format!(
        "metadata-force-recover: backed up corrupt agents/install-set.toml to {backup_name}"
    ));
    steps.push(
        "metadata-remove: agents/install-set.toml deleted after corrupt metadata backup"
            .to_string(),
    );
    Ok(())
}

#[cfg(unix)]
fn metadata_permissions(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn metadata_permissions(_metadata: &fs::Metadata) -> u32 {
    0o644
}

fn corrupt_install_metadata_backup_path(
    path: &std::path::Path,
) -> Result<std::path::PathBuf, NczError> {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| NczError::Precondition(format!("could not format backup timestamp: {err}")))?
        .replace(':', "");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            NczError::Precondition(format!(
                "install metadata path has no filename: {}",
                path.display()
            ))
        })?;
    Ok(path.with_file_name(format!("{file_name}.corrupt-backup-{timestamp}")))
}

fn remove_install_set_path(paths: &Paths) -> Result<bool, NczError> {
    let path = paths.agent_install_set();
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(&path).map_err(|err| {
                NczError::Inconsistent(format!(
                    "cannot remove install metadata directory at {}: {err}",
                    path.display()
                ))
            })?;
        }
        Ok(_) => {
            state::remove_file_durable(&path)?;
            return Ok(true);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(NczError::Io(err)),
    }

    if let Some(parent) = path.parent() {
        if parent.exists() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(true)
}

fn volume_name(agent: Agent) -> String {
    format!("{}-data", agent.slug())
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
    if metadata.is_empty() {
        Vec::new()
    } else {
        vec!["metadata-load: agents/install-set.toml".to_string()]
    }
}

fn service_name(agent: Agent) -> String {
    format!("{}.service", agent.slug())
}

fn docker_container_name(agent: Agent) -> String {
    format!("ncz-{}", agent.slug())
}

fn reload_image_source_step(entry: &AgentInstallMetadata) -> String {
    match &entry.image_source {
        ImageSource::Registry => format!("{} registry image refresh", runtime_slug(entry.runtime)),
        ImageSource::FleetCache { path } => format!(
            "{} fleet-cache image refresh from {}",
            runtime_slug(entry.runtime),
            path.display()
        ),
        ImageSource::Tarball { path } => format!(
            "{} tarball image refresh from {}",
            runtime_slug(entry.runtime),
            path.display()
        ),
    }
}

fn runtime_slug(runtime: ContainerRuntime) -> &'static str {
    match runtime {
        ContainerRuntime::Podman => "podman",
        ContainerRuntime::Docker => "docker",
    }
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
                    ImageSource::fleet_cache(path)
                        .map_err(|err| invalid_image_source_path("fleet-cache", err))
                }
            } else if let Some(path) = s.strip_prefix("tarball=") {
                if path.is_empty() {
                    Err(invalid_image_source(s))
                } else {
                    ImageSource::tarball(path)
                        .map_err(|err| invalid_image_source_path("tarball", err))
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

fn invalid_image_source_path(kind: &str, err: SpecError) -> NczError {
    NczError::Usage(format!("{err}; use '{kind}=/absolute/path'"))
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
    use crate::cmd::common::{out, test_paths};
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
        test_metadata_with_source(agent, runtime, ImageSource::Registry)
    }

    fn test_metadata_with_source(
        agent: Agent,
        runtime: ContainerRuntime,
        image_source: ImageSource,
    ) -> AgentInstallMetadata {
        AgentInstallMetadata {
            schema_version: AGENT_INSTALL_METADATA_SCHEMA_VERSION,
            agent,
            profile: match runtime {
                ContainerRuntime::Podman => ProfileTarget::Rpi5_16gb,
                ContainerRuntime::Docker => ProfileTarget::MacosArm64Docker,
            },
            runtime,
            sandbox: SandboxKind::OpenShell,
            installed_at: "2026-04-30T00:00:00Z".to_string(),
            image_source,
            image_reference: PENDING_IMAGE_REFERENCE.to_string(),
            image_digest: PENDING_IMAGE_DIGEST.to_string(),
        }
    }

    fn write_test_install_set(paths: &Paths, metadata: Vec<AgentInstallMetadata>) {
        agent_install_metadata::write_install_set(paths, metadata).unwrap();
    }

    fn expect_unknown_runtime_cleanup(runner: &FakeRunner, agent: Agent) {
        expect_podman_not_found_cleanup(runner, agent);
        expect_docker_not_found_cleanup(runner, agent);
    }

    fn expect_unknown_runtime_cleanup_with_missing_podman_tools(runner: &FakeRunner, agent: Agent) {
        let unit = service_name(agent);
        let volume = volume_name(agent);
        runner.expect(
            "systemctl",
            &["cat", &unit],
            out(127, "", "systemctl: command not found\n"),
        );
        runner.expect(
            "podman",
            &["container", "exists", agent.slug()],
            out(127, "", "podman: command not found\n"),
        );
        runner.expect(
            "podman",
            &["volume", "exists", &volume],
            out(127, "", "podman: command not found\n"),
        );
        expect_docker_not_found_cleanup(runner, agent);
    }

    fn expect_podman_not_found_cleanup(runner: &FakeRunner, agent: Agent) {
        let unit = service_name(agent);
        let volume = volume_name(agent);
        runner.expect("systemctl", &["cat", &unit], out(1, "", "not found\n"));
        runner.expect(
            "podman",
            &["container", "exists", agent.slug()],
            out(1, "", ""),
        );
        runner.expect("podman", &["volume", "exists", &volume], out(1, "", ""));
    }

    fn expect_docker_not_found_cleanup(runner: &FakeRunner, agent: Agent) {
        let container = docker_container_name(agent);
        let volume = volume_name(agent);
        runner.expect(
            "docker",
            &["container", "inspect", &container],
            out(1, "", "not found\n"),
        );
        runner.expect(
            "docker",
            &["volume", "inspect", &volume],
            out(1, "", "not found\n"),
        );
    }

    fn labeled_volume_inspect_json() -> &'static str {
        r#"[{"Labels":{"nclawzero":"true"}}]"#
    }

    fn unlabeled_volume_inspect_json() -> &'static str {
        r#"[{"Labels":{}}]"#
    }

    fn expect_podman_fallback_volume_cleanup(
        runner: &FakeRunner,
        agent: Agent,
        inspect_stdout: &str,
        expect_remove: bool,
    ) {
        let unit = service_name(agent);
        let volume = volume_name(agent);
        runner.expect("systemctl", &["cat", &unit], out(1, "", "not found\n"));
        runner.expect(
            "podman",
            &["container", "exists", agent.slug()],
            out(1, "", ""),
        );
        runner.expect("podman", &["volume", "exists", &volume], out(0, "", ""));
        runner.expect(
            "podman",
            &["volume", "inspect", &volume],
            out(0, inspect_stdout, ""),
        );
        if expect_remove {
            runner.expect("podman", &["volume", "rm", "-f", &volume], out(0, "", ""));
        }
    }

    fn expect_docker_fallback_volume_cleanup(
        runner: &FakeRunner,
        agent: Agent,
        inspect_stdout: &str,
        expect_remove: bool,
    ) {
        let container = docker_container_name(agent);
        let volume = volume_name(agent);
        runner.expect(
            "docker",
            &["container", "inspect", &container],
            out(1, "", "not found\n"),
        );
        runner.expect(
            "docker",
            &["volume", "inspect", &volume],
            out(0, inspect_stdout, ""),
        );
        if expect_remove {
            runner.expect("docker", &["volume", "rm", "-f", &volume], out(0, "", ""));
        }
    }

    fn uninstall_report(report: AgentReport) -> AgentMutationReport {
        match report {
            AgentReport::Uninstall(report) => report,
            other => panic!("expected uninstall report, got {other:?}"),
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
            ImageSource::fleet_cache("/mnt/argonas/agent-images").unwrap()
        );
        assert_eq!(
            parse_image_source("tarball=/tmp/agent.tar").unwrap(),
            ImageSource::tarball("/tmp/agent.tar").unwrap()
        );
    }

    #[test]
    fn rejects_relative_image_source_paths() {
        for (source, expected_hint) in [
            ("fleet-cache=./relative", "fleet-cache=/absolute/path"),
            ("tarball=./rel.tar", "tarball=/absolute/path"),
        ] {
            let err = parse_image_source(source).unwrap_err();
            assert!(matches!(
                err,
                NczError::Usage(message)
                    if message.contains("image source path must be absolute")
                        && message.contains(source.split_once('=').unwrap().1)
                        && message.contains(expected_hint)
            ));
        }
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
                    ImageSource::tarball("/tmp/hermes.tar").unwrap()
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
        assert!(steps.iter().any(|step| {
            step.starts_with("podman volume create") && step.contains("--label nclawzero=true")
        }));
        assert!(steps
            .iter()
            .any(|step| step.contains("/etc/containers/systemd/")
                && step.contains("Label=nclawzero=true")));
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
            step.starts_with("docker volume create") && step.contains("--label nclawzero=true")
        }));
        assert!(steps.iter().any(|step| {
            step.starts_with("docker run:")
                && step.contains("--label nclawzero=true")
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
        assert!(steps.last().unwrap().contains("agents/install-set.toml"));
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
        assert!(!paths.agent_install_set().exists());
    }

    #[test]
    fn install_returns_precondition_when_not_dry_run() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();

        let err = install(
            &ctx(&runner),
            &paths,
            Some("rpi5-16gb"),
            "triple",
            "openshell",
            "registry",
            false,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message == INSTALL_NON_DRY_RUN_PRECONDITION
        ));
        assert!(!paths.lock_path.exists());
        assert!(!paths.lock_path.parent().unwrap().exists());
        assert!(!paths.agent_install_set().exists());
    }

    #[test]
    fn install_persists_metadata_after_planning_when_not_dry_run() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());

        let report = apply_install(
            &paths,
            AgentSpec {
                profile: ProfileTarget::MacosArm64Docker,
                variant: Variant::Single {
                    agent: Agent::Hermes,
                },
                sandbox: SandboxKind::Naked,
                image_source: ImageSource::Registry,
            },
        )
        .unwrap();

        assert!(matches!(
            report,
            AgentInstallReport {
                applied: true,
                dry_run: false,
                ..
            }
        ));
        assert!(paths.lock_path.exists());
        assert!(paths.agent_install_set().exists());
        let metadata = agent_install_metadata::read(&paths, Agent::Hermes).unwrap();
        assert_eq!(
            metadata,
            AgentInstallMetadata {
                schema_version: AGENT_INSTALL_METADATA_SCHEMA_VERSION,
                agent: Agent::Hermes,
                profile: ProfileTarget::MacosArm64Docker,
                runtime: ContainerRuntime::Docker,
                sandbox: SandboxKind::Naked,
                installed_at: metadata.installed_at.clone(),
                image_source: ImageSource::Registry,
                image_reference: PENDING_IMAGE_REFERENCE.to_string(),
                image_digest: PENDING_IMAGE_DIGEST.to_string(),
            }
        );
        assert!(metadata.installed_at.ends_with('Z'));
    }

    #[test]
    fn reinstall_replaces_authoritative_install_set() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());

        apply_install(
            &paths,
            AgentSpec {
                profile: ProfileTarget::MacosArm64Docker,
                variant: Variant::Triple,
                sandbox: SandboxKind::Naked,
                image_source: ImageSource::Registry,
            },
        )
        .unwrap();
        assert_eq!(
            metadata_agents(&agent_install_metadata::read_all_installed(&paths).unwrap()),
            vec!["zeroclaw", "openclaw", "hermes"]
        );

        apply_install(
            &paths,
            AgentSpec {
                profile: ProfileTarget::MacosArm64Docker,
                variant: Variant::Single {
                    agent: Agent::Hermes,
                },
                sandbox: SandboxKind::Naked,
                image_source: ImageSource::Registry,
            },
        )
        .unwrap();

        let installed = agent_install_metadata::read_all_installed(&paths).unwrap();
        assert_eq!(metadata_agents(&installed), vec!["hermes"]);
        assert!(agent_install_metadata::read(&paths, Agent::Zeroclaw).is_err());
        let body = std::fs::read_to_string(paths.agent_install_set()).unwrap();
        assert!(!body.contains("zeroclaw"));
        assert!(!body.contains("openclaw"));
        assert!(body.contains("hermes"));
    }

    #[test]
    fn install_recovers_empty_directory_at_install_set_path() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        std::fs::create_dir_all(paths.agent_install_set()).unwrap();

        apply_install(
            &paths,
            AgentSpec {
                profile: ProfileTarget::MacosArm64Docker,
                variant: Variant::Single {
                    agent: Agent::Hermes,
                },
                sandbox: SandboxKind::Naked,
                image_source: ImageSource::Registry,
            },
        )
        .unwrap();

        assert!(paths.agent_install_set().is_file());
        let installed = agent_install_metadata::read_all_installed(&paths).unwrap();
        assert_eq!(metadata_agents(&installed), vec!["hermes"]);
    }

    #[test]
    fn install_rejects_non_empty_directory_at_install_set_path() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        std::fs::create_dir_all(paths.agent_install_set()).unwrap();
        std::fs::write(paths.agent_install_set().join("leftover"), "stale").unwrap();

        let err = apply_install(
            &paths,
            AgentSpec {
                profile: ProfileTarget::MacosArm64Docker,
                variant: Variant::Single {
                    agent: Agent::Hermes,
                },
                sandbox: SandboxKind::Naked,
                image_source: ImageSource::Registry,
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message)
                if message.contains("cannot replace non-empty install metadata directory")
                    && message.contains("install-set.toml")
                    && message.contains("remove the directory at")
                    && message.contains("manually then re-run install")
        ));
        assert!(paths.agent_install_set().is_dir());
        assert!(paths.agent_install_set().join("leftover").exists());
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
    fn uninstall_all_without_install_set_succeeds_with_compiled_agent_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        for agent in Agent::ALL {
            expect_unknown_runtime_cleanup_with_missing_podman_tools(&runner, agent);
        }

        let report = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::All,
            false,
            false,
            false,
        )
        .unwrap();
        let report = uninstall_report(report);

        assert!(report.applied);
        assert_eq!(report.agents, vec!["zeroclaw", "openclaw", "hermes"]);
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("metadata-load: agents/install-set.toml missing")));
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("podman container cleanup: zeroclaw not found")));
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("docker container cleanup: ncz-zeroclaw not found")));
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("metadata-remove: agents/install-set.toml already absent")));
        assert!(!paths.agent_install_set().exists());
        assert!(paths.lock_path.exists());
        runner.assert_done();
    }

    #[test]
    fn metadata_less_uninstall_refuses_unlabeled_fallback_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        expect_podman_fallback_volume_cleanup(
            &runner,
            Agent::Hermes,
            unlabeled_volume_inspect_json(),
            false,
        );
        expect_docker_not_found_cleanup(&runner, Agent::Hermes);

        let err = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            false,
            false,
            false,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message)
                if message.contains("ambiguous artifact hermes-data not labeled nclawzero=true; not deleting")
                    && message.contains("Re-run with --destructive-recovery to force delete")
                    && message.contains("metadata preserved for retry")
        ));
        assert!(paths.lock_path.exists());
        runner.assert_done();
    }

    #[test]
    fn metadata_less_uninstall_removes_labeled_fallback_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        expect_podman_fallback_volume_cleanup(
            &runner,
            Agent::Hermes,
            labeled_volume_inspect_json(),
            true,
        );
        expect_docker_not_found_cleanup(&runner, Agent::Hermes);

        let report = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            false,
            false,
            false,
        )
        .unwrap();
        let report = uninstall_report(report);

        assert!(report.applied);
        assert_eq!(report.agents, vec!["hermes"]);
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("podman volume cleanup: hermes-data removed")));
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("metadata-remove: agents/install-set.toml already absent")));
        runner.assert_done();
    }

    #[test]
    fn metadata_less_destructive_recovery_removes_labeled_and_unlabeled_fallback_volumes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        expect_podman_fallback_volume_cleanup(
            &runner,
            Agent::Hermes,
            unlabeled_volume_inspect_json(),
            true,
        );
        expect_docker_fallback_volume_cleanup(
            &runner,
            Agent::Hermes,
            labeled_volume_inspect_json(),
            true,
        );

        let report = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            false,
            false,
            true,
        )
        .unwrap();
        let report = uninstall_report(report);

        assert!(report.applied);
        assert_eq!(report.agents, vec!["hermes"]);
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("podman volume cleanup: hermes-data removed")));
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("docker volume cleanup: hermes-data removed")));
        runner.assert_done();
    }

    #[test]
    fn uninstall_all_with_installed_docker_hermes_skips_uninstalled_compiled_agents() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );
        let runner = FakeRunner::new();
        expect_docker_not_found_cleanup(&runner, Agent::Hermes);

        let report = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::All,
            false,
            false,
            false,
        )
        .unwrap();
        let report = uninstall_report(report);

        assert!(report.applied);
        assert_eq!(report.agents, vec!["hermes"]);
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step == "metadata-load: agents/install-set.toml"));
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("docker container cleanup: ncz-hermes not found")));
        assert!(!report
            .planned_steps
            .iter()
            .any(|step| step.contains("zeroclaw") || step.contains("openclaw")));
        assert!(!report
            .planned_steps
            .iter()
            .any(|step| step.contains("podman") || step.contains("systemctl")));
        assert!(!paths.agent_install_set().exists());
        runner.assert_done();
    }

    #[test]
    fn uninstall_with_unsupported_install_set_schema_preserves_metadata_and_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );
        let raw = std::fs::read_to_string(paths.agent_install_set())
            .unwrap()
            .replacen("schema_version = 1", "schema_version = 999", 1);
        std::fs::write(paths.agent_install_set(), &raw).unwrap();
        let runner = FakeRunner::new();

        let err = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::All,
            false,
            false,
            false,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message) if message == CORRUPT_METADATA_PRESERVED_MESSAGE
        ));
        assert_eq!(
            std::fs::read_to_string(paths.agent_install_set()).unwrap(),
            raw
        );
        assert!(paths.lock_path.exists());
        runner.assert_done();
    }

    #[test]
    fn uninstall_with_unknown_install_set_agent_preserves_metadata_and_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );
        let raw = std::fs::read_to_string(paths.agent_install_set())
            .unwrap()
            .replace("agent = \"hermes\"", "agent = \"newclaw\"");
        std::fs::write(paths.agent_install_set(), &raw).unwrap();
        let runner = FakeRunner::new();

        let err = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::All,
            false,
            false,
            false,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message) if message == CORRUPT_METADATA_PRESERVED_MESSAGE
        ));
        assert_eq!(
            std::fs::read_to_string(paths.agent_install_set()).unwrap(),
            raw
        );
        assert!(paths.lock_path.exists());
        runner.assert_done();
    }

    #[test]
    fn uninstall_force_recover_from_corrupt_all_backs_up_and_removes_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );
        let raw = std::fs::read_to_string(paths.agent_install_set())
            .unwrap()
            .replacen("schema_version = 1", "schema_version = 999", 1);
        std::fs::write(paths.agent_install_set(), &raw).unwrap();
        let runner = FakeRunner::new();
        for agent in Agent::ALL {
            expect_unknown_runtime_cleanup(&runner, agent);
        }

        let report = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::All,
            false,
            true,
            false,
        )
        .unwrap();
        let report = uninstall_report(report);

        assert!(report.applied);
        assert_eq!(report.agents, vec!["zeroclaw", "openclaw", "hermes"]);
        assert!(report.planned_steps.iter().any(|step| {
            step.contains("metadata-force-recover: backed up corrupt agents/install-set.toml")
        }));
        assert!(report.planned_steps.iter().any(|step| {
            step.contains(
                "metadata-remove: agents/install-set.toml deleted after corrupt metadata backup",
            )
        }));
        assert!(!paths.agent_install_set().exists());
        let backups = std::fs::read_dir(paths.agent_config_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some(name) if name.starts_with("install-set.toml.corrupt-backup-")
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), raw);
        assert!(paths.lock_path.exists());
        runner.assert_done();
    }

    #[test]
    fn uninstall_force_recover_from_corrupt_one_rejects_to_preserve_install_set() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![
                test_metadata(Agent::Zeroclaw, ContainerRuntime::Docker),
                test_metadata(Agent::Hermes, ContainerRuntime::Docker),
            ],
        );
        let raw = std::fs::read_to_string(paths.agent_install_set())
            .unwrap()
            .replacen("schema_version = 1", "schema_version = 999", 1);
        std::fs::write(paths.agent_install_set(), &raw).unwrap();
        let runner = FakeRunner::new();

        let err = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            false,
            true,
            false,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Usage(message)
                if message == FORCE_RECOVER_FROM_CORRUPT_REQUIRES_ALL_MESSAGE
        ));
        assert_eq!(
            std::fs::read_to_string(paths.agent_install_set()).unwrap(),
            raw
        );
        assert!(std::fs::read_dir(paths.agent_config_dir())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("install-set.toml.corrupt-backup-")));
        assert!(paths.lock_path.exists());
        runner.assert_done();
    }

    #[test]
    fn uninstall_single_missing_from_metadata_does_not_use_compiled_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );
        let runner = FakeRunner::new();

        let report = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Zeroclaw),
            false,
            false,
            false,
        )
        .unwrap();
        let report = uninstall_report(report);

        assert!(report.applied);
        assert!(report.agents.is_empty());
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step == "metadata-load: agents/install-set.toml"));
        assert!(!report
            .planned_steps
            .iter()
            .any(|step| step.contains("zeroclaw")));
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("metadata-remove: agents/install-set.toml unchanged")));
        let installed = agent_install_metadata::read_all_installed(&paths).unwrap();
        assert_eq!(metadata_agents(&installed), vec!["hermes"]);
        assert!(paths.lock_path.exists());
        runner.assert_done();
    }

    #[test]
    fn uninstall_single_uses_metadata_runtime_and_drops_metadata_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![
                test_metadata(Agent::Zeroclaw, ContainerRuntime::Podman),
                test_metadata(Agent::Hermes, ContainerRuntime::Docker),
            ],
        );
        let runner = FakeRunner::new();
        expect_docker_not_found_cleanup(&runner, Agent::Hermes);

        let report = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            false,
            false,
            false,
        )
        .unwrap();
        let report = uninstall_report(report);

        assert!(report.applied);
        assert_eq!(report.agents, vec!["hermes"]);
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("docker container cleanup: ncz-hermes not found")));
        assert!(!report
            .planned_steps
            .iter()
            .any(|step| step.contains("podman container cleanup: hermes")));
        assert!(report.planned_steps.iter().any(|step| {
            step.contains("metadata-remove: agents/install-set.toml entry for hermes")
        }));
        let installed = agent_install_metadata::read_all_installed(&paths).unwrap();
        assert_eq!(metadata_agents(&installed), vec!["zeroclaw"]);
        assert!(agent_install_metadata::read(&paths, Agent::Hermes).is_err());
        runner.assert_done();
    }

    #[test]
    fn uninstall_single_full_rejects_when_other_agents_retained() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![
                test_metadata(Agent::Zeroclaw, ContainerRuntime::Docker),
                test_metadata(Agent::Openclaw, ContainerRuntime::Docker),
                test_metadata(Agent::Hermes, ContainerRuntime::Docker),
            ],
        );
        std::fs::create_dir_all(paths.providers_dir()).unwrap();
        std::fs::write(paths.agent_env(), "OPENAI_API_KEY=test\n").unwrap();
        let runner = FakeRunner::new();

        let err = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            true,
            false,
            false,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Usage(message)
                if message.contains("--full is only allowed when uninstalling all agents")
                    && message.contains("zeroclaw, openclaw")
                    && message.contains("ncz agent uninstall --all --full")
                    && message.contains("drop --full")
        ));
        let installed = agent_install_metadata::read_all_installed(&paths).unwrap();
        assert_eq!(
            metadata_agents(&installed),
            vec!["zeroclaw", "openclaw", "hermes"]
        );
        assert!(paths.agent_env().exists());
        assert!(paths.providers_dir().exists());
        runner.assert_done();
    }

    #[test]
    fn uninstall_preserves_metadata_when_cleanup_probe_reports_daemon_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );
        let runner = FakeRunner::new();
        let container = docker_container_name(Agent::Hermes);
        let volume = volume_name(Agent::Hermes);
        runner.expect(
            "docker",
            &["container", "inspect", &container],
            out(125, "", "Cannot connect to Docker daemon\n"),
        );
        runner.expect(
            "docker",
            &["volume", "inspect", &volume],
            out(1, "", "not found\n"),
        );

        let err = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            false,
            false,
            false,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message)
                if message.contains("docker container cleanup: ncz-hermes")
                    && message.contains("Cannot connect to Docker daemon")
                    && message.contains("metadata preserved for retry")
        ));
        let installed = agent_install_metadata::read_all_installed(&paths).unwrap();
        assert_eq!(metadata_agents(&installed), vec!["hermes"]);
        runner.assert_done();
    }

    #[test]
    fn uninstall_preserves_metadata_when_cleanup_removal_reports_permission_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );
        let runner = FakeRunner::new();
        let container = docker_container_name(Agent::Hermes);
        let volume = volume_name(Agent::Hermes);
        runner.expect(
            "docker",
            &["container", "inspect", &container],
            out(0, "", ""),
        );
        runner.expect(
            "docker",
            &["rm", "-f", &container],
            out(1, "", "permission denied\n"),
        );
        runner.expect(
            "docker",
            &["volume", "inspect", &volume],
            out(1, "", "not found\n"),
        );

        let err = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            false,
            false,
            false,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message)
                if message.contains("docker container cleanup: ncz-hermes")
                    && message.contains("permission denied")
                    && message.contains("metadata preserved for retry")
        ));
        let installed = agent_install_metadata::read_all_installed(&paths).unwrap();
        assert_eq!(metadata_agents(&installed), vec!["hermes"]);
        runner.assert_done();
    }

    #[test]
    fn uninstall_all_not_found_cleanup_removes_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );
        let runner = FakeRunner::new();
        expect_docker_not_found_cleanup(&runner, Agent::Hermes);

        let report = uninstall(
            &ctx(&runner),
            &paths,
            AgentSelector::One(Agent::Hermes),
            false,
            false,
            false,
        )
        .unwrap();
        let report = uninstall_report(report);

        assert!(report.applied);
        assert_eq!(report.agents, vec!["hermes"]);
        assert!(report
            .planned_steps
            .iter()
            .any(|step| step.contains("docker container cleanup: ncz-hermes not found")));
        assert!(!paths.agent_install_set().exists());
        runner.assert_done();
    }

    #[test]
    fn install_non_dry_run_acquires_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());

        let report = apply_install(
            &paths,
            AgentSpec {
                profile: ProfileTarget::Rpi5_16gb,
                variant: Variant::Triple,
                sandbox: SandboxKind::OpenShell,
                image_source: ImageSource::Registry,
            },
        )
        .unwrap();

        assert!(matches!(
            report,
            AgentInstallReport {
                applied: true,
                dry_run: false,
                ..
            }
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
        write_test_install_set(
            &paths,
            vec![
                test_metadata(Agent::Zeroclaw, ContainerRuntime::Docker),
                test_metadata(Agent::Hermes, ContainerRuntime::Podman),
            ],
        );

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
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Hermes, ContainerRuntime::Docker)],
        );

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
                if message.contains("metadata-load: agents/install-set.toml")
                    && message.contains("docker stop ncz-hermes")
                    && !message.contains("systemctl stop")
        ));
    }

    #[test]
    fn all_selector_lifecycle_branches_per_agent_metadata_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        write_test_install_set(
            &paths,
            vec![
                test_metadata(Agent::Zeroclaw, ContainerRuntime::Docker),
                test_metadata(Agent::Hermes, ContainerRuntime::Podman),
            ],
        );

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
    fn reload_uses_persisted_registry_and_fleet_cache_sources() {
        for (image_source, expected) in [
            (
                ImageSource::Registry,
                "podman registry image refresh + systemctl restart hermes.service",
            ),
            (
                ImageSource::fleet_cache("/mnt/argonas/agent-images").unwrap(),
                "podman fleet-cache image refresh from /mnt/argonas/agent-images + systemctl restart hermes.service",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let paths = test_paths(tmp.path());
            let runner = FakeRunner::new();
            write_test_install_set(
                &paths,
                vec![test_metadata_with_source(
                    Agent::Hermes,
                    ContainerRuntime::Podman,
                    image_source,
                )],
            );

            let err = run_with_paths(
                &ctx(&runner),
                &paths,
                AgentAction::Reload {
                    agent: Some(AgentName::from(Agent::Hermes)),
                },
            )
            .unwrap_err();

            assert!(matches!(
                err,
                NczError::Precondition(message)
                    if message.contains("metadata-load: agents/install-set.toml")
                        && message.contains(expected)
            ));
        }
    }

    #[test]
    fn reload_rejects_tarball_source_without_new_from_arg() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        write_test_install_set(
            &paths,
            vec![test_metadata_with_source(
                Agent::Hermes,
                ContainerRuntime::Docker,
                ImageSource::tarball("/tmp/hermes.tar").unwrap(),
            )],
        );

        let err = run_with_paths(
            &ctx(&runner),
            &paths,
            AgentAction::Reload {
                agent: Some(AgentName::from(Agent::Hermes)),
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("cannot reload hermes from tarball /tmp/hermes.tar")
                    && message.contains("tarball is one-shot, re-run install with new --from")
        ));
    }

    #[test]
    fn install_persists_image_source_in_metadata() {
        for (from, expected) in [
            ("registry", ImageSource::Registry),
            (
                "fleet-cache=/mnt/argonas/agent-images",
                ImageSource::fleet_cache("/mnt/argonas/agent-images").unwrap(),
            ),
            (
                "tarball=/tmp/hermes.tar",
                ImageSource::tarball("/tmp/hermes.tar").unwrap(),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let paths = test_paths(tmp.path());

            apply_install(
                &paths,
                AgentSpec {
                    profile: ProfileTarget::MacosArm64Docker,
                    variant: Variant::Single {
                        agent: Agent::Hermes,
                    },
                    sandbox: SandboxKind::Naked,
                    image_source: parse_image_source(from).unwrap(),
                },
            )
            .unwrap();

            let metadata = agent_install_metadata::read(&paths, Agent::Hermes).unwrap();
            assert_eq!(
                metadata.schema_version,
                AGENT_INSTALL_METADATA_SCHEMA_VERSION
            );
            assert_eq!(metadata.image_source, expected);
            assert_eq!(metadata.image_reference, PENDING_IMAGE_REFERENCE);
            assert_eq!(metadata.image_digest, PENDING_IMAGE_DIGEST);
        }
    }

    #[test]
    fn status_loads_metadata_under_lock_and_uses_docker_status_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let runner = FakeRunner::new();
        write_test_install_set(
            &paths,
            vec![test_metadata(Agent::Openclaw, ContainerRuntime::Docker)],
        );

        let err = run_with_paths(&ctx(&runner), &paths, AgentAction::Status).unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("metadata-load: agents/install-set.toml")
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
    fn lint_verdict_table_covers_pass_skip_warn_fail_combinations() {
        let cases: &[(&str, &[InvariantStatus], Verdict, u32)] = &[
            ("empty", &[], Verdict::Incomplete, 0),
            ("all-pass", &[InvariantStatus::Pass], Verdict::Approve, 1),
            (
                "pass+skip",
                &[InvariantStatus::Pass, InvariantStatus::Skip],
                Verdict::Approve,
                1,
            ),
            ("all-skip", &[InvariantStatus::Skip], Verdict::Incomplete, 0),
            (
                "warn-only",
                &[InvariantStatus::Warn],
                Verdict::Incomplete,
                0,
            ),
            (
                "skip+warn",
                &[InvariantStatus::Skip, InvariantStatus::Warn],
                Verdict::Incomplete,
                0,
            ),
            ("fail-only", &[InvariantStatus::Fail], Verdict::Reject, 0),
            (
                "skip+fail",
                &[InvariantStatus::Skip, InvariantStatus::Fail],
                Verdict::Reject,
                0,
            ),
        ];

        for (name, statuses, expected_verdict, expected_passed) in cases {
            let report = AgentLintReport::from_results(
                (*name).to_string(),
                statuses.iter().copied().map(invariant).collect(),
            );

            assert_eq!(report.overall(), *expected_verdict, "{name}");
            assert_eq!(report.invariants_checked, statuses.len() as u32, "{name}");
            assert_eq!(report.invariants_passed, *expected_passed, "{name}");
        }
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
