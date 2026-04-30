//! Per-agent install metadata persisted by `ncz agent install`.

use std::fs;

use serde::{Deserialize, Serialize};

use crate::agent_spec::{Agent, ContainerRuntime, ProfileTarget, SandboxKind};
use crate::error::NczError;
use crate::state::{self, Paths};

pub const PENDING_IMAGE_DIGEST: &str = "pending";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstallMetadata {
    pub agent: Agent,
    pub profile: ProfileTarget,
    pub runtime: ContainerRuntime,
    pub sandbox: SandboxKind,
    pub installed_at: String,
    pub image_digest: String,
}

pub fn write(paths: &Paths, metadata: &AgentInstallMetadata) -> Result<(), NczError> {
    let path = paths.agent_install_metadata(metadata.agent);
    let body = toml::to_string_pretty(metadata).map_err(|err| {
        NczError::Precondition(format!(
            "could not serialize install metadata for {}: {err}",
            metadata.agent
        ))
    })?;
    state::atomic_write(&path, body.as_bytes(), 0o644)
}

pub fn read(paths: &Paths, agent: Agent) -> Result<AgentInstallMetadata, NczError> {
    let path = paths.agent_install_metadata(agent);
    let body = fs::read_to_string(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            missing_metadata_error(agent, &path)
        } else {
            NczError::Io(err)
        }
    })?;
    let metadata: AgentInstallMetadata = toml::from_str(&body).map_err(|err| {
        NczError::Inconsistent(format!(
            "invalid install metadata for {} at {}: {err}; reinstall with `ncz agent install`",
            agent,
            path.display()
        ))
    })?;
    if metadata.agent != agent {
        return Err(NczError::Inconsistent(format!(
            "install metadata agent mismatch at {}: expected {}, found {}; reinstall with `ncz agent install`",
            path.display(),
            agent,
            metadata.agent
        )));
    }
    Ok(metadata)
}

pub fn read_if_exists(
    paths: &Paths,
    agent: Agent,
) -> Result<Option<AgentInstallMetadata>, NczError> {
    let path = paths.agent_install_metadata(agent);
    if !path.exists() {
        return Ok(None);
    }
    read(paths, agent).map(Some)
}

pub fn read_all_installed(paths: &Paths) -> Result<Vec<AgentInstallMetadata>, NczError> {
    let mut metadata = Vec::new();
    for agent in Agent::ALL {
        if let Some(entry) = read_if_exists(paths, agent)? {
            metadata.push(entry);
        }
    }
    if metadata.is_empty() {
        return Err(NczError::Precondition(format!(
            "no agent install metadata found under {}; reinstall with `ncz agent install`",
            paths.agent_config_dir().display()
        )));
    }
    Ok(metadata)
}

fn missing_metadata_error(agent: Agent, path: &std::path::Path) -> NczError {
    NczError::Precondition(format!(
        "missing install metadata for {agent} at {}; reinstall with `ncz agent install`",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths(root: &std::path::Path) -> Paths {
        Paths {
            etc_dir: root.join("etc/nclawzero"),
            quadlet_dir: root.join("etc/containers/systemd"),
            lock_path: root.join("run/nclawzero.lock"),
        }
    }

    fn metadata(agent: Agent) -> AgentInstallMetadata {
        AgentInstallMetadata {
            agent,
            profile: ProfileTarget::MacosArm64Docker,
            runtime: ContainerRuntime::Docker,
            sandbox: SandboxKind::OpenShell,
            installed_at: "2026-04-30T00:00:00Z".to_string(),
            image_digest: PENDING_IMAGE_DIGEST.to_string(),
        }
    }

    #[test]
    fn install_metadata_roundtrips_as_toml_under_agent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let expected = metadata(Agent::Hermes);

        write(&paths, &expected).unwrap();

        let path = paths.agent_install_metadata(Agent::Hermes);
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("agent = \"hermes\""));
        assert!(body.contains("runtime = \"docker\""));
        assert_eq!(read(&paths, Agent::Hermes).unwrap(), expected);
    }

    #[test]
    fn missing_metadata_mentions_reinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());

        let err = read(&paths, Agent::Zeroclaw).unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("missing install metadata")
                    && message.contains("reinstall with `ncz agent install`")
        ));
    }
}
