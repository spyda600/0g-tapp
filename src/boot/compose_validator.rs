use crate::error::{DockerError, TappResult};
use serde_yaml::Value;
use tracing::warn;

/// Default resource limits applied to containers when not explicitly set.
const DEFAULT_MEM_LIMIT: &str = "512m";
const DEFAULT_CPUS: f64 = 1.0;
const DEFAULT_PIDS_LIMIT: i64 = 256;

/// Configurable resource limits for compose sandboxing.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub mem_limit: String,
    pub cpus: f64,
    pub pids_limit: i64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            mem_limit: DEFAULT_MEM_LIMIT.to_string(),
            cpus: DEFAULT_CPUS,
            pids_limit: DEFAULT_PIDS_LIMIT,
        }
    }
}

/// Dangerous capabilities that must never be granted to user containers.
const FORBIDDEN_CAPABILITIES: &[&str] = &["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "ALL"];

/// Host paths that must never be bind-mounted into containers.
const FORBIDDEN_MOUNT_PREFIXES: &[&str] =
    &["/var/run/docker.sock", "/etc/", "/root/", "/proc/", "/sys/"];

/// Validate and sanitize a Docker Compose YAML string.
///
/// Returns the sanitized YAML with resource limits injected where missing.
/// Returns an error if the compose content contains any forbidden configuration.
pub fn validate_and_sanitize(compose_content: &str, limits: &ResourceLimits) -> TappResult<String> {
    let mut doc: Value =
        serde_yaml::from_str(compose_content).map_err(|e| DockerError::InvalidComposeContent {
            reason: format!("Failed to parse compose YAML: {}", e),
        })?;

    let services = extract_services_mut(&mut doc)?;

    let service_names: Vec<String> = match services {
        Value::Mapping(ref m) => m
            .keys()
            .filter_map(|k| k.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    };

    for name in &service_names {
        let service = services
            .get_mut(Value::String(name.clone()))
            .ok_or_else(|| DockerError::InvalidComposeContent {
                reason: format!("Service '{}' disappeared during validation", name),
            })?;

        validate_service(name, service)?;
        inject_resource_limits(name, service, limits);
    }

    let output = serde_yaml::to_string(&doc).map_err(|e| DockerError::InvalidComposeContent {
        reason: format!("Failed to serialize sanitized compose YAML: {}", e),
    })?;

    Ok(output)
}

/// Extract a mutable reference to the `services` mapping from the compose document.
fn extract_services_mut(doc: &mut Value) -> TappResult<&mut Value> {
    // Docker Compose v2+ uses a top-level `services` key.
    // Some legacy files omit the version key but still use `services`.
    match doc.get_mut("services") {
        Some(services) => Ok(services),
        None => Err(DockerError::InvalidComposeContent {
            reason: "Compose file must contain a top-level 'services' key".to_string(),
        }
        .into()),
    }
}

/// Validate a single service definition for forbidden configuration.
fn validate_service(service_name: &str, service: &Value) -> TappResult<()> {
    check_privileged(service_name, service)?;
    check_network_mode(service_name, service)?;
    check_pid_mode(service_name, service)?;
    check_ipc_mode(service_name, service)?;
    check_cap_add(service_name, service)?;
    check_security_opt(service_name, service)?;
    check_volumes(service_name, service)?;
    check_forbidden_keys(service_name, service)?;
    Ok(())
}

/// Reject dangerous compose keys that could enable container escape.
fn check_forbidden_keys(name: &str, svc: &Value) -> TappResult<()> {
    // devices: can map host devices (/dev/mem, /dev/sda) into container
    if svc.get("devices").is_some() {
        return rejection(name, "'devices' is not allowed — host device access is forbidden");
    }
    // sysctls: can modify host kernel parameters
    if svc.get("sysctls").is_some() {
        return rejection(name, "'sysctls' is not allowed — kernel parameter modification is forbidden");
    }
    // userns_mode: can disable user namespace isolation
    if svc.get("userns_mode").is_some() {
        return rejection(name, "'userns_mode' is not allowed");
    }
    // cgroup_parent: can escape cgroup isolation
    if svc.get("cgroup_parent").is_some() {
        return rejection(name, "'cgroup_parent' is not allowed");
    }
    Ok(())
}

fn rejection(service_name: &str, reason: &str) -> TappResult<()> {
    Err(DockerError::InvalidComposeContent {
        reason: format!("Service '{}': {}", service_name, reason),
    }
    .into())
}

// --- Individual security checks ---

fn check_privileged(name: &str, svc: &Value) -> TappResult<()> {
    if let Some(val) = svc.get("privileged") {
        if val.as_bool() == Some(true) {
            return rejection(name, "privileged mode is not allowed");
        }
    }
    Ok(())
}

fn check_network_mode(name: &str, svc: &Value) -> TappResult<()> {
    if let Some(val) = svc.get("network_mode") {
        if val.as_str() == Some("host") {
            return rejection(name, "network_mode 'host' is not allowed");
        }
    }
    Ok(())
}

fn check_pid_mode(name: &str, svc: &Value) -> TappResult<()> {
    if let Some(val) = svc.get("pid") {
        if val.as_str() == Some("host") {
            return rejection(name, "pid 'host' is not allowed");
        }
    }
    Ok(())
}

fn check_ipc_mode(name: &str, svc: &Value) -> TappResult<()> {
    if let Some(val) = svc.get("ipc") {
        if val.as_str() == Some("host") {
            return rejection(name, "ipc 'host' is not allowed");
        }
    }
    Ok(())
}

fn check_cap_add(name: &str, svc: &Value) -> TappResult<()> {
    if let Some(caps) = svc.get("cap_add") {
        if let Some(seq) = caps.as_sequence() {
            for cap in seq {
                if let Some(cap_str) = cap.as_str() {
                    let upper = cap_str.to_uppercase();
                    if FORBIDDEN_CAPABILITIES.contains(&upper.as_str()) {
                        return rejection(
                            name,
                            &format!("capability '{}' is not allowed in cap_add", cap_str),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn check_security_opt(name: &str, svc: &Value) -> TappResult<()> {
    if let Some(opts) = svc.get("security_opt") {
        if let Some(seq) = opts.as_sequence() {
            for opt in seq {
                if let Some(opt_str) = opt.as_str() {
                    let lower = opt_str.to_lowercase();
                    if lower.contains("apparmor:unconfined") || lower.contains("seccomp:unconfined")
                    {
                        return rejection(
                            name,
                            &format!("security_opt '{}' is not allowed", opt_str),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn check_volumes(name: &str, svc: &Value) -> TappResult<()> {
    if let Some(vols) = svc.get("volumes") {
        if let Some(seq) = vols.as_sequence() {
            for vol in seq {
                let host_path = extract_host_path(vol);
                if let Some(path) = host_path {
                    // Reject path traversal
                    if path.contains("..") {
                        return rejection(
                            name,
                            &format!("volume mount '{}' contains path traversal (..)", path),
                        );
                    }
                    // Reject forbidden host paths
                    for prefix in FORBIDDEN_MOUNT_PREFIXES {
                        if path == *prefix || path.starts_with(prefix) {
                            return rejection(
                                name,
                                &format!("volume mount of host path '{}' is not allowed", path),
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Extract the host path from a volume entry.
///
/// Volumes can be specified as:
/// - Short syntax string: `"/host/path:/container/path:ro"`
/// - Long syntax mapping with `source` key
fn extract_host_path(vol: &Value) -> Option<String> {
    match vol {
        Value::String(s) => {
            // Short syntax: "host:container" or "host:container:mode"
            let parts: Vec<&str> = s.splitn(3, ':').collect();
            if parts.len() >= 2 {
                Some(parts[0].to_string())
            } else {
                // Named volume or anonymous — no host path to check
                None
            }
        }
        Value::Mapping(m) => {
            // Long syntax: { type: bind, source: /host/path, target: /container/path }
            if let Some(source) = m.get(&Value::String("source".to_string())) {
                source.as_str().map(String::from)
            } else {
                None
            }
        }
        _ => None,
    }
}

// --- Resource limit injection ---

/// Inject default resource limits into a service if not already set.
fn inject_resource_limits(service_name: &str, service: &mut Value, limits: &ResourceLimits) {
    let mapping = match service.as_mapping_mut() {
        Some(m) => m,
        None => return,
    };

    // mem_limit
    if !mapping.contains_key(&Value::String("mem_limit".to_string()))
        && !has_deploy_memory_limit(mapping)
    {
        warn!(
            service = %service_name,
            limit = %limits.mem_limit,
            "Injecting default mem_limit"
        );
        mapping.insert(
            Value::String("mem_limit".to_string()),
            Value::String(limits.mem_limit.clone()),
        );
    }

    // cpus
    if !mapping.contains_key(&Value::String("cpus".to_string())) && !has_deploy_cpu_limit(mapping) {
        warn!(
            service = %service_name,
            limit = %limits.cpus,
            "Injecting default cpus limit"
        );
        mapping.insert(
            Value::String("cpus".to_string()),
            Value::Number(serde_yaml::Number::from(limits.cpus)),
        );
    }

    // pids_limit
    if !mapping.contains_key(&Value::String("pids_limit".to_string())) {
        warn!(
            service = %service_name,
            limit = %limits.pids_limit,
            "Injecting default pids_limit"
        );
        mapping.insert(
            Value::String("pids_limit".to_string()),
            Value::Number(serde_yaml::Number::from(limits.pids_limit)),
        );
    }
}

/// Check if the service already has a memory limit under deploy.resources.limits.
fn has_deploy_memory_limit(mapping: &serde_yaml::Mapping) -> bool {
    mapping
        .get(&Value::String("deploy".to_string()))
        .and_then(|d| d.get("resources"))
        .and_then(|r| r.get("limits"))
        .and_then(|l| l.get("memory"))
        .is_some()
}

/// Check if the service already has a CPU limit under deploy.resources.limits.
fn has_deploy_cpu_limit(mapping: &serde_yaml::Mapping) -> bool {
    mapping
        .get(&Value::String("deploy".to_string()))
        .and_then(|d| d.get("resources"))
        .and_then(|r| r.get("limits"))
        .and_then(|l| l.get("cpus"))
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_limits() -> ResourceLimits {
        ResourceLimits::default()
    }

    fn assert_rejected(yaml: &str, expected_fragment: &str) {
        let result = validate_and_sanitize(yaml, &default_limits());
        assert!(result.is_err(), "Expected rejection but got Ok");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains(expected_fragment),
            "Error '{}' should contain '{}'",
            err_msg,
            expected_fragment,
        );
    }

    fn assert_accepted(yaml: &str) -> String {
        validate_and_sanitize(yaml, &default_limits())
            .expect("Expected compose to be accepted but was rejected")
    }

    // --- Rejection tests ---

    #[test]
    fn reject_privileged_true() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    privileged: true
"#,
            "privileged mode is not allowed",
        );
    }

    #[test]
    fn reject_network_mode_host() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    network_mode: host
"#,
            "network_mode 'host' is not allowed",
        );
    }

    #[test]
    fn reject_pid_host() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    pid: host
"#,
            "pid 'host' is not allowed",
        );
    }

    #[test]
    fn reject_ipc_host() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    ipc: host
"#,
            "ipc 'host' is not allowed",
        );
    }

    #[test]
    fn reject_cap_add_sys_admin() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    cap_add:
      - SYS_ADMIN
"#,
            "capability 'SYS_ADMIN' is not allowed",
        );
    }

    #[test]
    fn reject_cap_add_sys_ptrace() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    cap_add:
      - SYS_PTRACE
"#,
            "capability 'SYS_PTRACE' is not allowed",
        );
    }

    #[test]
    fn reject_cap_add_net_admin() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    cap_add:
      - NET_ADMIN
"#,
            "capability 'NET_ADMIN' is not allowed",
        );
    }

    #[test]
    fn reject_cap_add_all() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    cap_add:
      - ALL
"#,
            "capability 'ALL' is not allowed",
        );
    }

    #[test]
    fn reject_cap_add_case_insensitive() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    cap_add:
      - sys_admin
"#,
            "capability 'sys_admin' is not allowed",
        );
    }

    #[test]
    fn reject_security_opt_apparmor_unconfined() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    security_opt:
      - apparmor:unconfined
"#,
            "security_opt 'apparmor:unconfined' is not allowed",
        );
    }

    #[test]
    fn reject_security_opt_seccomp_unconfined() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    security_opt:
      - seccomp:unconfined
"#,
            "security_opt 'seccomp:unconfined' is not allowed",
        );
    }

    #[test]
    fn reject_volume_docker_socket() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"#,
            "volume mount of host path '/var/run/docker.sock' is not allowed",
        );
    }

    #[test]
    fn reject_volume_etc() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    volumes:
      - /etc/passwd:/etc/passwd:ro
"#,
            "volume mount of host path '/etc/passwd' is not allowed",
        );
    }

    #[test]
    fn reject_volume_root() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    volumes:
      - /root/.ssh:/root/.ssh
"#,
            "volume mount of host path '/root/.ssh' is not allowed",
        );
    }

    #[test]
    fn reject_volume_proc() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    volumes:
      - /proc/1/status:/proc_status
"#,
            "volume mount of host path '/proc/1/status' is not allowed",
        );
    }

    #[test]
    fn reject_volume_sys() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    volumes:
      - /sys/class:/sys_class
"#,
            "volume mount of host path '/sys/class' is not allowed",
        );
    }

    #[test]
    fn reject_volume_path_traversal() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    volumes:
      - ./data/../../etc/passwd:/etc/passwd
"#,
            "contains path traversal",
        );
    }

    #[test]
    fn reject_volume_long_syntax_docker_socket() {
        assert_rejected(
            r#"
services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
"#,
            "volume mount of host path '/var/run/docker.sock' is not allowed",
        );
    }

    // --- Acceptance / resource injection tests ---

    #[test]
    fn accept_safe_compose_and_inject_limits() {
        let output = assert_accepted(
            r#"
services:
  web:
    image: nginx
    ports:
      - "8080:80"
"#,
        );

        let doc: Value = serde_yaml::from_str(&output).unwrap();
        let svc = doc.get("services").unwrap().get("web").unwrap();

        assert_eq!(svc.get("mem_limit").unwrap().as_str().unwrap(), "512m");
        assert_eq!(svc.get("cpus").unwrap().as_f64().unwrap(), 1.0);
        assert_eq!(svc.get("pids_limit").unwrap().as_i64().unwrap(), 256);
    }

    #[test]
    fn preserve_existing_mem_limit() {
        let output = assert_accepted(
            r#"
services:
  web:
    image: nginx
    mem_limit: 1g
"#,
        );

        let doc: Value = serde_yaml::from_str(&output).unwrap();
        let svc = doc.get("services").unwrap().get("web").unwrap();
        assert_eq!(svc.get("mem_limit").unwrap().as_str().unwrap(), "1g");
    }

    #[test]
    fn preserve_deploy_resource_limits() {
        let output = assert_accepted(
            r#"
services:
  web:
    image: nginx
    deploy:
      resources:
        limits:
          memory: 2g
          cpus: "2.0"
"#,
        );

        let doc: Value = serde_yaml::from_str(&output).unwrap();
        let svc = doc.get("services").unwrap().get("web").unwrap();
        // Should NOT inject mem_limit/cpus because deploy.resources.limits already set
        assert!(svc.get("mem_limit").is_none());
        assert!(svc.get("cpus").is_none());
        // pids_limit should still be injected
        assert_eq!(svc.get("pids_limit").unwrap().as_i64().unwrap(), 256);
    }

    #[test]
    fn custom_resource_limits() {
        let limits = ResourceLimits {
            mem_limit: "1g".to_string(),
            cpus: 2.0,
            pids_limit: 512,
        };

        let output = validate_and_sanitize(
            r#"
services:
  web:
    image: nginx
"#,
            &limits,
        )
        .unwrap();

        let doc: Value = serde_yaml::from_str(&output).unwrap();
        let svc = doc.get("services").unwrap().get("web").unwrap();

        assert_eq!(svc.get("mem_limit").unwrap().as_str().unwrap(), "1g");
        assert_eq!(svc.get("cpus").unwrap().as_f64().unwrap(), 2.0);
        assert_eq!(svc.get("pids_limit").unwrap().as_i64().unwrap(), 512);
    }

    #[test]
    fn accept_privileged_false() {
        assert_accepted(
            r#"
services:
  web:
    image: nginx
    privileged: false
"#,
        );
    }

    #[test]
    fn accept_safe_capabilities() {
        assert_accepted(
            r#"
services:
  web:
    image: nginx
    cap_add:
      - NET_BIND_SERVICE
      - CHOWN
"#,
        );
    }

    #[test]
    fn accept_named_volumes() {
        assert_accepted(
            r#"
services:
  web:
    image: nginx
    volumes:
      - mydata:/data
"#,
        );
    }

    #[test]
    fn accept_safe_bind_mount() {
        assert_accepted(
            r#"
services:
  web:
    image: nginx
    volumes:
      - ./app_data:/data
"#,
        );
    }

    #[test]
    fn reject_missing_services_key() {
        let result = validate_and_sanitize("version: '3'\n", &default_limits());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("services"));
    }

    #[test]
    fn reject_invalid_yaml() {
        let result = validate_and_sanitize("{{{{not yaml", &default_limits());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parse"));
    }

    #[test]
    fn multiple_services_all_validated() {
        // First service is fine, second has privileged — should reject
        assert_rejected(
            r#"
services:
  web:
    image: nginx
  attacker:
    image: alpine
    privileged: true
"#,
            "privileged mode is not allowed",
        );
    }

    #[test]
    fn multiple_services_all_get_limits() {
        let output = assert_accepted(
            r#"
services:
  web:
    image: nginx
  worker:
    image: redis
"#,
        );

        let doc: Value = serde_yaml::from_str(&output).unwrap();
        for svc_name in &["web", "worker"] {
            let svc = doc.get("services").unwrap().get(*svc_name).unwrap();
            assert!(
                svc.get("mem_limit").is_some(),
                "{} missing mem_limit",
                svc_name
            );
            assert!(svc.get("cpus").is_some(), "{} missing cpus", svc_name);
            assert!(
                svc.get("pids_limit").is_some(),
                "{} missing pids_limit",
                svc_name
            );
        }
    }
}
