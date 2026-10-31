use std::fmt::{self, Write as _};
use std::io::Write as _;
use std::net::IpAddr;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, PoisonError};

use ipnet::IpNet;
use tracing::{info, trace, warn};

use super::FirewallError;
use super::plan::{DNS_PORT, Destination, HostSetId, Plan, Rule, SET_PREFIX_V4};
use crate::dns::PolicyDnsResolver;
use crate::model::RuntimeState;

const CHAIN_NAME: &str = "PORTCULLIS_EGRESS";
const STAGING_CHAIN_NAME: &str = "PORTCULLIS_EGRESS_NEXT";
const DOCKER_USER_CHAIN: &str = "DOCKER-USER";
/// Prefix of the scratch sets used to refill hostname sets atomically.
const TEMP_SET_PREFIX_V4: &str = "pc_t4_";

pub trait IptablesRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), FirewallError>;
    /// Run `iptables-restore --noflush` with the given script.
    fn run_iptables_restore(&self, script: &str) -> Result<(), FirewallError>;
    /// Run `ipset restore` with the given script.
    fn run_ipset_restore(&self, script: &str) -> Result<(), FirewallError>;
    fn read_iptables_save_filter(&self) -> Result<String, FirewallError>;
    /// Names of all existing ipsets, one per line (`ipset list -n`).
    fn list_ipsets(&self) -> Result<String, FirewallError>;
}

pub struct CommandIptablesRunner;

fn ensure_success(output: Output) -> Result<Output, FirewallError> {
    if output.status.success() {
        return Ok(output);
    }

    Err(FirewallError::CommandFailure {
        code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn run_with_stdin(program: &'static str, args: &[&str], script: &str) -> Result<(), FirewallError> {
    trace!(program, args = ?args, script, "executing firewall batch command");
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let Some(stdin) = child.stdin.as_mut() else {
        return Err(FirewallError::CommandStdinUnavailable { program });
    };
    stdin.write_all(script.as_bytes())?;
    ensure_success(child.wait_with_output()?)?;
    Ok(())
}

impl IptablesRunner for CommandIptablesRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), FirewallError> {
        trace!(program, args = ?args, "executing firewall command");
        let output = Command::new(program).args(args).output()?;
        ensure_success(output)?;

        Ok(())
    }

    fn run_iptables_restore(&self, script: &str) -> Result<(), FirewallError> {
        run_with_stdin("iptables-restore", &["--noflush"], script)
    }

    fn run_ipset_restore(&self, script: &str) -> Result<(), FirewallError> {
        run_with_stdin("ipset", &["restore"], script)
    }

    fn read_iptables_save_filter(&self) -> Result<String, FirewallError> {
        trace!(program = "iptables-save", args = ?["-t", "filter"], "reading firewall filter table");
        let output = Command::new("iptables-save")
            .args(["-t", "filter"])
            .output()?;
        let output = ensure_success(output)?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn list_ipsets(&self) -> Result<String, FirewallError> {
        trace!(program = "ipset", args = ?["list", "-n"], "listing ipsets");
        let output = Command::new("ipset").args(["list", "-n"]).output()?;
        let output = ensure_success(output)?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

pub struct IptablesFirewall<R> {
    runner: R,
    use_ipset: bool,
    /// Sorted ids of hostname ipsets this process may have created and not destroyed yet.
    known_sets: Mutex<Vec<HostSetId>>,
}

impl<R> IptablesFirewall<R>
where
    R: IptablesRunner,
{
    pub const fn new(runner: R, use_ipset: bool) -> Self {
        Self {
            runner,
            use_ipset,
            known_sets: Mutex::new(Vec::new()),
        }
    }

    pub fn apply<Dns>(&self, state: &RuntimeState, resolver: &mut Dns) -> Result<(), FirewallError>
    where
        Dns: PolicyDnsResolver,
    {
        let plan = Plan::build(state, resolver)?;
        info!(
            rule_count = plan.rules.len(),
            host_set_count = plan.host_sets.len(),
            container_count = state.containers().len(),
            "applying iptables changes"
        );

        // One buffer reused for every script.
        let mut script = String::with_capacity(plan.rules.len() * 64);
        let mut current_sets = Vec::new();
        if self.use_ipset {
            current_sets.extend(
                plan.host_sets
                    .iter()
                    .filter(|set| set.used_v4)
                    .map(|set| set.id),
            );
            current_sets.sort_unstable();

            render_ipset_script(&plan, &mut script)?;
            if !script.is_empty() {
                self.runner.run_ipset_restore(&script)?;
            }
            script.clear();

            // Track the sets before the rules apply, so they are destroyed later even if
            // applying the rules fails.
            let mut known = self
                .known_sets
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            known.extend_from_slice(&current_sets);
            known.sort_unstable();
            known.dedup();
        }

        render_iptables_script(&plan, CHAIN_NAME, self.use_ipset, &mut script)?;
        self.runner.run_iptables_restore(&script)?;

        if self.use_ipset {
            script.clear();
            self.destroy_stale_sets(&current_sets, &mut script)?;
        }
        Ok(())
    }

    /// Destroy known sets that are not part of `current` (sorted). Must run after the rules
    /// referencing them were replaced, otherwise the kernel refuses to destroy them.
    fn destroy_stale_sets(
        &self,
        current: &[HostSetId],
        script: &mut String,
    ) -> Result<(), FirewallError> {
        let mut known = self
            .known_sets
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for id in known.iter().filter(|id| current.binary_search(id).is_err()) {
            writeln!(script, "destroy {}", id.name(SET_PREFIX_V4))?;
        }
        if script.is_empty() {
            return Ok(());
        }

        match self.runner.run_ipset_restore(script) {
            Ok(()) => {
                known.clear();
                known.extend_from_slice(current);
            }
            // Keep tracking them so the next apply or cleanup retries.
            Err(error) => warn!(%error, "failed to destroy stale ipsets; will retry"),
        }
        Ok(())
    }

    pub fn initialize(&self) -> Result<(), FirewallError> {
        match self.runner.run("iptables", &["-N", CHAIN_NAME]) {
            Ok(()) => {}
            Err(FirewallError::CommandFailure { stderr, .. })
                if stderr.contains("Chain already exists") => {}
            Err(error) => return Err(error),
        }

        match self.runner.run(
            "iptables",
            &["-I", DOCKER_USER_CHAIN, "1", "-j", CHAIN_NAME],
        ) {
            Ok(()) => {}
            Err(FirewallError::CommandFailure { stderr, .. })
                if stderr.contains("exists") || stderr.contains("Bad rule") => {}
            Err(error) => return Err(error),
        }

        Ok(())
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let filter_rules = self.runner.read_iptables_save_filter()?;
        let mut script = String::new();
        render_cleanup_script(&filter_rules, &mut script)?;
        if !script.is_empty() {
            self.runner.run_iptables_restore(&script)?;
        }

        if self.use_ipset {
            // Covers sets left behind by previous processes as well.
            let sets = self.runner.list_ipsets()?;
            script.clear();
            render_ipset_cleanup_script(&sets, &mut script)?;
            if !script.is_empty() {
                self.runner.run_ipset_restore(&script)?;
            }
            self.known_sets
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
        }

        info!("iptables cleanup completed");
        Ok(())
    }
}

impl IptablesFirewall<CommandIptablesRunner> {
    #[must_use]
    pub fn with_cli() -> Self {
        let use_ipset = detect_ipset_available();
        if use_ipset {
            info!("ipset detected at startup; enabling ipset-backed hostname rules");
        } else {
            info!("ipset not detected at startup; using direct iptables hostname rules");
        }
        Self::new(CommandIptablesRunner, use_ipset)
    }
}

fn detect_ipset_available() -> bool {
    match Command::new("ipset").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Render the `ipset restore` script creating and populating one set per hostname that is
/// referenced by an IPv4 rule.
///
/// Each set is filled in a scratch set and swapped in, so live rules never observe a
/// partially filled set.
fn render_ipset_script(plan: &Plan, out: &mut String) -> fmt::Result {
    for set in plan.host_sets.iter().filter(|set| set.used_v4) {
        let name = set.id.name(SET_PREFIX_V4);
        let temp = set.id.name(TEMP_SET_PREFIX_V4);
        writeln!(out, "create {name} hash:ip -exist")?;
        writeln!(out, "create {temp} hash:ip -exist")?;
        writeln!(out, "flush {temp}")?;
        for address in set.v4() {
            writeln!(out, "add {temp} {address} -exist")?;
        }
        writeln!(out, "swap {temp} {name}")?;
        writeln!(out, "destroy {temp}")?;
    }
    Ok(())
}

/// Render the script destroying every managed set listed in `ipset list -n` output.
fn render_ipset_cleanup_script(sets: &str, out: &mut String) -> fmt::Result {
    for name in sets
        .lines()
        .map(str::trim)
        .filter(|name| name.starts_with(SET_PREFIX_V4) || name.starts_with(TEMP_SET_PREFIX_V4))
    {
        writeln!(out, "destroy {name}")?;
    }
    Ok(())
}

/// Render the `iptables-restore --noflush` script replacing the contents of `chain`.
///
/// Allowed traffic `RETURN`s to `DOCKER-USER` instead of being accepted, so Docker's own
/// rules (network isolation, internal networks, ICC settings) still apply: the policy can
/// only take access away, never grant it. This matches nftables, where `accept` in our
/// base chain doesn't skip Docker's chains.
///
/// The iptables backend only manages IPv4; IPv6 rules of the plan are skipped.
fn render_iptables_script(
    plan: &Plan,
    chain: &str,
    use_ipset: bool,
    out: &mut String,
) -> fmt::Result {
    out.push_str("*filter\n");
    writeln!(out, "-F {chain}")?;
    // Policy applies to new connections only; replies and established flows skip it.
    writeln!(
        out,
        "-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    )?;
    for rule in &plan.rules {
        render_rule(plan, rule, chain, use_ipset, out)?;
    }
    out.push_str("COMMIT\n");
    Ok(())
}

fn render_rule(
    plan: &Plan,
    rule: &Rule,
    chain: &str,
    use_ipset: bool,
    out: &mut String,
) -> fmt::Result {
    match *rule {
        Rule::AcceptDns {
            source: IpAddr::V4(source),
            destination,
            protocol,
        } => {
            write!(out, "-A {chain} -s {source}/32 ")?;
            if let Some(IpAddr::V4(destination)) = destination {
                write!(out, "-d {destination}/32 ")?;
            }
            writeln!(out, "-p {} --dport {DNS_PORT} -j RETURN", protocol.as_str())
        }
        Rule::DropDns {
            source: IpAddr::V4(source),
            protocol,
        } => writeln!(
            out,
            "-A {chain} -s {source}/32 -p {} --dport {DNS_PORT} -j DROP",
            protocol.as_str()
        ),
        Rule::AcceptNet {
            source: IpAddr::V4(source),
            destination: IpNet::V4(destination),
        } => writeln!(out, "-A {chain} -s {source}/32 -d {destination} -j RETURN"),
        Rule::DropNet {
            source: IpAddr::V4(source),
            destination: IpNet::V4(destination),
        } => writeln!(out, "-A {chain} -s {source}/32 -d {destination} -j DROP"),
        Rule::AcceptPort {
            source: IpAddr::V4(source),
            destination,
            protocol,
            port,
        } => {
            let protocol = protocol.as_str();
            match destination {
                Destination::Net(IpNet::V4(destination)) => writeln!(
                    out,
                    "-A {chain} -s {source}/32 -d {destination} -p {protocol} --dport {port} -j RETURN"
                ),
                Destination::Addr(IpAddr::V4(destination)) => writeln!(
                    out,
                    "-A {chain} -s {source}/32 -d {destination}/32 -p {protocol} --dport {port} -j RETURN"
                ),
                Destination::HostSet(index) => {
                    let Some(set) = plan.host_set(index) else {
                        return Ok(());
                    };
                    if use_ipset {
                        writeln!(
                            out,
                            "-A {chain} -s {source}/32 -m set --match-set {} dst -p {protocol} --dport {port} -j RETURN",
                            set.id.name(SET_PREFIX_V4)
                        )
                    } else {
                        for destination in set.v4() {
                            writeln!(
                                out,
                                "-A {chain} -s {source}/32 -d {destination}/32 -p {protocol} --dport {port} -j RETURN"
                            )?;
                        }
                        Ok(())
                    }
                }
                Destination::Net(IpNet::V6(_)) | Destination::Addr(IpAddr::V6(_)) => Ok(()),
            }
        }
        Rule::DropSource {
            source: IpAddr::V4(source),
        } => writeln!(out, "-A {chain} -s {source}/32 -j DROP"),
        Rule::DropSourceNet {
            subnet: IpNet::V4(subnet),
        } => writeln!(out, "-A {chain} -s {subnet} -j DROP"),
        // IPv6 is not managed by the iptables backend.
        _ => Ok(()),
    }
}

fn docker_user_jump_target(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("-A DOCKER-USER ")?;
    let mut parts = rest.split_whitespace();
    while let Some(part) = parts.next() {
        if part == "-j" {
            return parts.next();
        }
    }
    None
}

/// Render the cleanup script from `iptables-save -t filter` output. Leaves `out` empty when
/// there is nothing to clean up.
fn render_cleanup_script(filter_rules: &str, out: &mut String) -> fmt::Result {
    let mut has_egress_chain = false;
    let mut has_staging_chain = false;
    let mut egress_jump_count = 0usize;
    let mut staging_jump_count = 0usize;

    for line in filter_rules.lines() {
        if let Some(chain) = line.strip_prefix(':') {
            match chain.split_whitespace().next() {
                Some(CHAIN_NAME) => has_egress_chain = true,
                Some(STAGING_CHAIN_NAME) => has_staging_chain = true,
                _ => {}
            }
            continue;
        }
        match docker_user_jump_target(line) {
            Some(CHAIN_NAME) => egress_jump_count += 1,
            Some(STAGING_CHAIN_NAME) => staging_jump_count += 1,
            _ => {}
        }
    }

    if !has_egress_chain && !has_staging_chain && egress_jump_count + staging_jump_count == 0 {
        return Ok(());
    }

    out.push_str("*filter\n");
    for _ in 0..egress_jump_count {
        writeln!(out, "-D {DOCKER_USER_CHAIN} -j {CHAIN_NAME}")?;
    }
    for _ in 0..staging_jump_count {
        writeln!(out, "-D {DOCKER_USER_CHAIN} -j {STAGING_CHAIN_NAME}")?;
    }
    for (present, chain) in [
        (has_egress_chain, CHAIN_NAME),
        (has_staging_chain, STAGING_CHAIN_NAME),
    ] {
        if present {
            writeln!(out, "-F {chain}")?;
            writeln!(out, "-X {chain}")?;
        }
    }
    out.push_str("COMMIT\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::firewall::test_support::{self, MockResolver};

    fn render(state: &RuntimeState, use_ipset: bool) -> (String, String) {
        let plan = Plan::build(state, &mut MockResolver::default()).expect("plan should build");
        let mut ipset = String::new();
        render_ipset_script(&plan, &mut ipset).expect("ipset script should render");
        let mut iptables = String::new();
        render_iptables_script(&plan, CHAIN_NAME, use_ipset, &mut iptables)
            .expect("iptables script should render");
        (ipset, iptables)
    }

    fn has_line(script: &str, expected: &str) -> bool {
        script.lines().any(|line| line == expected)
    }

    #[test]
    fn renders_hostname_rules_without_ipset() {
        let (_, script) = render(&test_support::hostname_state(), false);
        assert!(has_line(
            &script,
            "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 1.1.1.1/32 -p tcp --dport 443 -j RETURN"
        ));
        assert!(!script.contains("--match-set"));
    }

    #[test]
    fn renders_hostname_rules_with_ipset_once_per_host() {
        let (ipset, script) = render(&test_support::shared_hostname_state(), true);
        assert_eq!(ipset.matches("create pc_h4_").count(), 1);
        assert_eq!(ipset.matches("swap pc_t4_").count(), 1);
        assert_eq!(script.matches("--match-set pc_h4_").count(), 2);
    }

    #[test]
    fn renders_icc_modes() {
        let (_, script) = render(&test_support::icc_state(), false);
        // allow: subnet accept
        assert!(has_line(
            &script,
            "-A PORTCULLIS_EGRESS -s 172.18.0.3/32 -d 172.18.0.0/16 -j RETURN"
        ));
        // allow-listed: alias target on the same network, then subnet drop
        assert!(has_line(
            &script,
            "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 172.18.0.10/32 -p tcp --dport 5432 -j RETURN"
        ));
        assert!(has_line(
            &script,
            "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 172.18.0.0/16 -j DROP"
        ));
        assert!(!script.contains("-d 172.19.0.10/32 -p tcp --dport 5432"));
    }

    #[test]
    fn renders_dns_and_baseline_rules() {
        let (_, script) = render(&test_support::hostname_state(), false);
        for expected in [
            "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 172.18.0.1/32 -p udp --dport 53 -j RETURN",
            "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 172.18.0.1/32 -p tcp --dport 53 -j RETURN",
            "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -p udp --dport 53 -j DROP",
            "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -j DROP",
            "-A PORTCULLIS_EGRESS -s 172.18.0.0/16 -j DROP",
        ] {
            assert!(has_line(&script, expected), "missing line: {expected}");
        }
        assert!(script.starts_with(
            "*filter\n-F PORTCULLIS_EGRESS\n-A PORTCULLIS_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\n"
        ));
        assert!(script.ends_with("COMMIT\n"));
    }

    #[test]
    fn skips_ipv6_rules() {
        let (_, script) = render(&test_support::ipv6_state(), false);
        assert!(!script.contains("fd00:"));
    }

    #[derive(Default)]
    struct RecordingRunner {
        save_filter_output: String,
        ipset_list_output: String,
        iptables_scripts: Mutex<Vec<String>>,
        ipset_scripts: Mutex<Vec<String>>,
    }

    impl IptablesRunner for RecordingRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<(), FirewallError> {
            Ok(())
        }

        fn run_iptables_restore(&self, script: &str) -> Result<(), FirewallError> {
            self.iptables_scripts
                .lock()
                .expect("lock")
                .push(script.to_string());
            Ok(())
        }

        fn run_ipset_restore(&self, script: &str) -> Result<(), FirewallError> {
            self.ipset_scripts
                .lock()
                .expect("lock")
                .push(script.to_string());
            Ok(())
        }

        fn read_iptables_save_filter(&self) -> Result<String, FirewallError> {
            Ok(self.save_filter_output.clone())
        }

        fn list_ipsets(&self) -> Result<String, FirewallError> {
            Ok(self.ipset_list_output.clone())
        }
    }

    #[test]
    fn refills_ipset_atomically_via_swap() {
        let (ipset, _) = render(&test_support::hostname_state(), true);
        let lines: Vec<&str> = ipset.lines().collect();
        let [
            create,
            create_temp,
            flush_temp,
            add_temp,
            swap,
            destroy_temp,
        ] = lines.as_slice()
        else {
            panic!("unexpected ipset script: {ipset}");
        };
        assert!(create.starts_with("create pc_h4_"));
        assert!(create_temp.starts_with("create pc_t4_"));
        assert!(flush_temp.starts_with("flush pc_t4_"));
        assert!(add_temp.starts_with("add pc_t4_") && add_temp.contains(" 1.1.1.1 "));
        assert!(swap.starts_with("swap pc_t4_") && swap.contains(" pc_h4_"));
        assert!(destroy_temp.starts_with("destroy pc_t4_"));
    }

    #[test]
    fn apply_destroys_sets_no_longer_referenced() {
        let firewall = IptablesFirewall::new(RecordingRunner::default(), true);
        let mut resolver = MockResolver::default();
        firewall
            .apply(&test_support::hostname_state(), &mut resolver)
            .expect("apply should succeed");
        firewall
            .apply(&test_support::icc_state(), &mut resolver)
            .expect("apply should succeed");
        firewall
            .apply(&test_support::icc_state(), &mut resolver)
            .expect("apply should succeed");

        let scripts = firewall.runner.ipset_scripts.lock().expect("lock");
        // fill on first apply, destroy after the second, nothing on the third
        assert_eq!(scripts.len(), 2);
        let destroy = scripts.get(1).expect("destroy script");
        assert!(destroy.starts_with("destroy pc_h4_"));
        assert_eq!(destroy.lines().count(), 1);
    }

    #[test]
    fn cleanup_destroys_managed_ipsets() {
        let runner = RecordingRunner {
            ipset_list_output: "pc_h4_0000000000000001\nunrelated\npc_t4_0000000000000002\n"
                .to_string(),
            ..RecordingRunner::default()
        };
        let firewall = IptablesFirewall::new(runner, true);
        firewall.cleanup().expect("cleanup should succeed");
        let scripts = firewall.runner.ipset_scripts.lock().expect("lock");
        assert_eq!(
            scripts.as_slice(),
            ["destroy pc_h4_0000000000000001\ndestroy pc_t4_0000000000000002\n"]
        );
    }

    #[test]
    fn apply_runs_ipset_before_iptables() {
        let firewall = IptablesFirewall::new(RecordingRunner::default(), true);
        firewall
            .apply(
                &test_support::hostname_state(),
                &mut MockResolver::default(),
            )
            .expect("apply should succeed");
        assert_eq!(firewall.runner.ipset_scripts.lock().expect("lock").len(), 1);
        assert_eq!(
            firewall.runner.iptables_scripts.lock().expect("lock").len(),
            1
        );
    }

    #[test]
    fn cleanup_renders_single_restore_batch() {
        let runner = RecordingRunner {
            save_filter_output: "\
*filter
:INPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
:PORTCULLIS_EGRESS - [0:0]
:PORTCULLIS_EGRESS_NEXT - [0:0]
-A DOCKER-USER -j PORTCULLIS_EGRESS
-A DOCKER-USER -j PORTCULLIS_EGRESS_NEXT
COMMIT
"
            .to_string(),
            ..RecordingRunner::default()
        };
        let firewall = IptablesFirewall::new(runner, false);
        firewall.cleanup().expect("cleanup should succeed");

        let scripts = firewall.runner.iptables_scripts.lock().expect("lock");
        assert_eq!(
            scripts.as_slice(),
            ["\
*filter
-D DOCKER-USER -j PORTCULLIS_EGRESS
-D DOCKER-USER -j PORTCULLIS_EGRESS_NEXT
-F PORTCULLIS_EGRESS
-X PORTCULLIS_EGRESS
-F PORTCULLIS_EGRESS_NEXT
-X PORTCULLIS_EGRESS_NEXT
COMMIT
"]
        );
    }

    #[test]
    fn cleanup_skips_restore_when_nothing_is_installed() {
        let runner = RecordingRunner {
            save_filter_output: "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n".to_string(),
            ..RecordingRunner::default()
        };
        let firewall = IptablesFirewall::new(runner, false);
        firewall.cleanup().expect("cleanup should succeed");
        assert!(
            firewall
                .runner
                .iptables_scripts
                .lock()
                .expect("lock")
                .is_empty()
        );
    }
}
