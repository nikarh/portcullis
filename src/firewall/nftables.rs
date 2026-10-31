use std::ffi::{CStr, CString};
use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::ptr::NonNull;
use std::sync::Mutex;

use tracing::{info, trace};

use super::FirewallError;
use super::plan::{
    DNS_PORT, Destination, HostSet, Plan, Rule, SET_PREFIX_V4, SET_PREFIX_V6, Source,
};
use crate::dns::PolicyDnsResolver;
use crate::model::RuntimeState;

/// Name of both managed tables.
const TABLE_NAME: &str = "portcullis";
/// Priority of both base chains: before Docker's filter chains.
const FORWARD_HOOK_PRIORITY: i32 = -1;

/// The managed tables: `inet` sees traffic routed out of a container's network, `bridge`
/// sees traffic between containers on the same network, which a bridge switches without
/// passing the IP hooks (unless `br_netfilter` is loaded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Table {
    Inet,
    Bridge,
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet => write!(f, "inet {TABLE_NAME}"),
            Self::Bridge => write!(f, "bridge {TABLE_NAME}"),
        }
    }
}

/// A chain, displayed as `<family> <table> <chain>`.
#[derive(Debug, Clone, Copy)]
enum Chain {
    /// The base chain of a table.
    Base(Table),
    /// Egress rules of the n-th source, in the inet table.
    Egress(usize),
    /// ICC rules of the n-th source, in the bridge table.
    Icc(usize),
}

impl Chain {
    const fn table(self) -> Table {
        match self {
            Self::Base(table) => table,
            Self::Egress(_) => Table::Inet,
            Self::Icc(_) => Table::Bridge,
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.table())?;
        match self {
            Self::Base(_) => f.write_str("forward"),
            Self::Egress(index) => write!(f, "egress{index}"),
            Self::Icc(index) => write!(f, "icc{index}"),
        }
    }
}

/// The chain name alone, as used in jump targets.
struct ChainName(Chain);

impl fmt::Display for ChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Chain::Base(_) => f.write_str("forward"),
            Chain::Egress(index) => write!(f, "egress{index}"),
            Chain::Icc(index) => write!(f, "icc{index}"),
        }
    }
}

pub trait NftRunner {
    /// Run an nft script as a single atomic transaction.
    fn run_script(&self, script: String) -> Result<(), FirewallError>;
}

pub struct NftablesFirewall<R = LibNftablesRunner> {
    runner: R,
}

impl<R> NftablesFirewall<R>
where
    R: NftRunner,
{
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn apply<Dns>(
        &self,
        state: &RuntimeState,
        resolver: &mut Dns,
        host_resolvers: &[IpAddr],
    ) -> Result<(), FirewallError>
    where
        Dns: PolicyDnsResolver,
    {
        let plan = Plan::build(state, resolver, host_resolvers);
        info!(
            source_count = plan.sources.len(),
            rule_count = plan.rule_count(),
            host_set_count = plan.host_sets.len(),
            container_count = state.containers().len(),
            "applying nftables changes"
        );

        let mut script = String::with_capacity(plan.rule_count() * 64);
        render_apply_script(&plan, &mut script)?;
        self.runner.run_script(script)
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let mut script = String::new();
        render_table_reset(&mut script)?;
        self.runner.run_script(script)?;
        info!("nftables cleanup completed");
        Ok(())
    }
}

impl NftablesFirewall<LibNftablesRunner> {
    pub fn with_libnftables() -> Result<Self, FirewallError> {
        let runner = LibNftablesRunner::new()?;
        Ok(Self::new(runner))
    }
}

/// Remove the managed tables. The `add` makes the `delete` succeed whether or not a table
/// exists, so neither cleanup nor apply depend on prior state or on matching error strings.
fn render_table_reset(out: &mut String) -> fmt::Result {
    for table in [Table::Inet, Table::Bridge] {
        writeln!(out, "add table {table}")?;
        writeln!(out, "delete table {table}")?;
    }
    Ok(())
}

/// Render the full apply script.
///
/// Each table has a base chain that lets established traffic through and dispatches each
/// managed source address through a verdict map to its own chain. A packet costs one hash
/// lookup plus the rules of its own source, regardless of how many containers are managed.
/// The inet base chain then drops unmanaged sources of enforced subnets.
///
/// Both tables are deleted and recreated inside the same transaction, so the swap is
/// atomic and chains and sets no longer needed disappear together with the old tables.
fn render_apply_script(plan: &Plan, out: &mut String) -> fmt::Result {
    render_table_reset(out)?;

    // Routed traffic.
    render_base_chain(out, Table::Inet)?;
    for (index, _) in plan.sources.iter().enumerate() {
        writeln!(out, "add chain {}", Chain::Egress(index))?;
    }
    for set in &plan.host_sets {
        if set.used_v4 {
            render_set(out, set, SET_PREFIX_V4, "ipv4_addr", set.v4())?;
        }
        if set.used_v6 {
            render_set(out, set, SET_PREFIX_V6, "ipv6_addr", set.v6())?;
        }
    }
    render_dispatch(out, plan, Table::Inet, |_| true, Chain::Egress)?;
    let base = Chain::Base(Table::Inet);
    for (family, is_family) in FAMILIES {
        let subnets = plan
            .enforced_subnets
            .iter()
            .filter(|subnet| is_family(&subnet.addr()));
        render_elements(
            out,
            format_args!("add rule {base} {family} saddr"),
            subnets,
            " drop",
        )?;
    }
    for (index, source) in plan.sources.iter().enumerate() {
        let chain = Chain::Egress(index);
        for rule in plan.egress_rules(source) {
            render_rule(plan, source.address, chain, rule, out)?;
        }
        writeln!(out, "add rule {chain} drop")?;
    }

    // Traffic between containers on the same network.
    let restricted = |source: &Source| !plan.icc_rules(source).is_empty();
    render_base_chain(out, Table::Bridge)?;
    for (index, _) in plan
        .sources
        .iter()
        .enumerate()
        .filter(|(_, source)| restricted(source))
    {
        writeln!(out, "add chain {}", Chain::Icc(index))?;
    }
    render_dispatch(out, plan, Table::Bridge, restricted, Chain::Icc)?;
    for (index, source) in plan.sources.iter().enumerate() {
        let chain = Chain::Icc(index);
        for rule in plan.icc_rules(source) {
            render_rule(plan, source.address, chain, rule, out)?;
        }
    }
    Ok(())
}

/// nftables keyword of an address family, and whether an address belongs to it.
type Family = (&'static str, fn(&IpAddr) -> bool);

const FAMILIES: [Family; 2] = [("ip", IpAddr::is_ipv4), ("ip6", IpAddr::is_ipv6)];

fn render_base_chain(out: &mut String, table: Table) -> fmt::Result {
    let base = Chain::Base(table);
    writeln!(out, "add table {table}")?;
    writeln!(
        out,
        "add chain {base} {{ type filter hook forward priority {FORWARD_HOOK_PRIORITY}; policy accept; }}"
    )?;
    // Policy applies to new connections only; replies and established flows skip it.
    writeln!(out, "add rule {base} ct state established,related accept")
}

/// Dispatch the selected sources from the base chain of `table` to their chains.
fn render_dispatch(
    out: &mut String,
    plan: &Plan,
    table: Table,
    selected: impl Fn(&Source) -> bool,
    chain: fn(usize) -> Chain,
) -> fmt::Result {
    let base = Chain::Base(table);
    for (family, is_family) in FAMILIES {
        let entries = plan
            .sources
            .iter()
            .enumerate()
            .filter(|(_, source)| is_family(&source.address) && selected(source))
            .map(|(index, source)| Goto(source.address, chain(index)));
        render_elements(
            out,
            format_args!("add rule {base} {family} saddr vmap"),
            entries,
            "",
        )?;
    }
    Ok(())
}

/// Write `{head} { e1, e2, ... }{tail}` and a newline; writes nothing without elements.
fn render_elements<T: fmt::Display>(
    out: &mut String,
    head: fmt::Arguments<'_>,
    elements: impl Iterator<Item = T>,
    tail: &str,
) -> fmt::Result {
    let mut elements = elements.peekable();
    if elements.peek().is_none() {
        return Ok(());
    }
    write!(out, "{head} {{ ")?;
    for (index, element) in elements.enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        write!(out, "{element}")?;
    }
    out.push_str(" }");
    out.push_str(tail);
    out.push('\n');
    Ok(())
}

fn render_set(
    out: &mut String,
    set: &HostSet,
    prefix: &'static str,
    type_name: &str,
    addresses: impl Iterator<Item = IpAddr>,
) -> fmt::Result {
    let name = set.id.name(prefix);
    let table = Table::Inet;
    writeln!(out, "add set {table} {name} {{ type {type_name}; }}")?;
    render_elements(
        out,
        format_args!("add element {table} {name}"),
        addresses,
        "",
    )
}

/// Verdict map entry dispatching a source address to its chain.
struct Goto(IpAddr, Chain);

impl fmt::Display for Goto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} : goto {}", self.0, ChainName(self.1))
    }
}

const fn family(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    }
}

fn render_rule(
    plan: &Plan,
    source: IpAddr,
    chain: Chain,
    rule: &Rule,
    out: &mut String,
) -> fmt::Result {
    let f = family(source);
    match *rule {
        Rule::AcceptDns {
            destination,
            protocol,
        } => {
            write!(out, "add rule {chain} ")?;
            if let Some(destination) = destination {
                write!(out, "{f} daddr {destination} ")?;
            }
            writeln!(out, "{} dport {DNS_PORT} accept", protocol.as_str())
        }
        Rule::DropDns { protocol } => writeln!(
            out,
            "add rule {chain} {} dport {DNS_PORT} drop",
            protocol.as_str()
        ),
        Rule::AcceptNet(destination) => {
            writeln!(out, "add rule {chain} {f} daddr {destination} accept")
        }
        Rule::DropNet(destination) => {
            writeln!(out, "add rule {chain} {f} daddr {destination} drop")
        }
        Rule::AcceptPort {
            destination,
            protocol,
            port,
        } => {
            let protocol = protocol.as_str();
            match destination {
                Destination::Net(destination) => writeln!(
                    out,
                    "add rule {chain} {f} daddr {destination} {protocol} dport {port} accept"
                ),
                Destination::Addr(destination) => writeln!(
                    out,
                    "add rule {chain} {f} daddr {destination} {protocol} dport {port} accept"
                ),
                Destination::HostSet(index) => {
                    let Some(set) = plan.host_set(index) else {
                        return Ok(());
                    };
                    let prefix = if source.is_ipv4() {
                        SET_PREFIX_V4
                    } else {
                        SET_PREFIX_V6
                    };
                    writeln!(
                        out,
                        "add rule {chain} {f} daddr @{} {protocol} dport {port} accept",
                        set.id.name(prefix)
                    )
                }
            }
        }
    }
}

#[allow(unsafe_code, warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/libnftables_bindings.rs"));
}

trait NftApi {
    type Handle: Copy;

    fn new_context(&self) -> Option<Self::Handle>;
    fn free_context(&self, handle: Self::Handle);
    fn buffer_output(&self, handle: Self::Handle) -> i32;
    fn buffer_error(&self, handle: Self::Handle) -> i32;
    fn run_script(&self, handle: Self::Handle, script: &CStr) -> i32;
    fn error_output(&self, handle: Self::Handle) -> Option<String>;
}

#[derive(Debug, Clone, Copy)]
struct RealNftApi;

#[allow(unsafe_code)]
impl NftApi for RealNftApi {
    type Handle = NonNull<bindings::nft_ctx>;

    fn new_context(&self) -> Option<Self::Handle> {
        // SAFETY: `nft_ctx_new` is an FFI constructor that returns either null or a valid
        // pointer to an allocated context when passed a valid flags value.
        let pointer = unsafe { bindings::nft_ctx_new(bindings::NFT_CTX_DEFAULT) };
        NonNull::new(pointer)
    }

    fn free_context(&self, handle: Self::Handle) {
        // SAFETY: `handle` comes from `nft_ctx_new` and is freed exactly once in `Drop`.
        unsafe { bindings::nft_ctx_free(handle.as_ptr()) };
    }

    fn buffer_output(&self, handle: Self::Handle) -> i32 {
        // SAFETY: `handle` points to a valid live context.
        unsafe { bindings::nft_ctx_buffer_output(handle.as_ptr()) }
    }

    fn buffer_error(&self, handle: Self::Handle) -> i32 {
        // SAFETY: `handle` points to a valid live context.
        unsafe { bindings::nft_ctx_buffer_error(handle.as_ptr()) }
    }

    fn run_script(&self, handle: Self::Handle, script: &CStr) -> i32 {
        // SAFETY: both pointers are valid for the duration of this call.
        unsafe { bindings::nft_run_cmd_from_buffer(handle.as_ptr(), script.as_ptr()) }
    }

    fn error_output(&self, handle: Self::Handle) -> Option<String> {
        // SAFETY: pointer is owned by libnftables for this context and may be null.
        let pointer = unsafe { bindings::nft_ctx_get_error_buffer(handle.as_ptr()) };
        if pointer.is_null() {
            return None;
        }

        // SAFETY: non-null C string pointer returned by libnftables.
        let cstr = unsafe { CStr::from_ptr(pointer) };
        Some(cstr.to_string_lossy().trim().to_string())
    }
}

struct NftContext<A>
where
    A: NftApi,
{
    api: A,
    handle: A::Handle,
}

impl<A> NftContext<A>
where
    A: NftApi,
{
    fn new(api: A) -> Result<Self, FirewallError> {
        let Some(handle) = api.new_context() else {
            return Err(FirewallError::LibContextCreate);
        };

        let output_rc = api.buffer_output(handle);
        if output_rc != 0 {
            api.free_context(handle);
            return Err(FirewallError::LibBufferConfig {
                buffer: "output",
                code: output_rc,
            });
        }

        let error_rc = api.buffer_error(handle);
        if error_rc != 0 {
            api.free_context(handle);
            return Err(FirewallError::LibBufferConfig {
                buffer: "error",
                code: error_rc,
            });
        }

        Ok(Self { api, handle })
    }

    /// Run `script`. Taking ownership of a `String` lets the NUL terminator be appended
    /// without copying the script.
    fn run_script(&mut self, script: impl Into<Vec<u8>>) -> Result<(), FirewallError> {
        let c_script = CString::new(script).map_err(|_| FirewallError::ScriptContainsNul)?;
        let result = self.api.run_script(self.handle, &c_script);
        if result == 0 {
            return Ok(());
        }

        let stderr = self
            .api
            .error_output(self.handle)
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| "unknown libnftables error".to_string());

        Err(FirewallError::LibCommandFailure {
            code: result,
            stderr,
        })
    }
}

impl<A> Drop for NftContext<A>
where
    A: NftApi,
{
    fn drop(&mut self) {
        self.api.free_context(self.handle);
    }
}

pub struct LibNftablesRunner {
    context: Mutex<NftContext<RealNftApi>>,
}

impl LibNftablesRunner {
    pub fn new() -> Result<Self, FirewallError> {
        let context = NftContext::new(RealNftApi)?;
        Ok(Self {
            context: Mutex::new(context),
        })
    }
}

impl NftRunner for LibNftablesRunner {
    fn run_script(&self, script: String) -> Result<(), FirewallError> {
        trace!(program = "nft", script, "executing firewall script");
        let mut guard = self
            .context
            .lock()
            .map_err(|_| FirewallError::LibContextLock)?;
        guard.run_script(script)
    }
}

#[cfg(test)]
mod libnftables_tests {
    use std::ffi::CStr;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Debug)]
    struct MockState {
        next_context: Option<usize>,
        output_rc: i32,
        error_rc: i32,
        run_rc: i32,
        error_message: String,
        freed: usize,
        scripts: Vec<String>,
    }

    #[derive(Clone)]
    struct MockApi {
        state: Arc<Mutex<MockState>>,
    }

    impl MockApi {
        fn new(state: MockState) -> Self {
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn state(&self) -> MockState {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.clone()
        }
    }

    impl NftApi for MockApi {
        type Handle = usize;

        fn new_context(&self) -> Option<Self::Handle> {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.next_context
        }

        fn free_context(&self, _handle: Self::Handle) {
            let mut guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.freed += 1;
        }

        fn buffer_output(&self, _handle: Self::Handle) -> i32 {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.output_rc
        }

        fn buffer_error(&self, _handle: Self::Handle) -> i32 {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.error_rc
        }

        fn run_script(&self, _handle: Self::Handle, script: &CStr) -> i32 {
            let mut guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.scripts.push(script.to_string_lossy().to_string());
            guard.run_rc
        }

        fn error_output(&self, _handle: Self::Handle) -> Option<String> {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            Some(guard.error_message.clone())
        }
    }

    fn base_state() -> MockState {
        MockState {
            next_context: Some(1),
            output_rc: 0,
            error_rc: 0,
            run_rc: 0,
            error_message: String::new(),
            freed: 0,
            scripts: Vec::new(),
        }
    }

    #[test]
    fn wrapper_runs_script_successfully() {
        let api = MockApi::new(base_state());
        let mut context = match NftContext::new(api.clone()) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("add table inet portcullis");
        assert!(result.is_ok());

        let state = api.state();
        assert_eq!(state.scripts.len(), 1);
    }

    #[test]
    fn wrapper_reports_script_failure() {
        let mut state = base_state();
        state.run_rc = -1;
        state.error_message = "syntax error".to_string();
        let api = MockApi::new(state);
        let mut context = match NftContext::new(api) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("invalid");
        assert!(matches!(
            result,
            Err(FirewallError::LibCommandFailure { code: -1, .. })
        ));
    }

    #[test]
    fn wrapper_rejects_nul_byte_scripts() {
        let api = MockApi::new(base_state());
        let mut context = match NftContext::new(api) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("bad\0script");
        assert!(matches!(result, Err(FirewallError::ScriptContainsNul)));
    }

    #[test]
    fn wrapper_frees_context_on_drop() {
        let api = MockApi::new(base_state());
        {
            let context = match NftContext::new(api.clone()) {
                Ok(value) => value,
                Err(error) => panic!("expected context creation to succeed: {error}"),
            };
            let _ = context;
        }

        let state = api.state();
        assert_eq!(state.freed, 1);
    }

    #[test]
    fn wrapper_fails_when_context_creation_fails() {
        let mut state = base_state();
        state.next_context = None;
        let api = MockApi::new(state);

        let result = NftContext::new(api);
        assert!(matches!(result, Err(FirewallError::LibContextCreate)));
    }

    #[test]
    fn wrapper_fails_when_output_buffering_fails() {
        let mut state = base_state();
        state.output_rc = -1;
        let api = MockApi::new(state);

        let result = NftContext::new(api);
        assert!(matches!(
            result,
            Err(FirewallError::LibBufferConfig {
                buffer: "output",
                code: -1
            })
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::firewall::test_support::{self, MockResolver};

    fn render(state: &RuntimeState) -> String {
        let plan = Plan::build(
            state,
            &mut MockResolver::default(),
            &test_support::host_resolvers(),
        );
        let mut script = String::new();
        render_apply_script(&plan, &mut script).expect("script should render");
        script
    }

    fn has_line(script: &str, expected: &str) -> bool {
        script.lines().any(|line| line == expected)
    }

    /// Name of the chain the base chain of `table` ("inet" or "bridge") dispatches
    /// `source` to.
    fn chain_of(script: &str, table: &str, source: &str) -> String {
        let prefix = format!("add rule {table} portcullis forward ");
        let needle = format!(" {source} : goto ");
        script
            .lines()
            .filter(|line| line.starts_with(prefix.as_str()) && line.contains("vmap"))
            .find_map(|line| line.split_once(needle.as_str()))
            .unwrap_or_else(|| panic!("no {table} dispatch for {source} in:\n{script}"))
            .1
            .split([',', ' '])
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn assert_rules(script: &str, table: &str, source: &str, expected: &[&str]) {
        let chain = chain_of(script, table, source);
        for rule in expected {
            let line = format!("add rule {table} portcullis {chain} {rule}");
            assert!(has_line(script, &line), "missing {line} in:\n{script}");
        }
    }

    #[test]
    fn renders_layout() {
        let script = render(&test_support::hostname_state());
        assert_eq!(chain_of(&script, "inet", "172.18.0.2"), "egress0");
        assert_eq!(chain_of(&script, "bridge", "172.18.0.2"), "icc0");
        let expected_head = "\
add table inet portcullis
delete table inet portcullis
add table bridge portcullis
delete table bridge portcullis
add table inet portcullis
add chain inet portcullis forward { type filter hook forward priority -1; policy accept; }
add rule inet portcullis forward ct state established,related accept
add chain inet portcullis egress0
";
        assert!(
            script.starts_with(expected_head),
            "unexpected head:\n{script}"
        );
        for expected in [
            "add rule inet portcullis forward ip saddr vmap { 172.18.0.2 : goto egress0 }",
            "add rule inet portcullis forward ip saddr { 172.18.0.0/16 } drop",
            "add rule inet portcullis egress0 drop",
            "add chain bridge portcullis forward { type filter hook forward priority -1; policy accept; }",
            "add rule bridge portcullis forward ct state established,related accept",
            "add rule bridge portcullis forward ip saddr vmap { 172.18.0.2 : goto icc0 }",
        ] {
            assert!(has_line(&script, expected), "missing line: {expected}");
        }
        // nothing for families without sources
        assert!(!script.contains("ip6 saddr"));
    }

    #[test]
    fn renders_hostname_set_once_per_host_and_family() {
        let script = render(&test_support::shared_hostname_state());
        assert_eq!(script.matches("add set inet portcullis pc_h4_").count(), 1);
        assert_eq!(
            script.matches("add element inet portcullis pc_h4_").count(),
            1
        );
        assert_eq!(script.matches("ip daddr @pc_h4_").count(), 2);
        // no IPv6 source references the host, so no IPv6 set is created
        assert!(!script.contains("pc_h6_"));
        assert!(script.contains(" { 1.1.1.1 }\n"));
    }

    #[test]
    fn renders_ipv6_rules_and_sets() {
        let script = render(&test_support::ipv6_state());
        assert!(script.contains("add set inet portcullis pc_h6_"));
        assert!(script.contains(" { 2606:4700::1111 }\n"));
        assert!(!script.contains("pc_h4_"));
        assert!(has_line(
            &script,
            "add rule inet portcullis forward ip6 saddr vmap { fd00::2 : goto egress0 }"
        ));
        assert!(script.contains("add rule inet portcullis egress0 ip6 daddr @pc_h6_"));
        assert_rules(
            &script,
            "inet",
            "fd00::2",
            &["ip6 daddr 2001:db8::/32 tcp dport 443 accept"],
        );
        assert_rules(&script, "bridge", "fd00::2", &["ip6 daddr fd00::/64 drop"]);
    }

    #[test]
    fn renders_icc_modes() {
        let script = render(&test_support::icc_state());
        // allow: no bridge rules at all
        assert!(!script.contains("172.18.0.3 : goto icc"));
        assert_rules(
            &script,
            "inet",
            "172.18.0.3",
            &["ip daddr 172.18.0.0/16 accept"],
        );
        assert_rules(
            &script,
            "bridge",
            "172.18.0.2",
            &[
                "ip daddr 172.18.0.10 tcp dport 5432 accept",
                "ip daddr 172.18.0.0/16 drop",
            ],
        );
        assert!(!script.contains("ip daddr 172.19.0.10 tcp dport 5432"));
    }

    #[test]
    fn renders_dns_rules() {
        let script = render(&test_support::hostname_state());
        assert_rules(
            &script,
            "inet",
            "172.18.0.2",
            &[
                "ip daddr 9.9.9.9 udp dport 53 accept",
                "ip daddr 9.9.9.9 tcp dport 53 accept",
                "udp dport 53 drop",
                "tcp dport 53 drop",
                "ip daddr 8.8.8.0/24 tcp dport 853 accept",
            ],
        );
    }

    #[test]
    fn renders_unresolvable_hostname_as_empty_set() {
        let script = render(&test_support::unresolvable_state());
        assert!(script.contains("add set inet portcullis pc_h4_"));
        assert!(!script.contains("add element"));
        assert!(script.contains("ip daddr @pc_h4_"));
        assert_rules(
            &script,
            "inet",
            "172.18.0.2",
            &["ip daddr 8.8.8.0/24 tcp dport 853 accept"],
        );
    }

    #[test]
    fn apply_succeeds_with_unresolvable_hostname() {
        let firewall = NftablesFirewall::new(RecordingRunner::default());
        firewall
            .apply(
                &test_support::unresolvable_state(),
                &mut MockResolver::default(),
                &[],
            )
            .expect("apply should succeed");
        assert_eq!(firewall.runner.scripts.lock().expect("lock").len(), 1);
    }

    #[derive(Default)]
    struct RecordingRunner {
        scripts: Mutex<Vec<String>>,
    }

    impl NftRunner for RecordingRunner {
        fn run_script(&self, script: String) -> Result<(), FirewallError> {
            self.scripts.lock().expect("lock").push(script);
            Ok(())
        }
    }

    #[test]
    fn apply_runs_single_script() {
        let firewall = NftablesFirewall::new(RecordingRunner::default());
        firewall
            .apply(
                &test_support::hostname_state(),
                &mut MockResolver::default(),
                &[],
            )
            .expect("apply should succeed");
        let scripts = firewall.runner.scripts.lock().expect("lock");
        assert_eq!(scripts.len(), 1);
    }

    #[test]
    fn cleanup_deletes_table_even_if_missing() {
        let firewall = NftablesFirewall::new(RecordingRunner::default());
        firewall.cleanup().expect("cleanup should succeed");
        let scripts = firewall.runner.scripts.lock().expect("lock");
        assert_eq!(
            scripts.as_slice(),
            [
                "add table inet portcullis\ndelete table inet portcullis\nadd table bridge portcullis\ndelete table bridge portcullis\n"
            ]
        );
    }
}
