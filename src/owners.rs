//! Who each managed container address belongs to, to tell when an address changes hands
//! and its tracked connections must be forgotten (see `conntrack`).
//!
//! Kept in the state directory as well: when a container is removed and Docker gives its
//! address to a new one while Portcullis isn't running, the next start still sees that the
//! address changed hands.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::model::{ContainerId, MacAddress, RuntimeState};

/// Who an address belongs to: a recreated container has a new ID, and usually a new MAC.
pub type Owner = (ContainerId, Option<MacAddress>);

#[derive(Debug, Default)]
pub struct Owners {
    /// The owner of each address at the last update; none for an address two containers
    /// claimed at once.
    by_address: HashMap<IpAddr, Option<Owner>>,
    file: Option<PathBuf>,
    /// Changed since last saved.
    unsaved: bool,
}

impl Owners {
    /// The owners saved in `file`, which updates are saved to.
    pub fn load(file: PathBuf) -> io::Result<Self> {
        let by_address = match fs::read_to_string(&file) {
            Ok(saved) => parse(&saved),
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            by_address,
            file: Some(file),
            unsaved: false,
        })
    }

    /// Take the owners of `state`'s addresses. Returns the addresses whose owner changed,
    /// or that have none anymore. Addresses that just appeared aren't among them: that is
    /// every address when Portcullis starts for the first time.
    ///
    /// Docker's events of a removed container can come after a new container with its
    /// address was found: both claim the address for a while. The owner is the one the
    /// rules are applied for (see `Plan::build`): the one that isn't stopping. A container
    /// recreated in its predecessor's place takes the address over once, when it is found,
    /// and not again when the predecessor is removed: by then it may have connections of
    /// its own, made under its own rules. When more than one claimant isn't stopping,
    /// nobody owns the address, and it changes hands again when one owner is left.
    pub fn update(&mut self, state: &RuntimeState) -> HashSet<IpAddr> {
        let current = owners(state);
        let reassigned = self
            .by_address
            .iter()
            .filter(|(address, owner)| current.get(*address) != Some(*owner))
            .map(|(address, _)| *address)
            .collect();
        if current != self.by_address {
            self.by_address = current;
            self.unsaved = true;
        }
        reassigned
    }

    /// Save the owners, if they changed since they were last saved.
    pub fn save(&mut self) -> io::Result<()> {
        let Some(file) = &self.file else {
            return Ok(());
        };
        if !self.unsaved {
            return Ok(());
        }
        let temporary = file.with_extension("tmp");
        if let Some(directory) = file.parent() {
            fs::create_dir_all(directory)?;
        }
        fs::write(&temporary, render(&self.by_address))?;
        fs::rename(&temporary, file)?;
        self.unsaved = false;
        Ok(())
    }
}

fn owners(state: &RuntimeState) -> HashMap<IpAddr, Option<Owner>> {
    /// Who owns an address so far, and whether its claimants are stopping. `owner` is
    /// `None` for more than one claimant of a kind.
    struct Claim {
        owner: Option<Owner>,
        stopping: bool,
    }
    let mut claims: HashMap<IpAddr, Claim> = HashMap::new();
    for container in state.containers().values() {
        let stopping = state.is_stopping(&container.id);
        for attachment in &container.attachments {
            let owner = (container.id.clone(), attachment.mac_address);
            claims
                .entry(attachment.ip_address)
                .and_modify(|claim| {
                    if claim.owner.as_ref() == Some(&owner) {
                        return;
                    }
                    match (claim.stopping, stopping) {
                        // One that isn't stopping gets the rules over stopping ones.
                        (true, false) => {
                            claim.owner = Some(owner.clone());
                            claim.stopping = false;
                        }
                        (false, true) => {}
                        // Two of a kind: which one the rules are for isn't known.
                        _ => claim.owner = None,
                    }
                })
                .or_insert(Claim {
                    owner: Some(owner),
                    stopping,
                });
        }
    }
    claims
        .into_iter()
        .map(|(address, claim)| (address, claim.owner))
        .collect()
}

/// One line per address: the address, then the container's ID and MAC (`-` without one),
/// or `-` alone when contested.
fn render(owners: &HashMap<IpAddr, Option<Owner>>) -> String {
    let mut lines: Vec<String> = owners
        .iter()
        .map(|(address, owner)| match owner {
            Some((container, mac)) => format!(
                "{address} {container} {}",
                mac.map_or_else(|| "-".to_string(), |mac| mac.to_string())
            ),
            None => format!("{address} -"),
        })
        .collect();
    lines.sort_unstable();
    lines.push(String::new());
    lines.join("\n")
}

/// What `render` wrote; lines that don't parse are left out.
fn parse(saved: &str) -> HashMap<IpAddr, Option<Owner>> {
    saved
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?.parse().ok()?;
            let owner = match (fields.next()?, fields.next()) {
                ("-", None) => None,
                (container, Some("-")) => Some((container.to_string().into(), None)),
                (container, Some(mac)) => {
                    Some((container.to_string().into(), Some(mac.parse().ok()?)))
                }
                (_, None) => return None,
            };
            Some((address, owner))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Container, ContainerPolicy, NetworkAttachment, RuntimeState, RuntimeStateAction,
    };

    fn container(id: &str, address: &str, mac: &str) -> RuntimeStateAction {
        RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: id.to_string().into(),
                name: id.to_string().into(),
                attachments: vec![NetworkAttachment {
                    network_id: "n0".into(),
                    ip_address: address.parse().expect("address"),
                    mac_address: Some(mac.parse().expect("mac")),
                    aliases: Vec::new(),
                }],
                runtime_dns_servers: HashSet::new(),
                policy: ContainerPolicy::default(),
                sandbox: None,
            }),
        }
    }

    fn remove(id: &str) -> RuntimeStateAction {
        RuntimeStateAction::RemoveContainer {
            container_id: id.to_string().into(),
        }
    }

    fn addresses(list: &[&str]) -> HashSet<IpAddr> {
        list.iter()
            .map(|address| address.parse().expect("address"))
            .collect()
    }

    #[test]
    fn tells_addresses_that_change_hands() {
        let mut owners = Owners::default();
        let mut state = RuntimeState::default();
        state.apply_action(container("a", "172.18.0.2", "02:42:ac:12:00:02"));
        state.apply_action(container("b", "172.18.0.3", "02:42:ac:12:00:03"));
        assert_eq!(owners.update(&state), addresses(&[]));
        assert_eq!(owners.update(&state), addresses(&[]));

        state.apply_action(remove("a"));
        state.apply_action(container("c", "172.18.0.2", "02:42:ac:12:00:04"));
        assert_eq!(owners.update(&state), addresses(&["172.18.0.2"]));
        state.apply_action(remove("b"));
        assert_eq!(owners.update(&state), addresses(&["172.18.0.3"]));
    }

    fn stopping(state: &mut RuntimeState, ids: &[&str]) {
        state.set_stopping(ids.iter().map(|id| id.to_string().into()).collect());
    }

    #[test]
    fn a_recreated_container_takes_the_address_over_once() {
        let mut owners = Owners::default();
        let mut state = RuntimeState::default();
        state.apply_action(container("a", "172.18.0.2", "02:42:ac:12:00:02"));
        owners.update(&state);
        // a stops; it still owns its address.
        stopping(&mut state, &["a"]);
        assert_eq!(owners.update(&state), addresses(&[]));
        // c, recreated in its place, is found with a's address before Docker reported a
        // gone: the rules are c's from now on, and a's connections go.
        state.apply_action(container("c", "172.18.0.2", "02:42:ac:12:00:04"));
        assert_eq!(owners.update(&state), addresses(&["172.18.0.2"]));
        assert_eq!(owners.update(&state), addresses(&[]));
        // a is removed: the connections c made meanwhile stay.
        state.apply_action(remove("a"));
        stopping(&mut state, &[]);
        assert_eq!(owners.update(&state), addresses(&[]));
    }

    #[test]
    fn a_recreated_container_found_first_takes_the_address_over_once() {
        // The state yields containers in any order: the new one may come first.
        for (old, new) in [("a-old", "z-new"), ("z-old", "a-new")] {
            let mut owners = Owners::default();
            let mut state = RuntimeState::default();
            state.apply_action(container(old, "172.18.0.2", "02:42:ac:12:00:02"));
            owners.update(&state);
            stopping(&mut state, &[old]);
            state.apply_action(container(new, "172.18.0.2", "02:42:ac:12:00:04"));
            assert_eq!(owners.update(&state), addresses(&["172.18.0.2"]));
            state.apply_action(remove(old));
            stopping(&mut state, &[]);
            assert_eq!(owners.update(&state), addresses(&[]));
        }
    }

    #[test]
    fn an_address_two_running_containers_claim_changes_hands_when_claimed_and_when_settled() {
        let mut owners = Owners::default();
        let mut state = RuntimeState::default();
        state.apply_action(container("a", "172.18.0.2", "02:42:ac:12:00:02"));
        owners.update(&state);
        // c found with a's address while a's namespace is still there: which of them
        // the rules are for isn't known.
        state.apply_action(container("c", "172.18.0.2", "02:42:ac:12:00:04"));
        assert_eq!(owners.update(&state), addresses(&["172.18.0.2"]));
        // Still contested: nothing new.
        assert_eq!(owners.update(&state), addresses(&[]));
        // a stops: c's from now on, and what was made meanwhile may have been under a's
        // rules.
        stopping(&mut state, &["a"]);
        assert_eq!(owners.update(&state), addresses(&["172.18.0.2"]));
        state.apply_action(remove("a"));
        stopping(&mut state, &[]);
        assert_eq!(owners.update(&state), addresses(&[]));
    }

    #[test]
    fn an_address_of_a_removed_container_given_to_another_changes_hands() {
        let mut owners = Owners::default();
        let mut state = RuntimeState::default();
        state.apply_action(container("a", "172.18.0.2", "02:42:ac:12:00:02"));
        owners.update(&state);
        stopping(&mut state, &["a"]);
        owners.update(&state);
        state.apply_action(remove("a"));
        stopping(&mut state, &[]);
        assert_eq!(owners.update(&state), addresses(&["172.18.0.2"]));
        state.apply_action(container("c", "172.18.0.2", "02:42:ac:12:00:04"));
        assert_eq!(owners.update(&state), addresses(&[]));
    }

    #[test]
    fn remembers_owners_across_restarts() {
        let directory =
            std::env::temp_dir().join(format!("portcullis-owners-{}", std::process::id()));
        let file = directory.join("owners");
        let _ = fs::remove_file(&file);
        let mut state = RuntimeState::default();
        state.apply_action(container("a", "172.18.0.2", "02:42:ac:12:00:02"));
        state.apply_action(container("b", "172.18.0.3", "02:42:ac:12:00:03"));
        let mut owners = Owners::load(file.clone()).expect("load");
        assert_eq!(owners.update(&state), addresses(&[]));
        owners.save().expect("save");

        // While Portcullis isn't running, a is removed and c gets its address.
        state.apply_action(remove("a"));
        state.apply_action(container("c", "172.18.0.2", "02:42:ac:12:00:04"));
        let mut restarted = Owners::load(file.clone()).expect("load");
        assert_eq!(restarted.update(&state), addresses(&["172.18.0.2"]));
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn reads_what_it_wrote() {
        let mut saved = HashMap::new();
        saved.insert(
            "172.18.0.2".parse().expect("address"),
            Some((
                "a".to_string().into(),
                Some("02:42:ac:12:00:02".parse().expect("mac")),
            )),
        );
        saved.insert(
            "172.18.0.3".parse().expect("address"),
            Some(("b".to_string().into(), None)),
        );
        saved.insert("172.18.0.4".parse().expect("address"), None);
        assert_eq!(parse(&render(&saved)), saved);
        assert_eq!(
            parse("garbage\n172.18.0.5\n172.18.0.6 a zz\n"),
            HashMap::new()
        );
    }
}
