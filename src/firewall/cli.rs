use std::io::Write as _;
use std::process::{Command, Stdio};

use tracing::{debug, trace};

use super::{FirewallError, NftRunner, split_nft_commands};

pub struct CommandNftRunner;

impl NftRunner for CommandNftRunner {
    fn run_script(&self, script: &str) -> Result<(), FirewallError> {
        trace!(script = %script, "executing nft script via cli");
        for command in split_nft_commands(script) {
            debug!(program = "nft", command = %command, "executing firewall command");
        }
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;

        let mut stdin = child.stdin.take().ok_or(FirewallError::MissingStdin)?;
        stdin
            .write_all(script.as_bytes())
            .map_err(|error| FirewallError::StdinWrite(error.to_string()))?;
        drop(stdin);

        let output = child
            .wait_with_output()
            .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;

        if output.status.success() {
            trace!("nft cli script executed successfully");
            return Ok(());
        }

        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        debug!(code, stderr = %stderr, "nft cli script execution failed");
        Err(FirewallError::CommandFailure { code, stderr })
    }
}
