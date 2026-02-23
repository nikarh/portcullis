use tracing::{error, info};

fn main() {
    if let Err(error) = portcullis::logging::init_logging() {
        error!(%error, "failed to initialize logging");
        std::process::exit(1);
    }

    info!("portcullis prototype started");
}
