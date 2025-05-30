use crate::prelude::*;

mod crypto_auth;
use crypto_auth::crypto_auth;

#[derive(clap::Args, Clone, Debug)]
pub(crate) struct AuthArgs {
    #[command(flatten)]
    pub(crate) gas: GasArgs,
}

#[derive(clap::Subcommand, Clone, Debug)]
pub(crate) enum CryptoCommand {
    #[command(about = "Establish a secure session with a peer")]
    Auth(AuthArgs),
}

pub(crate) async fn handle(cmd: CryptoCommand) -> AnyResult<(), NexusCliError> {
    match cmd {
        CryptoCommand::Auth(args) => crypto_auth(args).await,
    }
}
