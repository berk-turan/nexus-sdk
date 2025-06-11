mod network_create;

use {
    crate::{
        command_title,
        prelude::*,
        sui::{build_sui_client, create_wallet_context},
    },
    network_create::*,
};

#[derive(Subcommand)]
pub(crate) enum NetworkCommand {
    #[command(
        about = "Create a new Nexus network and assign leader caps to the provided addresses"
    )]
    Create(CreateNetwork),
}

#[derive(Args)]
struct CreateNetwork {
    /// Space separated list of addresses to assign leader caps to
    #[arg(
        long = "addresses",
        short = 'a',
        help = "Space separated list of addresses to assign leader caps to",
        num_args = 0..,
        value_name = "ADDRESSES"
    )]
    addresses: Vec<sui::ObjectID>,
    /// How many leader caps to assign to each address
    #[arg(
        long = "count-leader-caps",
        short = 'c',
        help = "How many leader caps to assign to each address",
        default_value = "5",
        value_name = "COUNT"
    )]
    count_leader_caps: u32,
    #[command(flatten)]
    gas: GasArgs,
}

/// Handle the provided network command. The [NetworkCommand] instance is passed
/// from [crate::main].
pub(crate) async fn handle(command: NetworkCommand) -> AnyResult<(), NexusCliError> {
    match command {
        // == `$ nexus network create` ==
        NetworkCommand::Create(cmd) => execute_command(cmd, false).await,
    }
}

impl Runnable for CreateNetwork {
    async fn run(
        &self,
        ctx: CliContext,
        logger: &Logger,
    ) -> AnyResult<impl Serialize, NexusCliError> {
        // Print the command title.
        logger.command_title("Create Network");

        // Confirm the action.
        logger.confirm("Are you sure you want to create a new network?");

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Notify about the success.
        logger.success("Network created successfully");

        Ok(())
    }
}

pub(crate) async fn execute_command<T: Runnable>(
    command: T,
    json: bool,
) -> AnyResult<(), NexusCliError> {
    let ctx = CliContext::new().await?;
    let logger = Logger::new(!json);

    // Run the command and print the result or the error.
    match command.run(ctx, &logger).await {
        Ok(result) => {
            if !json {
                return Ok(());
            }

            let Ok(json_string) = serde_json::to_string_pretty(&result) else {
                eprintln!(
                    "\n{ballot} Failed to serialize JSON",
                    ballot = "✖".red().bold()
                );

                std::process::exit(1);
            };

            println!("{}", json_string);
        }
        Err(e) => {
            eprintln!("\n{ballot} {e}", ballot = "✖".red().bold());

            std::process::exit(1);
        }
    };

    Ok(())
}

pub(crate) trait Runnable {
    async fn run(
        &self,
        ctx: CliContext,
        logger: &Logger,
    ) -> AnyResult<impl Serialize, NexusCliError>;
}

pub(crate) struct CliContext {
    pub(crate) sui: sui::Client,
    pub(crate) conf: CliConf,
    pub(crate) wallet: sui::WalletContext,
}

impl CliContext {
    /// Create a new CLI context with the Sui client and wallet context
    /// initialized based on the configuration loaded from the CLI configuration
    /// file.
    pub(crate) async fn new() -> AnyResult<Self, NexusCliError> {
        let conf = CliConf::load().await.map_err(NexusCliError::Any)?;
        let sui = build_sui_client(&conf.sui).await?;
        let wallet = create_wallet_context(&conf.sui.wallet_path, conf.sui.net).await?;

        Ok(Self { sui, conf, wallet })
    }

    /// Fetch the Nexus objects from the configuration and return them.
    pub(crate) async fn get_nexus_objects(&mut self) -> AnyResult<NexusObjects, NexusCliError> {
        crate::sui::get_nexus_objects(&mut self.conf).await
    }
}

pub(crate) struct Logger {
    enabled: bool,
}

impl Logger {
    pub(crate) fn new(enabled: bool) -> Self {
        // Initialize the logger here, e.g., using `env_logger` or any other logging framework
        Self { enabled }
    }

    /// Print a command title with an arrow and separator.
    pub(crate) fn command_title<T: AsRef<str>>(&self, title: T) {
        if !self.enabled {
            return;
        }

        println!(
            "\n{arrow} {title}{separator}",
            arrow = "▶".bold().purple(),
            title = title.as_ref().bold(),
            separator = crate::display::separator()
        );
    }

    /// Print a confirmation message.
    pub(crate) fn confirm<T: AsRef<str>>(&self, msg: T) {
        if !self.enabled {
            return;
        }

        use std::io::Write;

        print!(
            "[{warning}] {message} {yn}: ",
            warning = "?".bold().yellow(),
            message = msg.as_ref().bold(),
            yn = "[y/N]".truecolor(100, 100, 100)
        );

        std::io::stdout().flush().unwrap();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        if input.trim().to_lowercase() != "y" {
            std::process::exit(1);
        }
    }

    /// Notify about a successful operation.
    pub(crate) fn success<T: AsRef<str>>(&self, msg: T) {
        if !self.enabled {
            return;
        }

        println!(
            "[{check}] {msg}",
            check = "✓".green().bold(),
            msg = msg.as_ref().bold()
        );
    }

    /// Notify about an error.
    pub(crate) fn error<T: AsRef<str>>(&self, msg: T) {
        if !self.enabled {
            return;
        }

        eprintln!(
            "[{ballot}] {msg}",
            ballot = "✖".red().bold(),
            msg = msg.as_ref().bold()
        );
    }

    /// Print a list item.
    pub(crate) fn item<T: AsRef<str>>(&self, item: T) {
        if !self.enabled {
            return;
        }

        println!(
            "    {arrow} {item}",
            arrow = "▶".truecolor(100, 100, 100),
            item = item.as_ref()
        );
    }

    /// Print a loading message.
    pub(crate) fn loading<T: AsRef<str>>(&self, msg: T) -> crate::display::LoadingHandle {
        use {
            indicatif::{ProgressBar, ProgressStyle},
            std::time::Duration,
        };

        let pb = ProgressBar::new_spinner();

        if !JSON_MODE.load(std::sync::atomic::Ordering::Relaxed) {
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("[{spinner}] {msg}")
                    .unwrap(),
            );
            pb.set_message(msg.as_ref().to_owned());
            pb.enable_steady_tick(Duration::from_millis(100));
        }

        // TODO: Add enabled check to loading handle.
        crate::display::LoadingHandle::new(pb, msg.as_ref().to_owned())
    }
}
