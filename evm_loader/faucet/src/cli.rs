//! Faucet options parser.

use crate::config;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(about = "NeonLabs Token Faucet Service")]
pub struct Application {
    #[structopt(
        parse(from_os_str),
        short,
        long,
        default_value = &config::DEFAULT_CONFIG,
        help = "Path to the config file"
    )]
    pub config: PathBuf,

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    #[structopt(about = "Shows config")]
    Config {
        #[structopt(
            parse(from_os_str),
            short,
            long,
            default_value = &config::DEFAULT_CONFIG,
            help = "Path to the config file"
        )]
        file: PathBuf,
    },

    #[structopt(about = "Shows environment variables")]
    Env {},

    #[structopt(about = "Starts listening for requests")]
    Run {
        #[structopt(
            long,
            default_value = &config::AUTO,
            help = "Number of listening workers"
        )]
        workers: String,
    },
}

/// Constructs instance of Application.
pub fn application() -> Application {
    Application::from_args()
}
