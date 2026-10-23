use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(about = "An A4A protocol relay node written in Rust", author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"))]
pub struct CLIArgs {
    #[arg(
        long,
        help = "Check the local HTTP health endpoint and exit",
        default_value_t = false
    )]
    pub healthcheck: bool,
    #[arg(
        long,
        help = "Literal socket address used by --healthcheck",
        default_value = "127.0.0.1:8080"
    )]
    pub healthcheck_address: SocketAddr,
    #[arg(
        short,
        long,
        help = "Use the <directory> as the location of the database",
        required = false
    )]
    pub db: Option<String>,
    #[arg(
        short,
        long,
        help = "Use the <file name> as the location of the config file",
        required = false
    )]
    pub config: Option<String>,
}
