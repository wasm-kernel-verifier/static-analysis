#![feature(exitcode_exit_method)]
#![feature(iter_intersperse)]
#![feature(new_range_api)]
#![feature(range_into_bounds)]

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use foldhash::HashSet;

mod check;
mod parser;
mod sym2;
// mod sym3;
// mod symbolic;
mod typed;

#[derive(clap::Parser)]
pub struct Opts {
    /// Path to .wasm binary
    #[arg(required = true)]
    file: PathBuf,

    #[arg(long = "func", short = 'f')]
    start_from_func: Vec<String>,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .try_init()
        .unwrap();

    let opts = Opts::parse();
    if !opts.file.is_file() {
        if opts.file.exists() {
            eprintln!(
                "Path [{}] exists but is not a normal file",
                opts.file.display()
            );
        } else {
            eprintln!("Path [{}] does not exist", opts.file.display());
        }
        return ExitCode::FAILURE;
    }

    let file_contents = match std::fs::read(&opts.file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to open file [{}]: {e}", opts.file.display());
            return ExitCode::FAILURE;
        }
    };
    let file_name = opts
        .file
        .file_name()
        .unwrap()
        .to_str()
        .expect("Filename contains invalid UTF-8");

    let program = match parser::parse_wasm(&file_contents, file_name) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to parse WASM binary: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    println!("Loaded WASM binary {}", file_name);

    match sym2::execute(
        program,
        HashSet::from_iter(opts.start_from_func.into_iter()),
    ) {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("Failed to execute program: {e:?}");
        }
    }

    ExitCode::SUCCESS
}
