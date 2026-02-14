#![feature(exitcode_exit_method)]

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;

mod parser;
mod symbolic;

#[derive(clap::Parser)]
pub struct Opts {
    /// Path to .wasm binary
    #[arg(required = true)]
    file: PathBuf,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt::init();

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

    let () = symbolic::execute(program);

    ExitCode::SUCCESS
}
