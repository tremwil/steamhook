use std::{error::Error, fs, path::PathBuf};

use clap::{value_parser, Arg, Command};
use patterns::PatternRVAs;
use pelite::pe32::PeFile;

mod patterns;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = Command::new("steamhook-analysis")
        .about("Extract IPC call information from the steamclient binary")
        .arg(
            Arg::new("steamclient_path")
                .required(true)
                .value_parser(value_parser!(PathBuf))
                .help("Path to the 32-bit steamclient DLL to run analysis on."),
        )
        .get_matches();

    let path = matches.get_one::<PathBuf>("steamclient_path").unwrap();
    let client_bytes = fs::read(path)?;
    let pe = PeFile::from_bytes(&client_bytes)?;

    let patterns = PatternRVAs::new(&pe);
    println!("{:#?}", patterns);

    Ok(())
}
