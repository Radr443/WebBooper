use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short = 'u', long = "url", help = "URL to scan")]
    pub url: Option<String>,

    #[arg(short = 'o', long = "output", help = "Save scan results to a file")]
    pub output: Option<String>,

    #[arg(long = "info", help = "Information on the tool")]
    pub info: bool,

    #[arg(long = "subdomains", help = "Only scan for subdomains")]
    pub subdomains: bool,

    #[arg(long = "webcert", help = "Retrieve web certificate information")]
    pub webcert: bool,

    #[arg(long = "upload", help = "upload your results somewhere")]
    pub upload: Option<String>,

    #[arg(long = "directory", help = "Only scan common directories")]
    pub directory: bool,
    // #[arg(short = 'v', long = "verbose", help = "detailed output whilst working!!")]
    // pub verbose: bool,
}
