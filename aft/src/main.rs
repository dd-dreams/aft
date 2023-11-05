//! Main.
pub mod clients;
pub mod config;
pub mod constants;
pub mod errors;
pub mod sender;
pub mod relay;
pub mod utils;

use aft_crypto::{
    bip39,
    data::{create_128_encryptor, Aes128Gcm, SData},
};
use config::Config;
use env_logger::{self, fmt::Color};
use log::{error, info, Level};
use sender::Sender;
use std::{env::args as args_fn, io::Write};

const SENDER_MODE: u8 = 1;
const RECEIVER_MODE: u8 = 2;
const DOWNLOAD_MODE: u8 = 3;
const RELAY_MODE: u8 = 4;
const DEFAULT_PORT: u16 = 1122;
const DESCR_MSG: &str = "aft - file transfer done easily";
const USAGE_MSG: &str = "Usage:
    aft sender [--address <address>] [--port <port>] <filename>
    aft receiver [-p <port>]
    aft download -a <address> [-p <port>]
    aft relay [-p <port>]
    aft <mode> [options ...]";
const POSITIONAL_ARGS_MSG: &str = "Positional arguments:
    mode
    ";
const OPTIONS_ARGS_MSG: &str = "Optional arguments:
    -a --address ADDRESS        Address.
    -p --port PORT              Port.
    -i --identifier IDENTIFIER  Identifier to find the receiver. Used only when its not P2P.
    -v --verbose VERBOSE        Verbose level. Default is 1 (warnings only). Range 1-3.
    -c --config CONFIG          Config location.
    -v --version                Show version.";

struct CliArgs<'a> {
    mode: u8,
    address: Option<&'a str>,
    port: u16,
    identifier: Option<&'a str>,
    verbose: u8,
    filename: &'a str,
}

impl<'a> CliArgs<'a> {
    pub fn new(mode: u8) -> Self {
        CliArgs {
            mode,
            address: None,
            port: DEFAULT_PORT,
            identifier: None,
            verbose: 1,
            filename: "",
        }
    }

    pub fn is_relay_receiver(&self) -> bool {
        [RELAY_MODE, RECEIVER_MODE].contains(&self.mode)
    }

    pub fn is_sender(&self) -> bool {
        self.mode == SENDER_MODE
    }

    pub fn set_address(&mut self, address: &'a str) -> bool {
        if self.mode == RELAY_MODE {
            return false;
        }
        self.address = Some(address);
        true
    }

    pub fn set_port(&mut self, port: u16) -> bool {
        self.port = port;
        true
    }

    pub fn set_identifier(&mut self, identifier: &'a str) -> bool {
        if self.mode == RELAY_MODE {
            return false;
        }
        self.identifier = Some(identifier);
        true
    }

    pub fn set_verbose(&mut self, verbose: u8) -> bool {
        if (1..=3).contains(&verbose) {
            return false;
        }
        self.verbose = verbose;
        true
    }

    pub fn set_filename(&mut self, filename: &'a str) -> bool {
        if [RELAY_MODE, DOWNLOAD_MODE, RECEIVER_MODE].contains(&self.mode) || filename.is_empty() {
            return false;
        }
        self.filename = filename;
        true
    }
}

/// Builds the logger.
fn build_logger(level: &str) {
    let env = env_logger::Env::default().default_filter_or(level);
    let mut binding = env_logger::Builder::from_env(env);
    let builder = if ["trace", "debug"].contains(&level) {
        binding.format(|buf, record| {
            let mut style = buf.style();
            let level = record.level();
            if level == Level::Warn {
                style.set_color(Color::Yellow);
            } else if level == Level::Error {
                style.set_color(Color::Red);
            } else {
                style.set_color(Color::Green);
            }
            writeln!(buf, "[{} {}] {}", buf.timestamp(), style.value(level), record.args())
        })
    } else {
        binding.format(|buf, record| {
            let mut style = buf.style();
            let level = record.level();
            if [Level::Warn, Level::Error].contains(&level) {
                style.set_color(Color::Red);
                writeln!(buf, "{} {}", style.value("[!]"), record.args())
            } else {
                style.set_color(Color::Green);
                writeln!(buf, "{} {}", style.value("[*]"), record.args())
            }
        })
    }.target(env_logger::Target::Stdout);

    builder.init();
}

/// Generates code-phrase from an IP address. This only supports IPv4 addresses.
///
/// Returns the code-phrase.
fn generate_code_from_pub_ip() -> String {
    let pub_ip = utils::get_pub_ip().expect("Couldn't get public IP address");
    let octets = utils::ip_to_octets(&pub_ip).map(|octet| octet as usize);
    // An octet maximum size is 256
    let wordlist = &bip39::create_wordlist()[..=255];

    let mut codes = String::new();

    for octet in octets {
        codes.push_str(wordlist[octet]);
        codes.push('-');
    }

    // Remove the last dash
    codes.pop();

    codes
}

/// Gets the IP from a generated code-phrase. Only supports IPv4 addresses.
/// Basically the reversed edition of `generate_code_from_pub_ip`.
///
/// Returns the IP.
fn get_ip_from_code(codes: &str) -> String {
    let wordlist = &bip39::create_wordlist()[..=255];

    let mut pub_ip = String::new();

    for code in codes.split('-') {
        for (i, word) in wordlist.iter().enumerate() {
            if word == &code {
                pub_ip.push_str(&i.to_string());
                pub_ip.push('.');
            }
        }
    }

    pub_ip.pop();

    pub_ip
}

/// Main CLI function.
#[tokio::main]
async fn main() {
    let args: Vec<String> = args_fn().collect();
    if args.len() == 1 || args.len() > 9 {
        println!("{}\n\n{}\n\n{}\n{}", DESCR_MSG, USAGE_MSG, POSITIONAL_ARGS_MSG, OPTIONS_ARGS_MSG);
        return;
    }

    let mut config =
        Config::new(&format!("{}/../.config", env!("CARGO_MANIFEST_DIR"))).unwrap_or_default();
    let mut verbose_mode = config.get_verbose();

    if args.len() - 1 == 1 && ["--version"].contains(&args[1].as_str()) {
        println!("aft v{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let mut cliargs = CliArgs::new(match args[1].to_lowercase().as_str() {
        "sender" => SENDER_MODE,
        "receiver" => RECEIVER_MODE,
        "download" => DOWNLOAD_MODE,
        "relay" => RELAY_MODE,
        _ => {
            println!("Invalid mode.");
            return;
        }
    });

    if !cliargs.is_relay_receiver() && args.len() < 3 {
        println!("Not enough arguments provided.");
        return;
    }

    for i in (2..args.len()).step_by(2) {
        let arg = &args[i];
        if ["--address", "-a"].contains(&arg.as_str()) {
            if cliargs.is_relay_receiver() {
                println!("Can't use {} argument when mode==relay | receiver", arg);
                return;
            }
            // TODO: add check for IP
            cliargs.set_address(&args[i + 1]);
        } else if ["--port", "-p"].contains(&arg.as_str()) {
            cliargs.set_port(if let Ok(v) = args[i + 1].parse() {
                v
            } else {
                println!("Not a port.");
                return;
            });
        } else if ["--identifier", "-i"].contains(&arg.as_str()) {
            if cliargs.is_relay_receiver() {
                println!("Can't use {} argument when mode==relay,receiver", arg);
                return;
            }
            cliargs.set_identifier(&args[i + 1]);
        } else if ["--verbose", "-v"].contains(&arg.as_str()) {
            cliargs.set_verbose(if let Ok(v) = args[i + 1].parse() {
                verbose_mode = v;
                v
            } else {
                println!("Invalid verbose level.");
                return;
            });
        } else if ["--config", "-c"].contains(&arg.as_str()) {
            config = match Config::new(&args[i + 1]) {
                Ok(v) => v,
                Err(_) => {
                    println!("Invalid config location");
                    return;
                }
            }
        } else if cliargs.is_sender() && i == args.len() - 1 {
            cliargs.set_filename(args.last().expect("No filename provided."));
        } else {
            println!("Unknown argument {}", arg);
            return;
        }
    }

    let verbose_mode = match verbose_mode {
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    build_logger(verbose_mode);

    if cliargs.mode == RELAY_MODE {
        info!("Running relay");
        relay::init(&format!("0.0.0.0:{}", cliargs.port)).await.unwrap();
    } else if cliargs.mode == RECEIVER_MODE {
        let pass = SData(rpassword::prompt_password("Password: ").expect("Couldn't read password"));
        println!("Code: {}", generate_code_from_pub_ip());
        info!("Running receiver");

        let mut receiver =
            clients::Receiver::new(&format!("0.0.0.0:{}", cliargs.port), create_128_encryptor);

        receiver.receive(pass).expect("Something went wrong");
    } else if cliargs.mode == DOWNLOAD_MODE {
        info!("Running downloader");
        let identifier = config.get_identifier();
        if identifier.is_none() {
            error!("Identifier not set.");
            return;
        }

        let mut downloader = clients::Downloader::<Aes128Gcm>::new(
            &format!(
                "{}:{}",
                cliargs.address.expect("No address specified"),
                cliargs.port
            ),
            identifier.unwrap().to_string(),
            create_128_encryptor,
        );

        downloader.init().expect("There was an error with the relay server.");
    } else if cliargs.mode == SENDER_MODE {
        info!("Running sender");
        let pass = SData(rpassword::prompt_password("Password: ").expect("Couldn't read password"));
        let addr = match cliargs.address {
            Some(ip) => ip.to_string(),
            None => {
                let codes = utils::get_input("Code: ").expect("Coudln't read codes");
                get_ip_from_code(&codes)
            }
        };
        let mut c = Sender::new( &format!("{}:{}", &addr, cliargs.port), create_128_encryptor);

        if c.init(cliargs.filename, config.get_identifier().expect("Identifier isn't present"),
                cliargs.identifier, pass,).unwrap() && c.send_chunks().is_err() {
            error!("\nCan't reach relay.");
        }
    } else {
        error!("Unknown mode.");
    }
}
