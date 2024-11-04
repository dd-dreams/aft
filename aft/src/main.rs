//! Main.
#[cfg(feature = "clients")]
pub mod clients;
pub mod config;
pub mod constants;
pub mod errors;
#[cfg(feature = "relay")]
pub mod relay;
#[cfg(feature = "sender")]
pub mod sender;
pub mod utils;

use aft_crypto::{
    bip39,
    data::{create_128_encryptor, create_256_encryptor, Algo, SData},
    password_generator::generate_passphrase,
};
use config::Config;
use log::{error, info, Level};
use std::{env::args as args_fn, io::Write, net::{Ipv4Addr, ToSocketAddrs}};

const SENDER_MODE: u8 = 1;
const RECEIVER_MODE: u8 = 2;
const DOWNLOAD_MODE: u8 = 3;
const RELAY_MODE: u8 = 4;
const DESCR_MSG: &str = "aft - file transfer done easily";
const USAGE_MSG: &str = "Usage:
    aft sender [--address <address>] [--port <port>] [--identifier <identifier>] <filename>
    aft receiver [-p <port>]
    aft download -a <address> [-p <port>] [-i <identifier>]
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
    -v --version                Show version.
    -e --encryption ALGORITHM   Possible values: [AES128, AES256].
    -t --threads THREADS        Number of threads to use.
    -s --checksum               Check checksum at the end. Only relevant if mode == sender.";
const PASSPHRASE_DEFAULT_LEN: u8 = 6;

macro_rules! create_sender {
    ($algo:ident, $cliargs:ident, $sen_ident:expr, $addr:ident, $pass:ident) => {
        {
            let mut sender = sender::Sender::new($addr, $algo, $cliargs.checksum, $cliargs.algo);

            let init = sender.init($cliargs.filename, $sen_ident,
                    $cliargs.identifier, $pass);

            match init {
                Ok(b) => if !b {return;},
                Err(e) => {error!("{e}"); return;}
            }
            if let Err(e) = sender.send_chunks($cliargs.threads) {
                error!("Connection error: {}", e);
            }
        }
    }
}

struct CliArgs<'a> {
    mode: u8,
    address: Option<String>,
    port: u16,
    identifier: Option<&'a str>,
    verbose: u8,
    filename: &'a str,
    algo: Algo,
    threads: usize,
    pub checksum: bool,
}

impl<'a> CliArgs<'a> {
    pub fn new(mode: u8) -> Self {
        CliArgs {
            mode,
            address: None,
            port: constants::DEFAULT_PORT,
            identifier: None,
            verbose: 1,
            filename: "",
            algo: Algo::Aes128,
            // SAFETY: 4 != 0
            threads: std::thread::available_parallelism()
                .unwrap_or(std::num::NonZero::new(4).unwrap()).get(),
            checksum: false,
        }
    }

    pub fn is_relay_receiver(&self) -> bool {
        [RELAY_MODE, RECEIVER_MODE].contains(&self.mode)
    }

    pub fn is_sender(&self) -> bool {
        self.mode == SENDER_MODE
    }

    pub fn set_address(&mut self, address: String) -> bool {
        if self.mode == RELAY_MODE {
            return false;
        }
        self.address = Some(address);
        true
    }

    pub fn set_port(&mut self, port: u16) {
        self.port = port;
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

    pub fn set_algo(&mut self, algo: &str) {
        self.algo = algo.to_lowercase().as_str().into();
    }

    pub fn set_threads(&mut self, threads: usize) -> bool {
        if threads == 0 {
            return false;
        }
        self.threads = threads;
        true
    }
}

/// Checks if the terminal supports ANSI escape codes.
fn check_support_ansi() -> bool {
    if cfg!(windows) {
        if let Ok(term) = std::env::var("TERM") {
            if !term.starts_with("xterm") {
                return false;
            }
        }
    }

    // Unix machines support ANSI escape codes out of the box.
    true

}

/// Builds the logger.
fn build_logger(level: &str) {
    let env = env_logger::Env::default().default_filter_or(level);
    let mut binding = env_logger::Builder::from_env(env);
    let builder = if ["trace", "debug"].contains(&level) {
        binding.format(|buf, record| {
            let color;
            let level = record.level();
            if !check_support_ansi() {
                return writeln!(buf, "[{} {}] {}", buf.timestamp(), level, record.args());
            }
            else if level == Level::Warn {
                // Yellow color
                color = "\x1B[0;33m";
            } else if level == Level::Error {
                // Red color
                color = "\x1B[0;91m";
            } else {
                // Green color
                color = "\x1B[0;92m";
            }
            writeln!(buf, "[{} {color}{}\x1B[0;0m] {}", buf.timestamp(), level, record.args())
        })
    } else {
        binding.format(|buf, record| {
            let msg;
            let level = record.level();
            if [Level::Warn, Level::Error].contains(&level) {
                msg = if check_support_ansi() {"\x1B[0;91m[!]\x1B[0;0m"} else {"[!]"};
            } else {
                msg = if check_support_ansi() {"\x1B[0;92m[*]\x1B[0;0m"} else {"[*]"};
            }
            writeln!(buf, "{msg} {}", record.args())
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

fn create_aft_dir() -> std::io::Result<()> {
    let path = &format!("{}/{}", utils::get_home_dir(), constants::AFT_DIRNAME);
    if std::path::Path::new(path).exists() {
        return Ok(());
    }
    std::fs::create_dir(path)
}

#[cfg(feature = "relay")]
#[tokio::main]
async fn run_relay(port: u16) {
    info!("Running relay");
    relay::init(&format!("0.0.0.0:{}", port)).await.unwrap();
}

fn main() {
    let args: Vec<String> = args_fn().collect();
    if args.len() == 1 || args.len() > 9 {
        println!("{}\n\n{}\n\n{}\n{}", DESCR_MSG, USAGE_MSG, POSITIONAL_ARGS_MSG, OPTIONS_ARGS_MSG);
        return;
    }

    let mut config = Config::new(&format!("{}/{}/config", utils::get_home_dir(), constants::AFT_DIRNAME))
        .unwrap_or_default();
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

    let mut i = 2;
    while i < args.len() {
        let arg = &args[i];
        i += 1;

        match arg.as_str() {
            "-a" | "--address" => {
                if cliargs.is_relay_receiver() {
                    println!("Can't use {} argument when mode==relay | receiver", arg);
                    return;
                }

                // Remove http(s):// since aft doesn't support HTTPS.
                let no_http_addr = args[i].replace("http://", "").replace("https://", "");
                // If it's an IP
                let addr = if format!("{}:{}", no_http_addr, cliargs.port).parse::<Ipv4Addr>().is_ok() {
                    no_http_addr
                // If It's some domain or some other address
                } else {
                    match (no_http_addr, cliargs.port).to_socket_addrs() {
                        Ok(v) => v,
                        Err(_) => {
                            error!("Address is invalid.");
                            return;
                        }
                    }.next().expect("Couldn't resolve address.").ip().to_string()
                };

                cliargs.set_address(addr);
            },
            "-p" | "--port" => cliargs.set_port(if let Ok(v) = args[i].parse() {
                v
                } else {
                    println!("Not a port.");
                    return;
            }),
            "-i" | "--identifier" => {
                if cliargs.is_relay_receiver() {
                    println!("Can't use {} argument when mode==relay,receiver", arg);
                    return;
                }
                cliargs.set_identifier(&args[i]);
            },
            "-v" | "--verbose" => {
                if !cliargs.set_verbose(if let Ok(v) = args[i].parse() {
                    verbose_mode = v;
                    v
                } else {
                    println!("Invalid verbose level.");
                    return;
                }) {
                    println!("Invalid verbose level.");
                }
            },
            "-c" | "--config" => {
                config = match Config::new(&args[i]) {
                    Ok(v) => v,
                    Err(_) => {
                        println!("Invalid config location");
                        return;
                    }
                }
            },
            "-e" | "--encryption" => cliargs.set_algo(&args[i]),

            "-t" | "--threads" => if !cliargs.set_threads(args[i].parse().expect("Invalid threads input")) {
                println!("Invalid number of threads");
                return;
            },
            "-s" | "--checksum" => {
                cliargs.checksum = true;
                i -= 1;
            },
            _ => {
                if cliargs.is_sender() && i == args.len() {
                    cliargs.set_filename(&args[i-1]);
                } else {
                    println!("Unknown argument {}", arg);
                    return;
                }
            }
        }
        i += 1;
    }

    let verbose_mode = match verbose_mode {
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    build_logger(verbose_mode);
    create_aft_dir().expect("Couldn't create directory");

    if cliargs.mode == RELAY_MODE {
        #[cfg(not(feature = "relay"))]
        {
            error!("Relay is not supported for this executable.");
            return;
        }

        #[cfg(feature = "relay")]
        run_relay(cliargs.port);
    } else if cliargs.mode == RECEIVER_MODE {
        #[cfg(not(feature = "clients"))]
        {
            error!("Receiver is not supported for this executable.");
            return;
        }

        let mut pass = SData(rpassword::prompt_password("Password (press Enter to generate one): ").expect("Couldn't read password"));
        if pass.0.is_empty() {
            pass = SData(generate_passphrase(PASSPHRASE_DEFAULT_LEN));
            println!("Generated passphrase: {}", pass.0);
        }
        println!("Code: {}", generate_code_from_pub_ip());
        info!("Running receiver");

        #[cfg(feature = "clients")]
        {
            let res = match cliargs.algo {
                Algo::Aes128 =>
                    clients::Receiver::new(&format!("0.0.0.0:{}", cliargs.port), create_128_encryptor).receive(pass, cliargs.threads),
                Algo::Aes256 =>
                    clients::Receiver::new(&format!("0.0.0.0:{}", cliargs.port), create_256_encryptor).receive(pass, cliargs.threads),
                _ => {error!("Unknown encryption algorithm."); return}
            };

            match res {
                Ok(b) => if b {info!("Finished successfully.")},
                Err(e) => error!("{}", e),
            }
        }
    } else if cliargs.mode == DOWNLOAD_MODE {
        #[cfg(not(feature = "clients"))]
        {
            error!("Downloading is not supported for this executable.");
            return;
        }

        info!("Running downloader");
        let identifier = if let Some(ident) = cliargs.identifier {
            ident
        } else if let Some(ident) = config.get_identifier() {
            ident
        } else {
            error!("Identifier not set.");
            return;
        }.to_string();

        let addr = &format!("{}:{}",cliargs.address.expect("No address specified"), cliargs.port);
        #[cfg(feature = "clients")]
        {
            let res = match cliargs.algo {
                Algo::Aes128 => clients::Downloader::new(addr, identifier, create_128_encryptor).init(cliargs.threads),
                Algo::Aes256=> clients::Downloader::new(addr, identifier, create_256_encryptor).init(cliargs.threads),
                _ => {error!("Unknown encryption algorithm."); return}
            };

            match res {
                Ok(b) => if b {info!("Finished successfully.")},
                Err(e) => error!("{}", e),
            }
        }
    } else if cliargs.mode == SENDER_MODE {
        #[cfg(not(feature = "sender"))]
        {
            error!("Sending is not supported for this executable.");
            return;
        }

        info!("Running sender");
        let pass = SData(rpassword::prompt_password("Password: ").expect("Couldn't read password"));
        let addr = match cliargs.address {
            Some(ip) => ip.to_string(),
            None => {
                let codes = utils::get_input("Code: ").expect("Coudln't read codes");
                get_ip_from_code(&codes)
            }
        };
        let addr = &format!("{}:{}", &addr, cliargs.port);

        #[cfg(feature = "sender")]
        match cliargs.algo {
            Algo::Aes128 => create_sender!(
                create_128_encryptor,
                cliargs,
                config.get_identifier().unwrap_or(&String::new()),
                addr, pass
                ),
            Algo::Aes256 => create_sender!(
                create_256_encryptor,
                cliargs,
                config.get_identifier().unwrap_or(&String::new()),
                addr, pass
                ),
            _ => {error!("Unknown encryption algorithm."); return}
        }
    } else {
        error!("Unknown mode.");
    }
}
