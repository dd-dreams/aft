//! Main.
pub mod server;
pub mod sender;
pub mod utils;
pub mod errors;
pub mod constants;
pub mod config;
pub mod database;
pub mod clients;

use server::Server;
use sender::Sender;
use std::env::args as args_fn;
use std::io::Write;
use env_logger::{self, fmt::Color};
use log::{debug, error, Level};
use config::Config;
use std::env;
use aft_crypto::{data::{Aes128Gcm, create_128_encryptor},
                 bip39};

pub const SENDER_MODE: u8 = 1;
pub const RECEIVER_MODE: u8 = 2;
pub const DOWNLOAD_MODE: u8 = 3;
pub const SERVER_MODE: u8 = 4;
pub const DEFAULT_PORT: u16 = 1122;
const HELP_MSG: &str = "aft - file transfer done easily";
const USAGE_MSG: &str = "Usage:
    aft --mode sender [--address <address>] [--port <port>] <filename>
    aft -m receiver [-p <port>]
    aft -m download -a <address> [-p <port>]
    aft -m server [-p <port>]";
const OPTIONS_MSG: &str = "Options:
    -m --mode MODE              Run as `sender`, `server`, `receiver` or `download`.
    -a --address ADDRESS        Address to connect to.
    -p --port PORT              Port to host the server on.
    -i --identifier IDENTIFIER  Identifier to find the receiver. Used only when its not P2P.
    -v --verbose VERBOSE        Verbose level. Default is 1 (warnings only). Range 1-3.
    -c --config CONFIG          Config location.
    -r --register REGISTER      Register.";

struct CliArgs<'a> {
    mode: u8,
    address: Option<&'a str>,
    port: u16,
    identifier: Option<&'a str>,
    verbose: u8,
    filename: &'a str,
    pub register: bool
}

impl<'a> CliArgs<'a> {
    pub fn new(mode: u8) -> Self {
        CliArgs { mode, address: None, port: DEFAULT_PORT, identifier: None, verbose: 1, filename: "", register: false}
    }

    pub fn is_server_receiver(&self) -> bool {
        ![SENDER_MODE, DOWNLOAD_MODE].contains(&self.mode)
    }

    pub fn is_sender(&self) -> bool {
        self.mode == SENDER_MODE
    }

    pub fn set_address(&mut self, address: &'a str) -> bool {
        if self.mode == SERVER_MODE {
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
        if self.mode == SERVER_MODE {
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
        if [SERVER_MODE, DOWNLOAD_MODE, RECEIVER_MODE].contains(&self.mode) {
            return false;
        }
        self.filename = filename;
        true
    }
}

/// Builds the logger.
fn build_logger(level: &str) {
    let env = env_logger::Env::default().default_filter_or(level);
    env_logger::Builder::from_env(env)
        .target(env_logger::Target::Stdout)
        .format(|buf, record| {
            let mut style = buf.style();
            let level = record.level();
            if level == Level::Warn {
                style.set_color(Color::Yellow);
            } else if level == Level::Error {
                style.set_color(Color::Red);
            } else {
                style.set_color(Color::Green);
            }
            writeln!(buf, "[{} {}] {}", buf.timestamp(), style.value(record.level()), record.args())
        })
        .init();
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

/// Gets the IP from a generates code-phrase. Only supports IPv4 addresses.
/// Basically the reversed edition of `generate_code_from_pub_ip`.
///
/// Returns the IP.
fn get_ip_from_code(codes: &str) -> String {
    let wordlist = &bip39::create_wordlist()[..=255];

    let mut pub_ip = String::new();

    for code in codes.split('-') {
        for i in 0..wordlist.len() {
            if wordlist[i] == code {
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
    if args.len() == 1 || args.len() > 11 {
        println!("{}\n\n{}\n\n{}", HELP_MSG, USAGE_MSG, OPTIONS_MSG);
        return;
    }

    let mut config = Config::new(&format!("{}/../.config", env!("CARGO_MANIFEST_DIR"))).unwrap_or_default();
    let mut verbose_mode = config.get_verbose();

    let mut cliargs = CliArgs::new(config.get_mode());
    // 1 to skip executable name
    let mut index = 1;

    while index < args.len() {
        // The filename.
        let arg = &args[index];
        if ["--mode", "-m"].contains(&arg.to_lowercase().as_str()) {
            cliargs = CliArgs::new(match args[index+1].to_lowercase().as_str() {
                "sender" => SENDER_MODE,
                "receiver" => RECEIVER_MODE,
                "download" => DOWNLOAD_MODE,
                "server" => SERVER_MODE,
                _ => {println!("Invalid mode."); return;}
            })
        }
        else if ["--address", "-a"].contains(&arg.to_lowercase().as_str()) {
            if cliargs.is_server_receiver() {
                println!("Can't use {} argument when mode==server,receiver", arg);
                return;
            }
            // TODO: add check for IP
            cliargs.set_address(&args[index+1]);
        }
        else if ["--port", "-p"].contains(&arg.to_lowercase().as_str()) {
            cliargs.set_port(if let Ok(v) = args[index+1].parse() {
                v
            } else {
                println!("Not a port.");
                return;
            });
        }
        else if ["--identifier", "-i"].contains(&arg.to_lowercase().as_str()) {
            if cliargs.is_server_receiver() {
                println!("Can't use {} argument when mode==server,receiver", arg);
                return;
            }
            cliargs.set_identifier(&args[index+1]);
        }
        else if ["--verbose", "-v"].contains(&arg.to_lowercase().as_str()) {
            cliargs.set_verbose(if let Ok(v) = args[index+1].parse() {
                verbose_mode = v;
                v
            } else {
                println!("Invalid verbose level.");
                return;
            });
        }
        else if ["--register", "-r"].contains(&arg.to_lowercase().as_str()) {
            if cliargs.is_sender() {
                println!("Can't use {} argument when mode==sender", arg);
                return;
            }
            cliargs.register = true;
            index -= 1;
        } else if ["--config", "-c"].contains(&arg.to_lowercase().as_str()) {
            config = match Config::new(&args[index+1]) {
                Ok(v) => v,
                Err(_) => {println!("Invalid config location"); return;}
            }
        } else if index+1 == args.len() {
            if !cliargs.set_filename(&args[index]) {
                println!("A filename is only passed when using sender mode");
                return;
            }
        } else {
            println!("Unknown argument {}", arg);
            return;
        }
        index += 2;
    }

    let verbose_mode = match verbose_mode {
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace"
    };
    build_logger(verbose_mode);

    if cliargs.mode == SERVER_MODE {
        debug!("Running server");
        // Not recommended using `PGPASSWORD` env var for security reasons (some OS's allow
        // non-root users to see env vars of other users). Recommended only when this program is
        // sandboxed in some way (docker or other).
        // TODO?
        let pass = env::var("PGPASSWORD").expect("Invalid PGPASSWORD environment variable.");
        let user = env::var("PGUSER").expect("Invalid PGUSER environment variable.");
        server::init(
            Server::new(cliargs.port, &user, &pass
                ).await).await.unwrap();
    }
    else if cliargs.mode == RECEIVER_MODE {
        let pass = rpassword::prompt_password("Password: ").expect("Couldn't read password");
        println!("Code: {}", generate_code_from_pub_ip());
        debug!("Running receiver");

        let mut receiver = clients::Receiver::new(&format!("0.0.0.0:{}", cliargs.port), create_128_encryptor);

        receiver.receive(&pass).expect("Something went wrong");
    }
    else if cliargs.mode == DOWNLOAD_MODE {
        debug!("Running downloader");
        let identifier = config.get_identifier();
        if identifier.is_none() {
            error!("Identifier not set.");
            return;
        }
        let mut downloader = clients::Downloader::<Aes128Gcm>::new(
            &format!("{}:{}", cliargs.address.expect("No address specified"), cliargs.port),
            identifier.unwrap().to_string(), create_128_encryptor);

        let mut pass = rpassword::prompt_password("Password: ").expect("Couldn't read password");

        downloader.init(cliargs.register, &mut pass).expect("There was an error with the server.");
    }
    else if cliargs.mode == SENDER_MODE {
        debug!("Running sender");
        let pass = rpassword::prompt_password("Password: ").expect("Couldn't read password");
        let addr = match cliargs.address {
            Some(ip) => ip.to_string(),
            None => {
                let codes = utils::get_input("Code: ").expect("Coudln't read codes");
                get_ip_from_code(&codes)
            }
        };
        let mut c = Sender::new(
            &format!("{}:{}", &addr, cliargs.port),
            config.get_identifier().expect("No identifier set.").clone(), create_128_encryptor);

        if !c.init_send(cliargs.filename, config.get_identifier().expect("Identifier isn't present"), cliargs.identifier, &pass).unwrap() {
            return;
        }

        if c.send_chunks().is_err() {
            println!("\nCan't reach server.");
        }
    }
    else {
        println!("Unknown mode.");
    }
}
