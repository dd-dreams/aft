//! Handles the config file.
use crate::{errors::ErrorsConfig, utils::error_other};
use log::error;
use std::{fs::File, io, io::prelude::*, path::Path};

const VERBOSE_OPTION: &str = "verbose";
const IDENTIFIER_OPTION: &str = "identifier";
const MODE_OPTION: &str = "mode";
const DELIMITER: &str = "=";
const OPTIONS: [&str; 3] = [VERBOSE_OPTION, IDENTIFIER_OPTION, MODE_OPTION];

enum Options {
    Verbose(u8),
    Identifier(String),
    DefaultMode(u8),
    None,
}

pub struct Config {
    verbose: Options,
    identifier: Options,
}

impl Config {
    /// Builds a new config object.
    pub fn new(path: &str) -> io::Result<Self> {
        let path = Path::new(path);
        if !path.is_dir() {
            let mut config = String::new();
            File::open(path)?.read_to_string(&mut config)?;
            return Config::generate_config(config);
        }
        Ok(Config::default())
    }

    fn generate_config(content: String) -> io::Result<Config> {
        let mut verbose = Options::None;
        let mut identifier = Options::None;
        let mut mode = Options::None;

        for (index, line) in content.lines().enumerate() {
            let line_splitted: Vec<&str> = line.split(DELIMITER).collect();
            // "option = value"
            if line_splitted.len() != 2 || !OPTIONS.contains(&line_splitted[0]) {
                error!("Bad syntax, line: {}", index);
                return Err(error_other!(ErrorsConfig::WrongSyntax));
            }

            match line_splitted[0].to_lowercase().as_str().trim() {
                VERBOSE_OPTION => {
                    if let Options::None = verbose {
                        let value = Config::get_char_val(&line_splitted, index)?;
                        if value > '0' && value < '3' {
                            // safe to unwrap because we checked if its a digit or not
                            verbose = Options::Verbose(value.to_digit(10).unwrap() as u8);
                        }
                    } else {
                        error!("Already assigned a value, line: {}", index);
                        return Err(error_other!(ErrorsConfig::WrongSyntax));
                    }
                }
                IDENTIFIER_OPTION => {
                    if let Options::None = identifier {
                        identifier = Options::Identifier(line_splitted[1].to_string());
                    } else {
                        error!("Already assigned a value, line: {}", index);
                        return Err(error_other!(ErrorsConfig::WrongSyntax));
                    }
                }
                MODE_OPTION => {
                    if let Options::None = mode {
                        let value = Config::get_char_val(&line_splitted, index)?;
                        // modes: 1=client, 2=receiver, 3=download and 4=relay.
                        if value > '0' && value < '5' {
                            // safe to unwrap because we checked if its a digit or not
                            mode = Options::DefaultMode(value.to_digit(10).unwrap() as u8);
                        }
                    } else {
                        error!("Already assigned a value, line: {}", index);
                        return Err(error_other!(ErrorsConfig::WrongSyntax));
                    }
                }
                _ => {
                    error!("No such option, line: {}", index);
                    return Err(error_other!(ErrorsConfig::NoOption));
                }
            }
        }

        Ok(Config {
            verbose,
            identifier,
        })
    }

    fn get_char_val(tokens: &[&str], index: usize) -> io::Result<char> {
        let value = tokens[1].trim().chars().next();
        if value.is_none() {
            error!("Bad syntax, line: {}", index);
            return Err(error_other!(ErrorsConfig::WrongSyntax));
        }
        Ok(value.unwrap())
    }

    /// Returns verbose number if set, else, returns 0 (info only).
    pub fn get_verbose(&self) -> u8 {
        if let Options::Verbose(val) = self.verbose {
            val
        } else {
            // info only
            3
        }
    }

    /// Returns the identifier if set, else, returns None.
    pub fn get_identifier(&self) -> Option<&String> {
        if let Options::Identifier(val) = &self.identifier {
            Some(val)
        } else {
            None
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            verbose: Options::None,
            identifier: Options::None,
        }
    }
}
