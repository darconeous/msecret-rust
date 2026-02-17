// MSecret
//
// Copyright 2023 Robert Quattlebaum
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate num_bigint_dig as num_bigint;

use std::io::{stdout, IsTerminal, Write};
use std::process::exit;

use anyhow::{bail, ensure, Error};
use clap::Parser;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::line_buffer::LineBuffer;
use rustyline::{Changeset, Context, Editor};

use command::Command;
use msecret::*;

mod bin_format;
mod command;

#[cfg(test)]
mod tests;

#[derive(
    Debug,
    Parser,
    rustyline::Helper,
    rustyline::Highlighter,
    rustyline::Hinter,
    rustyline::Validator,
)]
#[command(name = "msecret")]
#[command(about = "A tool for deriving cryptographic secrets", long_about = None)]
pub struct ToolArgs {
    /// Filename to load the initial secret from.
    #[arg(short = 'f', long, value_name = "FILENAME")]
    pub secret_file: Option<String>,

    /// Initial secret specified on the command line. (WARNING: NOT SECURE)
    #[arg(short, long, value_name = "HEX-SECRET")]
    pub secret: Option<Secret>,

    /// Initial secret is randomly generated.
    #[arg(long)]
    pub rand_secret: bool,

    /// Initial secret is generated from a passphrase read in from stdin.
    /// Optionally specify a SECRET_ID to verify the derived secret instead of
    /// asking for the passphrase twice. Up to three attempts are allowed.
    #[arg(long, num_args(0..=1), require_equals = true, value_name = "SECRET_ID")]
    pub passphrase: Option<Option<SecretId>>,

    /// Initial keypath, like `/1/CA/com.example/sig`
    #[arg(value_name = "KEYPATH")]
    #[arg(short, long)]
    pub keypath: Option<String>,

    /// Command to perform.
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Completer for ToolArgs {
    type Candidate = Pair;

    //#[cfg(!complete)]
    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let _ = (line, pos, ctx);
        Ok((0, Vec::with_capacity(0)))
    }

    // #[cfg(complete)]
    // fn complete(&self, line: &str, pos: usize, ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
    //     // TODO: Writeme!
    //     let mut cmd = Self::command();
    //     let mut tokens = match shellwords::split(line) {
    //         Ok(mut args) => {
    //             args.insert(0, cmd.get_name().to_string());
    //             args.into_iter()
    //         },
    //         Err(_) => {
    //             eprintln!("tab: Can't split");
    //             return Ok((0, vec![]));
    //         }
    //     };
    //
    //     let mut last_token = String::from(tokens.next_back().unwrap());
    //
    //     for tok in tokens {
    //         let next_cmd = cmd.find_subcommand(tok);
    //         if next_cmd.is_none() {
    //             eprintln!("tab: next_cmd.is_none");
    //             return Ok((pos, vec![]));
    //         }
    //         cmd = next_cmd.unwrap().clone();
    //     }
    //
    //     let candidates: Vec<String> = cmd
    //         .completions
    //         .to_vec()
    //         .into_iter()
    //         .filter(|x| x.starts_with(&last_token))
    //         .collect();
    //     Ok((
    //         line.len() - last_token.len() - 1,
    //         candidates
    //             .iter()
    //             .map(|cmd| Pair {
    //                 display: String::from(cmd),
    //                 replacement: format!("{} ", cmd),
    //             })
    //             .collect(),
    //     ))
    // }

    fn update(&self, line: &mut LineBuffer, start: usize, elected: &str, cl: &mut Changeset) {
        // TODO: Writeme!
        let end = line.pos();
        line.replace(start..end, elected, cl);
    }
}

impl ToolArgs {
    pub fn evaluate(&self) -> Result {
        let mut tool_state = StandardToolState::default();

        self.init_tool_state(&mut tool_state)?;

        self.process(tool_state)
    }

    pub fn init_tool_state<T: AsMut<S>, S: ToolState>(&self, mut tool_state: T) -> Result {
        let tool_state = tool_state.as_mut();

        if let Some(secret) = self.secret.as_ref().map(Secret::clone) {
            ensure!(
                self.secret_file.is_none(),
                "Can't specify both --secret and --secret-file at same time!"
            );
            ensure!(
                !self.rand_secret,
                "Can't specify both --secret and --rand-secret at same time!"
            );
            ensure!(
                self.passphrase.is_none(),
                "Can't specify both --secret and --passphrase at same time!"
            );
            tool_state.import_root(&secret)?;
        } else if let Some(secret_file) = self.secret_file.as_ref().map(String::clone) {
            ensure!(
                !self.rand_secret,
                "Can't specify both --secret-file and --rand-secret at same time!"
            );
            ensure!(
                self.passphrase.is_none(),
                "Can't specify both --secret-file and --passphrase at same time!"
            );
            tool_state.load(secret_file.as_ref())?;
        } else if self.rand_secret {
            ensure!(
                self.passphrase.is_none(),
                "Can't specify both --rand-secret and --passphrase at same time!"
            );
            tool_state.generate()?;
        } else if let Some(passphrase_secret_id) = self.passphrase.as_ref() {
            if let Some(expected_id) = passphrase_secret_id {
                // Secret ID provided: verify instead of asking twice, up to 3 attempts.
                let mut imported = false;
                for attempt in 0..3usize {
                    let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
                    ensure!(!passphrase.is_empty(), "Passphrase was empty.");
                    let secret = Secret::from_passphrase(&passphrase);
                    if secret.id() == *expected_id {
                        tool_state.import_root(&secret)?;
                        imported = true;
                        break;
                    }
                    eprintln!(
                        "Passphrase produces secret ID {}, expected {}.",
                        secret.id(),
                        expected_id
                    );
                    if attempt == 2 {
                        bail!("Too many incorrect passphrase attempts");
                    }
                }
                if !imported {
                    bail!("Too many incorrect passphrase attempts");
                }
            } else {
                // No secret ID: ask twice to confirm.
                let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
                ensure!(!passphrase.is_empty(), "Passphrase was empty.");
                let passphrase_check = rpassword::prompt_password("Verify passphrase: ")?;
                ensure!(passphrase == passphrase_check, "Passphrases do not match.");
                tool_state.import_root(&Secret::from_passphrase(passphrase))?;
            }
            eprintln!("Imported {}", tool_state.current_secret()?.id());
        }

        if let Some(keypath) = self.keypath.as_ref() {
            tool_state.update_keypath(keypath)?;
        }

        Ok(())
    }

    pub fn process_line<T: AsMut<S>, S: ToolState, W: Write>(
        mut tool_state: T,
        line: &str,
        out: &mut W,
    ) -> Result<bool> {
        #[derive(Debug, Parser)]
        struct CommandLine {
            #[command(subcommand)]
            command: Command,
        }

        let mut args = match shellwords::split(line) {
            Ok(args) => args,
            Err(err) => {
                eprintln!("{:?}", err);
                return Ok(true);
            }
        };

        args.insert(0, ">".to_string());

        let command = CommandLine::try_parse_from(args)?.command;

        if let &Command::Exit = &command {
            return Ok(false);
        }

        command.process(&mut tool_state, out)?;

        Ok(true)
    }

    pub fn process<T: ToolState>(&self, mut tool_state: T) -> Result<(), Error> {
        if let Some(command) = &self.command {
            command.process(&mut tool_state, &mut stdout())?;
            if stdout().is_terminal() {
                println!();
            }
        } else {
            let mut rl = Editor::<ToolArgs, rustyline::history::DefaultHistory>::new()?;

            let mut last_command_did_err = false;

            loop {
                let mut prompt = if tool_state.root_secret().is_ok() {
                    format!("{}> ", tool_state.get_keypath()?)
                } else {
                    "> ".to_string()
                };

                if last_command_did_err {
                    prompt.insert_str(0, "❌ ")
                }

                let line = rl.readline(&prompt);

                match line {
                    Ok(line) => {
                        if line.trim().is_empty() {
                            // Ignore blank lines.
                            continue;
                        }

                        rl.add_history_entry(line.as_str())?;

                        match Self::process_line(&mut tool_state, &line, &mut stdout()) {
                            Ok(true) => {
                                last_command_did_err = false;
                                if stdout().is_terminal() {
                                    println!();
                                }
                                continue;
                            }
                            Ok(false) => break,
                            Err(err) => {
                                last_command_did_err =
                                    !line.ends_with("help") && !line.starts_with("help");
                                eprintln!("{}", err);
                                continue;
                            }
                        }
                    }
                    Err(ReadlineError::Interrupted) => {
                        break;
                    }
                    Err(ReadlineError::Eof) => {
                        break;
                    }
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

fn main() {
    match ToolArgs::parse().evaluate() {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{:?}", err);
            exit(-2);
        }
    }
}
