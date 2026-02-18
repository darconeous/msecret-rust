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

/// Wrapper used to parse REPL lines via clap and to build the completion command tree.
#[derive(Debug, Parser)]
struct ReplCommandLine {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
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

/// Zero-sized rustyline helper that provides tab completion for the interactive REPL.
#[derive(rustyline::Helper, rustyline::Hinter, rustyline::Highlighter, rustyline::Validator)]
struct ReplHelper;

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        use clap::CommandFactory;

        let line_to_cursor = &line[..pos];

        // Tokenize up to the cursor; bail out gracefully on parse errors (e.g. unclosed quotes).
        let mut tokens = match shellwords::split(line_to_cursor) {
            Ok(t) => t,
            Err(_) => return Ok((pos, vec![])),
        };

        // Separate the partial word being typed from the already-completed tokens.
        let (partial, complete_start) =
            if !line_to_cursor.ends_with(|c: char| c.is_whitespace()) && !tokens.is_empty() {
                let partial = tokens.pop().unwrap();
                let start = pos - partial.len();
                (partial, start)
            } else {
                (String::new(), pos)
            };

        // Walk the command tree with the "done" tokens, tracking state.
        let mut cmd = ReplCommandLine::command();
        let mut cmd_names: Vec<String> = vec![];
        let mut positional_index: usize = 0;
        let mut expect_value_for: Option<String> = None;

        for token in &tokens {
            if expect_value_for.take().is_some() {
                // This token is the value consumed by the previous flag; skip tree navigation.
                continue;
            }

            if token.starts_with('-') {
                // Flag token — determine if the next token will be its value.
                let flag_name = token.trim_start_matches('-');
                if let Some(arg) = cmd.get_arguments().find(|a| {
                    a.get_long() == Some(flag_name)
                        || a.get_short()
                            .map(|c| c.to_string() == flag_name)
                            .unwrap_or(false)
                }) {
                    if flag_takes_value(arg) {
                        expect_value_for = Some(flag_name.to_string());
                    }
                }
            } else if let Some(sub) = cmd.find_subcommand(token) {
                // Descend into subcommand; record the canonical name.
                let name = sub.get_name().to_string();
                cmd = sub.clone();
                cmd_names.push(name);
                positional_index = 0;
            } else {
                // Positional argument value — advance the index.
                positional_index += 1;
            }
        }

        // Collect the candidate completion strings.
        let candidates: Vec<String> = if let Some(flag_name) = expect_value_for {
            // The last done token was a value-taking flag; complete with its possible values.
            cmd.get_arguments()
                .find(|a| a.get_long() == Some(flag_name.as_str()))
                .map(|a| {
                    a.get_possible_values()
                        .iter()
                        .map(|v| v.get_name().to_string())
                        .collect()
                })
                .unwrap_or_default()
        } else if partial.starts_with('-') {
            // User is typing a flag; offer --long-flag names.
            cmd.get_arguments()
                .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
                .collect()
        } else if is_ecc_curve_position(&cmd_names, positional_index) {
            // First positional arg of an ecc subcommand — offer the runtime curve list.
            ecc_curve_completions()
        } else {
            // Default: offer subcommand names and their aliases.
            cmd.get_subcommands()
                .flat_map(|sub| {
                    std::iter::once(sub.get_name().to_string())
                        .chain(sub.get_all_aliases().map(str::to_string))
                })
                .collect()
        };

        // Filter by prefix and wrap in Pairs.
        let pairs: Vec<Pair> = candidates
            .into_iter()
            .filter(|c| c.starts_with(&partial))
            .map(|c| Pair {
                display: c.clone(),
                replacement: format!("{c} "),
            })
            .collect();

        Ok((complete_start, pairs))
    }

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
        let mut args = match shellwords::split(line) {
            Ok(args) => args,
            Err(err) => {
                eprintln!("{:?}", err);
                return Ok(true);
            }
        };

        args.insert(0, ">".to_string());

        let command = ReplCommandLine::try_parse_from(args)?.command;

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
            let mut rl = Editor::<ReplHelper, rustyline::history::DefaultHistory>::new()?;
            rl.set_helper(Some(ReplHelper));

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

/// Returns true when the argument at `positional_index` inside the given command path is the
/// `curve` positional arg of an `ecc` subcommand (public/private/sign/verify).
fn is_ecc_curve_position(cmd_names: &[String], positional_index: usize) -> bool {
    if positional_index != 0 {
        return false;
    }
    let n = cmd_names.len();
    if n >= 2
        && cmd_names[n - 2] == "ecc"
        && matches!(
            cmd_names[n - 1].as_str(),
            "sign" | "public" | "private" | "verify"
        )
    {
        return true;
    }
    // apple-ctk-export ecc <CURVE>
    #[cfg(all(target_os = "macos", feature = "asf"))]
    if n >= 2 && cmd_names[n - 2] == "apple-ctk-export" && cmd_names[n - 1] == "ecc" {
        return true;
    }
    false
}

/// Returns the list of supported ECC curve names, mirroring the output of `ecc list`.
fn ecc_curve_completions() -> Vec<String> {
    let mut curves = vec![
        "ed25519".to_string(),
        "x25519".to_string(),
        // Shorthand aliases accepted by ec_group_from_str
        "p256".to_string(),
        "p384".to_string(),
        "p521".to_string(),
    ];
    #[cfg(feature = "openssl")]
    {
        use openssl::{ec::EcGroup, nid::Nid};
        for i in 0..32000i32 {
            let nid = Nid::from_raw(i);
            if EcGroup::from_curve_name(nid).is_ok() {
                if let Ok(name) = nid.short_name() {
                    curves.push(name.to_string());
                }
            }
        }
    }
    curves
}

/// Returns true if a clap Arg consumes the next token as its value.
fn flag_takes_value(arg: &clap::Arg) -> bool {
    use clap::ArgAction;
    matches!(arg.get_action(), ArgAction::Set | ArgAction::Append)
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
