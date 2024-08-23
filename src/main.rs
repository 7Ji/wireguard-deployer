/*
sd-networkd-wg-deployed, to generate easily deployable WireGuard configs and keys for systemd-networkd
Copyright (C) 2024-present Guoxin "7Ji" Pu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

mod error;
mod io;
mod layer;
mod wgkey;

use crate::error::{Error, Result};

#[derive(Clone, Default, clap::ValueEnum)]
enum Mode {
    #[default]
    Layer,
    Ospf,
}   

#[derive(clap::Parser)]
pub(crate) struct Arguments {
    /// The mode to run the deployer in
    #[arg(short, long, default_value_t, value_enum)]
    mode: Mode,

    /// Create a flattened config at the given path
    #[arg(short, long, default_value_t)]
    flatten: String,

    /// Cache keys as raw bytes instead of base64, saves a few bytes, useful
    /// if you don't need to check the content of keys
    #[arg(short, long, default_value_t)]
    rawkey: bool,

    /// Path to .yaml config file
    #[arg()]
    config: String,

    /// Path to folder that configs and keys shall be cached from and deployed 
    /// into 
    #[arg()]
    deploy: String,
}


fn main() -> Result<()> {
    let args: Arguments = clap::Parser::parse();
    match args.mode {
        Mode::Layer => layer::main(&args),
        Mode::Ospf => todo!(),
    }
}
