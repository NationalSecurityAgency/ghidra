/* ###
 * IP: BinCraft 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use clap::{Clap, AppSettings};

mod bridge;
mod cli;

#[derive(Clap)]
#[clap(version = "1.0", author = "BinCraft Team")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    /// commandline debugging mode
    #[clap(short, long)]
    cli_debug: bool
}

fn main() {

    let opts: Opts = Opts::parse();

    if opts.cli_debug {
        cli::cli_main();
    } else {
        bridge::ffi::ghidra_process_main();
    }
}
