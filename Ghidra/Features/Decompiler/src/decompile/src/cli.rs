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
use crate::bridge::ffi;
use anyhow;
use cxx::UniquePtr;
use easy_repl::{command, CommandStatus, Repl};
use std::{
    collections::HashMap,
    env::{self},
    pin::Pin,
};

struct CliContext {
    status: UniquePtr<ffi::IfaceStatus>,
    data_map: HashMap<String, *mut ffi::IfaceData>,
    interface_cmds: HashMap<String, UniquePtr<ffi::IfaceCommand>>,
}

impl CliContext {
    fn new() -> Self {
        let mut ctx = Self {
            status: ffi::new_iface_status_stub(),
            data_map: HashMap::new(),
            interface_cmds: HashMap::new(),
        };

        ctx.register_command("load-file", ffi::new_load_file_command());
        ctx.register_command("add-path", ffi::new_add_path_command());
        ctx.register_command("save", ffi::new_save_command());
        ctx.register_command("restore", ffi::new_restore_command());

        ctx.register_command("decompile", ffi::new_decompile_command());
        ctx.register_command("print-raw", ffi::new_print_raw_command());
        ctx.register_command("print-c", ffi::new_print_c_command());

        ctx
    }

    fn command(&mut self, name: &str) -> Pin<&mut ffi::IfaceCommand> {
        self.interface_cmds.get_mut(name).unwrap().as_mut().unwrap()
    }

    fn register_command(&mut self, name: &str, mut command: UniquePtr<ffi::IfaceCommand>) {
        let entry = self
            .data_map
            .entry(command.as_mut().unwrap().getModuleRust().to_string())
            .or_insert(command.as_mut().unwrap().createData());
        unsafe {
            command
                .as_mut()
                .unwrap()
                .setData(self.status.as_mut().unwrap().get_unchecked_mut() as *mut ffi::IfaceStatus, *entry);
        }
        self.interface_cmds.insert(name.to_string(), command);
    }
}

macro_rules! call_cmd {
    ($cmd:ident, $($arg:ident),*) => {
        let mut v = vec![];
        $(
            v.push($arg.to_string());
        )*
        let s = v.join(" ");
        unsafe { ffi::call_cmd($cmd, &s) };
    };
}

fn init_decompiler(sleigh_home: Option<String>) {
    let ghidra_root = if let Some(ghidra_root) = sleigh_home {
        ghidra_root
    } else {
        let ghidra_root = match env::var("SLEIGHHOME") {
            Ok(v) => v,
            _ => panic!("SLEIGHHOME not set to ghidra install"),
        };
        ghidra_root
    };

    ffi::startDecompilerLibrary(&ghidra_root);
}

pub(crate) fn cli_main(sleigh_home: Option<String>) {
    init_decompiler(sleigh_home);

    let mut ctx = CliContext::new();

    let mut rl = Repl::builder()
        .prompt("\x1b[1;32mdecomp> \x1b[0m")
        .with_filename_completion(true)
        .add(
            "load-file",
            command! {
                "load the binary into cli",
                (filename: String) => |filename: String| {
                    let cmd = ctx.command("load-file");
                    call_cmd!(cmd, filename);
                    Ok(CommandStatus::Done)
                }
            },
        )
        .build()
        .expect("unable to build cli");
    rl.run().expect("unable to run cli");
}
