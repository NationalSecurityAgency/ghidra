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

use std::io::Read;
use std::pin::Pin;
use cxx::CxxString;

use crate::patch::Patches;

#[cxx::bridge]
pub(crate) mod ffi {

    extern "Rust" {
        type Patches;
        fn new_patches() -> Box<Patches>;
        fn add_patch(self: &mut Patches, space: &CxxString, offset: u64, payload: &CxxString);
    }

    unsafe extern "C++" {
        include!("ghidra_process.hh");

        fn ghidra_process_main();

        include!("architecture.hh");
        type Architecture;

        include!("libdecomp.hh");
        fn startDecompilerLibrary(sleigh_home: &str);

        include!("interface.hh");
        type IfaceStatus;
        fn new_iface_status_stub() -> UniquePtr<IfaceStatus>;

        type IfaceData;
        type IfaceCommand;

        unsafe fn call_cmd(cmd: Pin<&mut IfaceCommand>, s: &str);
        fn getModuleRust(self: &IfaceCommand) -> String;
        fn createData(self: Pin<&mut IfaceCommand>) -> *mut IfaceData;
        unsafe fn setData(
            self: Pin<&mut IfaceCommand>,
            root: *mut IfaceStatus,
            data: *mut IfaceData,
        );

        include!("consolemain.hh");
        fn new_load_file_command() -> UniquePtr<IfaceCommand>;
        fn new_add_path_command() -> UniquePtr<IfaceCommand>;
        fn new_save_command() -> UniquePtr<IfaceCommand>;
        fn new_restore_command() -> UniquePtr<IfaceCommand>;

        fn console_main_rust(args: &[String]) -> i32;

        include!("ifacedecomp.hh");
        fn new_decompile_command() -> UniquePtr<IfaceCommand>;
        fn new_print_raw_command() -> UniquePtr<IfaceCommand>;
        fn new_print_c_command() -> UniquePtr<IfaceCommand>;
        fn new_addressrange_load_command() -> UniquePtr<IfaceCommand>;
        fn new_load_func_command() -> UniquePtr<IfaceCommand>;

        include!("ruststream.hh");
        type StreamReader;
        fn read(self: Pin<&mut StreamReader>, buf: &mut [u8]) -> usize;

        include!("opcodes.hh");
        type OpCode;
    }
}

struct RustReader<'a> {
    reader: Pin<&'a mut ffi::StreamReader>,
}

impl<'a> RustReader<'a> {
    pub fn new(reader: Pin<&'a mut ffi::StreamReader>) -> Self {
        Self { reader }
    }
}

impl<'a> Read for RustReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.reader.as_mut().read(buf))
    }
}

fn new_patches() -> Box<Patches> {
    Box::new(Patches::default())
}