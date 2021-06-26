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

use cxx::{CxxString, type_id, ExternType};
use std::io::Read;
use std::pin::Pin;

use crate::patch::Patches;

unsafe impl ExternType for ffi::OpCode {
    type Id = type_id!("OpCode");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub(crate) mod ffi {
    
    extern "Rust" {
        type Patches;
        unsafe fn new_patches(arch: *mut Architecture) -> Box<Patches>;
        fn add_patch(self: &mut Patches, space: &CxxString, offset: usize, payload: &CxxString);
        unsafe fn resolve_patch(self: &Patches, addr: &Address, emit: *mut PcodeEmit) -> bool;
    }

    unsafe extern "C++" {
        include!("fspec.hh");
        include!("varnode.hh");
        include!("pcoderaw.hh");
        include!("architecture.hh");
        include!("space.hh");
        include!("address.hh");
        include!("translate.hh");
        include!("libdecomp.hh");
        include!("interface.hh");
        include!("consolemain.hh");
        include!("ifacedecomp.hh");
        include!("ruststream.hh");
        include!("ghidra_process.hh");

        type OpCode = crate::model::OpCode;
        type Address;
        type AddrSpace;
        type VarnodeData;
        type AddrSpaceManager;
        type Architecture;
        type PcodeEmit;
        type IfaceStatus;
        type IfaceData;
        type IfaceCommand;
        type StreamReader;

        fn ghidra_process_main();

        fn getName(self: &AddrSpace) -> &CxxString;

        unsafe fn new_address(space: *mut AddrSpace, off: usize) -> UniquePtr<Address>;
        fn getSpace(self: &Address) -> *mut AddrSpace;
        fn getOffset(self: &Address) -> usize;

        unsafe fn new_varnode_data(
            space: *mut AddrSpace,
            offset: usize,
            size: u32,
        ) -> UniquePtr<VarnodeData>;

        fn getAddrSpaceManager(self: &Architecture) -> &AddrSpaceManager;

        fn getSpaceByName(self: &AddrSpaceManager, name: &CxxString) -> *mut AddrSpace;

        unsafe fn dump_rust(
            emit: *mut PcodeEmit,
            addr: &Address,
            opcode: OpCode,
            out_var: UniquePtr<VarnodeData>,
            input_vars: &[UniquePtr<VarnodeData>],
            size: i32,
        );

        fn startDecompilerLibrary(sleigh_home: &str);

        fn new_iface_status_stub() -> UniquePtr<IfaceStatus>;


        unsafe fn call_cmd(cmd: Pin<&mut IfaceCommand>, s: &str);
        fn getModuleRust(self: &IfaceCommand) -> String;
        fn createData(self: Pin<&mut IfaceCommand>) -> *mut IfaceData;
        unsafe fn setData(
            self: Pin<&mut IfaceCommand>,
            root: *mut IfaceStatus,
            data: *mut IfaceData,
        );

        fn new_load_file_command() -> UniquePtr<IfaceCommand>;
        fn new_add_path_command() -> UniquePtr<IfaceCommand>;
        fn new_save_command() -> UniquePtr<IfaceCommand>;
        fn new_restore_command() -> UniquePtr<IfaceCommand>;

        fn console_main_rust(args: &[String]) -> i32;

        fn new_decompile_command() -> UniquePtr<IfaceCommand>;
        fn new_print_raw_command() -> UniquePtr<IfaceCommand>;
        fn new_print_c_command() -> UniquePtr<IfaceCommand>;
        fn new_addressrange_load_command() -> UniquePtr<IfaceCommand>;
        fn new_load_func_command() -> UniquePtr<IfaceCommand>;

        fn read(self: Pin<&mut StreamReader>, buf: &mut [u8]) -> usize;

        // opcode
        fn get_opcode(s: &CxxString) -> OpCode;
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

unsafe fn new_patches(arch: *mut ffi::Architecture) -> Box<Patches> {
    Box::new(Patches::new(arch))
}
