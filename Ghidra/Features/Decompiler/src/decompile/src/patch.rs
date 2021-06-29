/* ###
 * IP: GHIDRA
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
use crate::model::Address;
use cxx::{let_cxx_string, CxxString, UniquePtr};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "patch")]
pub struct Patch {
    addr: Address,
    payload: String,
    size: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Patches {
    #[serde(rename = "patch")]
    patches: Vec<Patch>,
    #[serde(skip)]
    #[serde(default = "std::ptr::null_mut")]
    arch: *mut ffi::Architecture,
}

impl Patches {
    pub(crate) fn new(arch: *mut ffi::Architecture) -> Self {
        Self {
            patches: Vec::new(),
            arch,
        }
    }

    pub(crate) fn add_patch(&mut self, space: &CxxString, offset: usize, size: i32, payload: &CxxString) {
        let space = space.to_string();
        let payload = payload.to_string();

        self.patches.push(Patch {
            addr: Address { space, offset },
            payload,
            size
        })
    }

    fn space_id_by_name(&self, name: &str) -> *mut ffi::AddrSpace {
        let addr_manager = unsafe { self.arch.as_ref().unwrap().getAddrSpaceManager() };
        let_cxx_string!(space = name);
        let space = addr_manager.getSpaceByName(&space);
        space
    }

    // parses (space, offset, size) into varnode data
    fn parse_varnode_data(&self, s: &str) -> UniquePtr<ffi::VarnodeData> {
        let s = s.trim().trim_matches(|c| c == '(' || c == ')');
        let parts: Vec<_> = s.split(",").collect();
        let space = parts[0];
        let offset = parse_int::parse(parts[1]).unwrap();
        let size = parse_int::parse(parts[2]).unwrap();

        if space == "null" {
            return UniquePtr::null();
        }

        let space = self.space_id_by_name(&space);

        unsafe { ffi::new_varnode_data(space, offset, size) }
    }

    /// resolves the patch, if a patch is successfully resolved,
    /// returns the intruction length. If not, returns 0 (indicating)
    /// zero step length.
    pub(crate) fn resolve_patch(
        &self,
        addr: &ffi::Address,
        emit: *mut ffi::PcodeEmit,
    ) -> i32 {
        dbg!(&self.patches.len());

        let patch = self
            .patches
            .iter()
            .filter(|patch| {
                let space_name = unsafe { addr.getSpace().as_ref().unwrap().getName().to_string() };
                space_name == patch.addr.space && addr.getOffset() == patch.addr.offset
            })
            .next();
        let patch = match patch {
            Some(p) => p,
            None => return 0,
        };

        let space = self.space_id_by_name(&patch.addr.space);
        let addr = unsafe { ffi::new_address(space, patch.addr.offset) };

        for payload in patch.payload.split("\n").into_iter() {

            if payload.trim().len() == 0 {
                continue;
            }

            let (lhs, rest) = if payload.find(" = ").is_some() {
                let parts: Vec<_> = payload.split(" = ").collect();

                let lhs = self.parse_varnode_data(&parts[0]);

                (lhs, parts[1])
            } else {
                (UniquePtr::null(), payload)
            };

            
            let opcode = rest.split(" ").next().unwrap();
            let_cxx_string!(opcode = opcode);

            let opcode = ffi::get_opcode(&opcode);

            let mut inputs = vec![];
            let input_str: Vec<_> = rest.split(" ").collect();
            let input_str = input_str[1..].join("");

            for input_varnode in input_str.split("),").into_iter() {

                if input_varnode.trim().len() == 0 {
                    continue
                }

                inputs.push(self.parse_varnode_data(input_varnode));
            }

            unsafe {
                ffi::dump_rust(
                    emit,
                    addr.as_ref().unwrap(),
                    opcode,
                    lhs,
                    &inputs,
                    inputs.len().try_into().unwrap(),
                );
            }
        }

        patch.size
    }
}



#[test]
fn test_parse_patch() {
    let s = r#"
<patches>
<patch>
  <addr space="ram" offset="0x2069ef" size="1"/>
  <payload><![CDATA[
(register, 0x206, 1) = COPY (const, 0x1, 1)
CBRANCH (ram, 0x2075ba, 8), (register, 0x206, 1)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2075ff" size="1"/>
  <payload><![CDATA[
CBRANCH (ram, 0x2077ce, 8), (register, 0x206, 1)
BRANCH (ram, 0x20782d, 8)
]]></payload>
</patch>
</patches>
    "#;
    use serde_xml_rs::from_str;

    let patches: Patches = from_str(s).unwrap();
    println!("{:?}", patches);
}
