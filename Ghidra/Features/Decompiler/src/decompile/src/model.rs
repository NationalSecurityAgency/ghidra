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

/// "SoftwareModelling" (as in Java)

use serde::{Serialize, Deserialize};
pub use crate::bridge::OpCode;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "addr")]
pub struct Address {
    pub space: String,
    #[serde(with = "crate::serde_int")]
    pub offset: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "addr")]
pub struct Varnode {
    pub space: String,
    #[serde(with = "crate::serde_int")]
    pub offset: u64,
    #[serde(with = "crate::serde_int")]
    pub size: u32,
    pub persists: bool,
    #[serde(rename = "addrtied")]
    pub addr_tied: bool,
    pub unaff: bool,
    pub input: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SeqNum {
    pub space: String,
    #[serde(with = "crate::serde_int")]
    pub offset: u64,
    pub uniq: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PcodeOp {
    #[serde(rename = "code")]
    pub opcode: OpCode,
    #[serde(rename = "seqnum")]
    pub seq: SeqNum,
    pub inputs: Vec<Varnode>,
    pub output: Option<Varnode>,
}

#[test]
fn test_address_xml_parse() {
    use serde_xml_rs::{from_str, to_string};

    let a = r#"<addr space="ram" offset="0x2075ff"/>"#;
    let addr: Address = from_str(a).unwrap();
    assert_eq!(addr.space, "ram");
    assert_eq!(addr.offset, 0x2075ff);

    let res = to_string(&addr).unwrap();
    let addr_again: Address = from_str(&res).unwrap();
    assert_eq!(addr_again.space, addr.space);
    assert_eq!(addr_again.offset, addr.offset);
}