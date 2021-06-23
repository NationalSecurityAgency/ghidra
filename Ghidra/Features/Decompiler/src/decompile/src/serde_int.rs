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

/// deals with serde automatic int parse and hex serialize
use serde::{Deserialize, Deserializer, de, Serializer};
use num_traits::Num;
use std::fmt::LowerHex;

pub(crate) fn serialize<S, T: LowerHex>(item: &T, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
    s.serialize_str(&format!("0x{:x}", item))
}

pub(crate) fn deserialize<'de, D, T: Num>(des: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(des)?;
    parse_int::parse(&s).map_err(|_| de::Error::custom(format!("parse int {} error", s)))
}