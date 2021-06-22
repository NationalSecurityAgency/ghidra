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
use anyhow::{anyhow, Result};

pub(super) fn exec(filename: String, mut target: String) -> Result<()> {
    let target = if target.len() == 0 {
        target = "default".to_string();
    };

    let cap = unsafe { ffi::ArchitectureCapability_findCapability(&filename) };
    if cap.is_null() {
        return Err(anyhow!("Unable to recognize image file {}", filename));
    }

    let cap = unsafe {
        cap.as_mut().unwrap()
    };

    cap.buildArchitecture(&filename, &target);

    Ok(())
}
