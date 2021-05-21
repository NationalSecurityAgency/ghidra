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
// Script to fix up Windows RTTI vtables and structures 
//@category C++

import ghidra.app.cmd.data.rtti.RttiUtil;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class IdPeRttiScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			if (!isRunningHeadless()) {
				println("There is no open program.");
				return;
			}
			currentProgram.setTemporary(true);
			return;
		}

		boolean isPe = PEUtil.isVisualStudioOrClangPe(currentProgram);
		if (!isPe) {
			if (!isRunningHeadless()) {
				println("The current program is not a Visual Studio or Clang PE program.");
				return;
			}
			currentProgram.setTemporary(true);
			return;
		}

		Address commonVfTableAddress = RttiUtil.findTypeInfoVftableAddress(currentProgram, monitor);

		if (commonVfTableAddress == null) {
			if (!isRunningHeadless()) {
				println("The current program does not appear to contain RTTI.");
				return;
			}
			currentProgram.setTemporary(true);
			return;
		}

		if (!isRunningHeadless()) {
			println("The current program is a Visual Studio PE or Clang that contains RTTI.");
			return;
		}
		currentProgram.setTemporary(false);

	}


}
