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
//
//@__params_start
//@toolbar world.png
//@menupath Tools.Scripts Manager.Repair Disassembly Script
//@__params_end

import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.ReDisassembler;

public class RepairDisassemblyScript extends GhidraScript {
	@Override
	protected void run() throws Exception {
		ReDisassembler dis = new ReDisassembler(currentProgram);
		dis.disasemble(currentAddress, monitor);
	}
}
