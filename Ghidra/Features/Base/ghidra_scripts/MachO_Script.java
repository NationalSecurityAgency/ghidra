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
//Mac OS X Mach-O
//Given a raw binary Mach-O image,
//this script will create data structures
//representing the Mach header. Including,
//but not limited to, the Mach header,
//program headers, section headers, etc.
//@category Binary

import ghidra.app.cmd.formats.MachoBinaryAnalysisCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.ProgramModule;

public class MachO_Script extends GhidraScript {

	@Override
	public void run() throws Exception {
		ProgramModule module = currentProgram.getListing().getDefaultRootModule();
		MachoBinaryAnalysisCommand command = new MachoBinaryAnalysisCommand(currentAddress, module);
		command.applyTo(currentProgram, monitor);
	}

}
