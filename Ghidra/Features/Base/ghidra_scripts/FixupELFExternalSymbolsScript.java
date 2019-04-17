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
// Fixes up any unresolved external symbols (for ELF binaries).
//
// The current program's "External Programs" list needs to be correct before running
// this script.
//
// This script can be run multiple times without harm, generally after updating the "External Programs"
// list.
//
//@category Symbol
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.util.ELFExternalSymbolResolver;
import ghidra.util.Msg;

public class FixupELFExternalSymbolsScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (!ElfLoader.ELF_NAME.equals(currentProgram.getExecutableFormat())) {
			Msg.showError(this, null, "FixupELFExternalSymbols",
				"Current program is not an ELF program!  (" + currentProgram.getExecutableFormat() +
					")");
			return;
		}
		MessageLog msgLog = new MessageLog();
		ELFExternalSymbolResolver.fixUnresolvedExternalSymbols(currentProgram, false, msgLog,
			monitor);
		Msg.info(this, msgLog.toString());
	}

}
