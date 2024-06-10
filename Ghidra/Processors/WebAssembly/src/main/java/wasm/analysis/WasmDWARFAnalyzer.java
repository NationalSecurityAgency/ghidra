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
package wasm.analysis;

import ghidra.app.plugin.core.analysis.DWARFAnalyzer;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import wasm.WasmLoader;

public class WasmDWARFAnalyzer extends DWARFAnalyzer {

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();

		if (WasmLoader.WEBASSEMBLY.equals(format)
				&& DWARFSectionProviderFactory.createSectionProviderFor(program, TaskMonitor.DUMMY) != null) {
			return true;
		}
		return false;
	}
}
