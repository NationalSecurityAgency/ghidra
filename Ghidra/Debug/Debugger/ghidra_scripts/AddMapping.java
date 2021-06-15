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
import com.google.common.collect.Range;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;

public class AddMapping extends GhidraScript {
	@Override
	protected void run() throws Exception {
		DebuggerStaticMappingService mappings =
			state.getTool().getService(DebuggerStaticMappingService.class);
		DebuggerTraceManagerService traces =
			state.getTool().getService(DebuggerTraceManagerService.class);
		Trace currentTrace = traces.getCurrentTrace();
		AddressSpace dynRam = currentTrace.getBaseAddressFactory().getDefaultAddressSpace();
		AddressSpace statRam = currentProgram.getAddressFactory().getDefaultAddressSpace();

		try (UndoableTransaction tid =
			UndoableTransaction.start(currentTrace, "Add Mapping", true)) {
			mappings.addMapping(
				new DefaultTraceLocation(currentTrace, null, Range.atLeast(0L),
					dynRam.getAddress(0x00400000)),
				new ProgramLocation(currentProgram, statRam.getAddress(0x00400000)),
				0x10000, false);
		}
	}
}
