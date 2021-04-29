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
package ghidra.app.plugin.core.debug.utils;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public enum ProgramLocationUtils {
	;

	public static ProgramLocation replaceAddress(ProgramLocation loc, Program program,
			Address address) {
		// HACK: ... and a half
		SaveState state = new SaveState("LOC");
		loc.saveState(state);
		state.putString("_ADDRESS", address.toString());
		state.putString("_BYTE_ADDR",
			address.add(loc.getByteAddress().subtract(loc.getAddress())).toString());
		return ProgramLocation.getLocation(program, state);
	}

	public static ProgramLocation replaceProgram(ProgramLocation loc, Program program) {
		// HACK: ... and a half
		SaveState state = new SaveState("LOC");
		loc.saveState(state);
		return ProgramLocation.getLocation(program, state);
	}
}
