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
import ghidra.program.util.BytesFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;

public enum ProgramLocationUtils {
	;

	public static ProgramLocation replaceAddress(ProgramLocation loc, Program program,
			Address address) {
		// Outside of byte fields, I really don't care
		if (loc instanceof BytesFieldLocation) {
			return new BytesFieldLocation(program, address);
		}
		return new ProgramLocation(program, address);
	}

	/**
	 * Swap out the trace view of a {@link ProgramLocation} if it is not the canonical view
	 * 
	 * <p>
	 * If the program location is not associated with a trace, the same location is returned.
	 * Otherwise, this ensures that the given view is the canonical one for the same trace. If
	 * matchSnap is true, the view is only replaced when the replacement shares the same snap.
	 * 
	 * @param location a location possibly in a trace view
	 * @param matchSnap true to only replace is snap matches, false to always replace
	 * @return the adjusted location
	 */
	public static ProgramLocation fixLocation(ProgramLocation loc, boolean matchSnap) {
		Program program = loc.getProgram();
		if (!(program instanceof TraceProgramView)) {
			return loc;
		}
		TraceProgramView itsView = (TraceProgramView) program;
		Trace trace = itsView.getTrace();
		TraceProgramView canonicalView = trace.getProgramView();
		if (canonicalView == itsView ||
			(matchSnap && canonicalView.getSnap() != itsView.getSnap())) {
			return loc;
		}
		return replaceProgram(loc, canonicalView);
	}

	public static ProgramLocation replaceProgram(ProgramLocation loc, Program program) {
		// HACK: ... and a half
		SaveState state = new SaveState("LOC");
		loc.saveState(state);
		return ProgramLocation.getLocation(program, state);
	}
}
