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
package ghidra.pyghidra.interpreter;

import java.io.PrintWriter;

import ghidra.app.script.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * Custom {@link GhidraScript} only for use with the PyGhidra interpreter console
 */
public final class InterpreterGhidraScript extends GhidraScript {

	// public default constructor for use by PyGhidraPlugin
	// the default constructor for FlatProgramAPI has protected visibility
	public InterpreterGhidraScript() {
	}

	@Override
	public void run() {
		// we run in the interpreter console so we do nothing here
	}

	public Address getCurrentAddress() {
		return currentAddress;
	}

	public ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	public ProgramSelection getCurrentSelection() {
		return currentSelection;
	}

	public ProgramSelection getCurrentHighlight() {
		return currentHighlight;
	}

	public PrintWriter getWriter() {
		return writer;
	}

	public void setCurrentProgram(Program program) {
		currentProgram = program;
		state.setCurrentProgram(program);
	}

	public void setCurrentAddress(Address address) {
		currentAddress = address;
		state.setCurrentAddress(address);
	}

	public void setCurrentLocation(ProgramLocation location) {
		currentLocation = location;
		currentAddress = location != null ? location.getAddress() : null;
		state.setCurrentLocation(location);
	}

	public void setCurrentSelection(ProgramSelection selection) {
		currentSelection = selection;
		state.setCurrentSelection(selection);
	}

	public void setCurrentHighlight(ProgramSelection highlight) {
		currentHighlight = highlight;
		state.setCurrentHighlight(highlight);
	}

	public void set(GhidraState state, PrintWriter writer) {
		set(state, new ScriptControls(writer, writer, new InterpreterTaskMonitor(writer)));
	}
}
