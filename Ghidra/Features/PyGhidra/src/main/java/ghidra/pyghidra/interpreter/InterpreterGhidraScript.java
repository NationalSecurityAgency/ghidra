package ghidra.pyghidra.interpreter;

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
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
		set(state, new InterpreterTaskMonitor(writer), writer);
	}
}
