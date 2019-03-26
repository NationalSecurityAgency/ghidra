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
package ghidra.app.decompiler.component;

import java.io.File;

import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.UndefinedFunction;
import ghidra.util.task.SwingRunnable;
import ghidra.util.task.TaskMonitor;

class DecompileRunnable implements SwingRunnable {
	private volatile Function functionToDecompile;
	private final Program program;
	private ProgramLocation location;
	private File debugFile;
	private DecompileResults decompileResults;
	private String errorMessage;
	private ViewerPosition viewerPosition;

	private final DecompilerManager decompilerManager;

	/**
	 * Constructor for a scheduled Decompile runnable
	 * @param program the program containing the function to be decompiled
	 * @param location the location for which to find its containing function.
	 * @param debugFile if non-null, the file to store decompile debug information.
	 */
	public DecompileRunnable(Program program, ProgramLocation location, File debugFile,
			ViewerPosition viewerPosition, DecompilerManager decompilerManager) {
		this.program = program;
		this.location = location;
		this.debugFile = debugFile;
		this.viewerPosition = viewerPosition;
		this.decompilerManager = decompilerManager;
	}

	public boolean update(DecompileRunnable newRunnable) {

		ProgramLocation newLocation = newRunnable.location;
		Program newProgram = newRunnable.program;
		if (!matches(newProgram, newLocation)) {
			return false;
		}

		location = newLocation;
		ViewerPosition newPosition = newRunnable.viewerPosition;
		if (newPosition != null) {
			viewerPosition = newPosition;
		}

		return true;
	}

	/**
	 * Checks if the given program and location represent the same function as this
	 * decompile's function
	 */
	private boolean matches(Program otherProgram, ProgramLocation otherLocation) {
		if (functionToDecompile == null) {
			return false;
		}
		if (program != otherProgram) {
			return false;
		}
		if (otherLocation.getAddress() == null) {
			return true;
		}
		return functionToDecompile.getBody().contains(otherLocation.getAddress());
	}

	/**
	 * Performs the decompile.
	 */
	@Override
	public void monitoredRun(TaskMonitor monitor) {
		monitor.setIndeterminate(true);
		Function function = findFunction(monitor);
		if (function == null) {
			return;
		}
		CodeUnit cu = program.getListing().getCodeUnitAt(function.getEntryPoint());
		if (cu instanceof Data && ((Data) cu).isDefined()) {
			return;
		}
		monitor.setMessage("Decompiling function: " + function.getName() + "...");
		functionToDecompile = function;
		try {
			decompileResults =
				decompilerManager.decompile(program, functionToDecompile, debugFile, monitor);
		}
		catch (DecompileException e) {
			errorMessage = e.getMessage();
		}

	}

	/**
	 * Automatically called in the Swing thread by the RunManager after the run() method completes.
	 * If the decompile wasn't cancelled, it reports the results back to the DecompilerController.
	 */
	@Override
	public void swingRun(boolean isCancelled) {
		if (isCancelled) {
			decompilerManager.setDecompileData(this,
				new EmptyDecompileData("Decompile Cancelled."));
		}
		else {
			DecompileData decompileData = new DecompileData(program, functionToDecompile, location,
				decompileResults, errorMessage, debugFile, viewerPosition);
			decompilerManager.setDecompileData(this, decompileData);
		}
	}

	/**
	 * locates the function to be decompiled based on the location given at construction time.
	 */
	private Function findFunction(TaskMonitor monitor) {
		if (program == null || location == null) {
			return null;
		}
		Address address = location.getAddress();
		if (address == null) {
			return null;
		}

		if (monitor.isCancelled()) {
			return null;
		}

		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function != null) {
			return function;
		}

		// couldn't find the function, make an undefined one
		function = UndefinedFunction.findFunction(program, address, monitor);
		if (function != null) {
			// Make sure there isn't a real function at the location found
			// function may not contain currentAddress in its body.
			// This will cause provider to re-decompile when
			// clicking around the currentAddress :(
			Function realFunction =
				program.getFunctionManager().getFunctionAt(function.getEntryPoint());
			if (realFunction != null) {
				return realFunction;
			}
		}

		return function;
	}
}
