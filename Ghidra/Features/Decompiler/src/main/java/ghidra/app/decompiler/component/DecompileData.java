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

import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;

import java.io.File;

import docking.widgets.fieldpanel.support.ViewerPosition;

public class DecompileData {

	private final Program program;
	private final Function function;
	private final ProgramLocation location;
	private final DecompileResults decompileResults;
	private final File debugFile;
	private final String message;
	private final ViewerPosition viewerPosition;

	public DecompileData(Program program, Function function, ProgramLocation location,
			DecompileResults decompileResults, String errorMessage, File debugFile,
			ViewerPosition viewerPosition) {
				this.program = program;
				this.function = function;
				this.location = location;
				this.decompileResults = decompileResults;
				this.message = errorMessage;
				this.debugFile = debugFile;
				this.viewerPosition = viewerPosition;
	}
	
	public boolean hasDecompileResults() {
		if (decompileResults == null) {
			return false;
		}
		return decompileResults.getCCodeMarkup() != null;
	}
	
	public DecompileResults getDecompileResults() {
		return decompileResults;
	}

	public Program getProgram() {
		return program;
	}

	public Function getFunction() {
		return function;
	}

	public HighFunction getHighFunction() {
		if (decompileResults != null) {
			return decompileResults.getHighFunction();
		}
		return null;
	}
	
	public ProgramLocation getLocation() {
		return location;
	}

	public ClangTokenGroup getCCodeMarkup() {
		if (decompileResults == null) {
			return null;
		}
		return decompileResults.getCCodeMarkup();
	}

	public String getErrorMessage() {
		if (message != null) {
			return message;
		}
		if (function == null) {
			return "No Function";
		}
		if (decompileResults != null) {
			String err = decompileResults.getErrorMessage();
			if (err != null) {
				return err;
			}
		}
		return "Unknown Error";
	}
	
	public File getDebugFile() {
		return debugFile;
	}

	public boolean contains(ProgramLocation programLocation) {
		if (!hasDecompileResults()) {
			return false;
		}
		if (programLocation.getProgram() != getProgram()) {
			return false;
		}
		Address address = programLocation.getAddress();
		if (address == null) {
			return false;
		}
		return function.getBody().contains(address);
	}

	public AddressSpace getFunctionSpace() {
		return function.getEntryPoint().getAddressSpace();
	}

	public ViewerPosition getViewerPosition() {
		return viewerPosition;
	}
}
