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
package ghidra.app.context;

import java.util.HashSet;
import java.util.Set;

import docking.ComponentProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;

public class ProgramLocationActionContext extends ProgramActionContext
		implements FunctionSupplierContext {

	private final ProgramLocation location;
	private final ProgramSelection selection;
	private final ProgramSelection highlight;

	private CodeUnit cu;
	private boolean codeUnitInitialized = false;

	public ProgramLocationActionContext(ComponentProvider provider, Program program,
			ProgramLocation location, ProgramSelection selection, ProgramSelection highlight) {
		super(provider, program);
		this.location = location;
		this.selection = selection;
		this.highlight = highlight;
	}

	/**
	 * @return Returns the program location.
	 */
	public ProgramLocation getLocation() {
		return location;
	}

	/**
	 * @return Returns the program selection.
	 */
	public ProgramSelection getSelection() {
		return selection == null ? new ProgramSelection() : selection;
	}

	public ProgramSelection getHighlight() {
		return highlight == null ? new ProgramSelection() : highlight;
	}

	/**
	 * @return address corresponding to the action's program location or null
	 * if program location is null.
	 */
	public Address getAddress() {
		if (location != null) {
			return location.getAddress();
		}
		return null;
	}

	/**
	 * Returns the code unit containing the action's program location or null
	 * @return the code unit containing the action's program location or null
	 */
	public CodeUnit getCodeUnit() {
		if (!codeUnitInitialized) {
			Address addr = getAddress();
			if (addr != null) {
				cu = program.getListing().getCodeUnitContaining(addr);
				if (cu instanceof Data && location.getComponentPath() != null) {
					Data data = (Data) cu;
					cu = data.getComponent(location.getComponentPath());
				}
			}
			codeUnitInitialized = true;
		}
		return cu;
	}

	public boolean hasSelection() {
		return (selection != null && !selection.isEmpty());
	}

	public boolean hasHighlight() {
		return (highlight != null && !highlight.isEmpty());
	}

	@Override
	public boolean hasFunctions() {
		if (selection == null || selection.isEmpty()) {
			return getFunctionForLocation() != null;
		}
		// see if selection contains at least one function
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator functionIter = functionManager.getFunctions(selection, true);
		return functionIter.hasNext();
	}

	@Override
	public Set<Function> getFunctions() {
		Set<Function> functions = new HashSet<>();
		if (selection == null || selection.isEmpty()) {
			functions.add(getFunctionForLocation());
		}
		else {
			FunctionManager functionManager = program.getFunctionManager();
			FunctionIterator functionIter = functionManager.getFunctions(selection, true);
			for (Function selectedFunction : functionIter) {
				functions.add(selectedFunction);
			}
		}
		return functions;
	}

	protected Function getFunctionForLocation() {
		if (location instanceof FunctionLocation functionLocation) {
			Address functionAddress = functionLocation.getFunctionAddress();
			return program.getFunctionManager().getFunctionAt(functionAddress);
		}
		Address address = getAddress();
		if (address != null) {
			return program.getFunctionManager().getFunctionContaining(address);
		}
		return null;
	}
}
