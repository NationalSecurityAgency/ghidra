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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class CreateExternalFunctionCmd implements Command {

	private Symbol extSymbol;

	private String libraryName;
	private Namespace parentNamespace;
	private String name;
	private Address address;

	private SourceType source;

	private String status;

	/**
	 * Create an external function
	 * @param extSymbol a non-function external symbol
	 */
	public CreateExternalFunctionCmd(Symbol extSymbol) {
		if (extSymbol == null) {
			throw new IllegalArgumentException("External symbol may not be null");
		}
		this.extSymbol = extSymbol;
		this.source = extSymbol.getSource();
	}

	/**
	 * Create an external function
	 * @param libraryName library name, if null the UNKNOWN library will be used
	 * @param name function name (required)
	 * @param address the address of the function's entry point in the external library (optional)
	 */
	public CreateExternalFunctionCmd(String libraryName, String name, Address address,
			SourceType source) {
		this.libraryName = libraryName != null ? libraryName : Library.UNKNOWN;
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("External function name must be specified");
		}
		this.name = name;
		this.address = address;
		if (source == null) {
			throw new IllegalArgumentException("Source cannot be null");
		}
		this.source = source;
	}

	/**
	 * Create an external function in the specified external namespace.
	 * @param externalParentNamespace the external parent namespace where the named function should be created (required)
	 * @param name function name (required)
	 * @param address the address of the function's entry point in the external library (optional)
	 * @param source the source type for this external function
	 */
	public CreateExternalFunctionCmd(Namespace externalParentNamespace, String name,
			Address address, SourceType source) {
		if (externalParentNamespace == null || name.length() == 0) {
			throw new IllegalArgumentException("A parent namespace must be specified.");
		}
		if (!externalParentNamespace.isExternal()) {
			throw new IllegalArgumentException(
				"The parent namespace must be an external namespace.");
		}
		this.parentNamespace = externalParentNamespace;
		this.name = name;
		this.address = address;
		if (source == null) {
			throw new IllegalArgumentException("Source cannot be null");
		}
		this.source = source;
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		if (extSymbol == null) {
			return createExternalFunction(program);
		}

		if (!extSymbol.isExternal() || extSymbol.getSymbolType() != SymbolType.LABEL) {
			// status = "Invalid symbol specified";
			return false;
		}

		// Convert symbol to external function
		ExternalLocation extLoc = (ExternalLocation) extSymbol.getObject();
		Function function = extLoc.createFunction();
		extSymbol = function.getSymbol();
		if (extSymbol.getSource() != source) {
			extSymbol.setSource(source);
		}
		return true;
	}

	private boolean createExternalFunction(Program program) {
		try {
			ExternalManager extMgr = program.getExternalManager();
			ExternalLocation extLoc;
			if (parentNamespace == null) {
				extLoc = extMgr.addExtFunction(libraryName, name, address, source);
			}
			else {
				extLoc = extMgr.addExtFunction(parentNamespace, name, address, source);
			}
			extSymbol = extLoc.getSymbol();
			return true;
		}
		catch (DuplicateNameException e) {
			status = e.getMessage();
		}
		catch (InvalidInputException e) {
			status = e.getMessage();
		}
		return false;
	}

	@Override
	public String getStatusMsg() {
		return status;
	}

	@Override
	public String getName() {
		return "Create External Function";
	}

	public Symbol getExtSymbol() {
		return extSymbol;
	}
}
