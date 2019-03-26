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
package ghidra.app.util.viewer.proxy;

import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

/**
 * Stores information about a variable in a program such that the variable can 
 * be retrieved when needed.
 */
public class VariableProxy extends ProxyObj<Variable> {

	private Program program;
	private Address locationAddr;
	private Address functionAddr;
	private Address storageAddr;
	private int firstUseOffset;
	private Variable var;
	private int ordinal = -1;

	/**
	 * Constructs a proxy for a variable.
	 * @param model listing model
	 * @param program the program containing the variable.
	 * @param locationAddr the listing address at which the function exists or was inferred via reference
	 * @param fun the function containing the variable.
	 * @param var the variable to proxy.
	 */
	public VariableProxy(ListingModel model, Program program, Address locationAddr, Function fun,
			Variable var) {
		super(model);
		this.program = program;
		this.locationAddr = locationAddr;
		this.var = var;
		this.functionAddr = fun.getEntryPoint();
		if (var instanceof Parameter) {
			ordinal = ((Parameter) var).getOrdinal();
		}
		Varnode firstVarnode = var.getFirstStorageVarnode();
		storageAddr = firstVarnode != null ? firstVarnode.getAddress() : null;
		firstUseOffset = var.getFirstUseOffset();
	}

	/**
	 * @see ghidra.app.util.viewer.proxy.ProxyObj#getObject()
	 */
	@Override
	public Variable getObject() {

		try {
			var.getName();
			return var;
		}
		catch (Exception e) {
		}

		if (storageAddr == null) {
			return null;
		}

		Listing listing = program.getListing();

		Function function = listing.getFunctionAt(functionAddr);
		if (function == null) {
			return null;
		}

		if (!locationAddr.equals(functionAddr)) {
			// ensure that inferred reference is valid
			if (listing.getFunctionAt(locationAddr) != null) {
				return null;
			}
			CodeUnit cu = listing.getCodeUnitAt(locationAddr);
			if (!(cu instanceof Data)) {
				return null;
			}
			Data data = (Data) cu;
			if (!(data.getDataType() instanceof Pointer)) {
				return null;
			}
			Reference ref = data.getPrimaryReference(0);
			if (ref == null || !ref.getToAddress().equals(functionAddr)) {
				return null;
			}
		}

		if (ordinal >= 0) {
			return function.getParameter(ordinal);
		}

		Variable[] vars = function.getLocalVariables();
		for (int i = 0; i < vars.length; i++) {
			if (firstUseOffset != vars[i].getFirstUseOffset()) {
				continue;
			}
			if (storageAddr.equals(vars[i].getMinAddress())) {
				var = vars[i];
				return var;
			}
		}
		return null;
	}

	public Address getLocationAddress() {
		return locationAddr;
	}

	public Address getFunctionAddress() {
		return functionAddr;
	}

}
