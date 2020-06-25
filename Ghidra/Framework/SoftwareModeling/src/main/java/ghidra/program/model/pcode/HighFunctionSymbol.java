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
package ghidra.program.model.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.InvalidInputException;

/**
 * A function symbol that encapsulates detailed information about a particular function
 * for the purposes of decompilation. The detailed model is provided by a backing HighFunction object.
 */
public class HighFunctionSymbol extends HighSymbol {

	/**
	 * Construct given an Address, size, and decompiler function model for the symbol.
	 * The Address is typically the entry point of the function but may be different
	 * if the function is getting mapped from elsewhere (i.e. the EXTERNAL space). The size
	 * is given in bytes but generally isn't the true size of the function. The size needs to
	 * make the symbol just big enough to absorb any off-cut Address queries.
	 * @param addr is the starting Address of the symbol
	 * @param size is the pseudo-size of the function
	 * @param function is the decompiler model of the function
	 */
	public HighFunctionSymbol(Address addr, int size, HighFunction function) {
		super(function.getID(), "", DataType.DEFAULT, function);
		VariableStorage store;
		try {
			store = new VariableStorage(getProgram(), addr, size);
		}
		catch (InvalidInputException e) {
			store = VariableStorage.UNASSIGNED_STORAGE;
		}
		MappedEntry entry = new MappedEntry(this, store, null);
		addMapEntry(entry);
	}

	@Override
	public boolean isGlobal() {
		return true;
	}

	@Override
	public Namespace getNamespace() {
		Function func = function.getFunction();
		Namespace namespc = func.getParentNamespace();
		while (func.isThunk() && namespc.getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			// Thunks can be in a different namespace than the thunked function.
			// We choose the thunk's namespace unless it is the global namespace
			func = func.getThunkedFunction(false);
			namespc = func.getParentNamespace();
		}
		return namespc;
	}

	@Override
	public void saveXML(StringBuilder buf) {
		MappedEntry entry = (MappedEntry) getFirstWholeMap();
		String funcString =
			function.buildFunctionXML(getId(), getNamespace(), entry.getStorage().getMinAddress(),
				entry.getSize());
		buf.append(funcString);
	}
}
