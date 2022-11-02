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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;

/**
 * A function symbol that represents only a shell of (the name and address) the function,
 * when no other information is available.
 */
public class HighFunctionShellSymbol extends HighSymbol {

	/**
	 * Construct the function shell given a name and address
	 * @param id is an id to associate with the new symbol
	 * @param nm is the given name
	 * @param addr is the given address
	 * @param manage is PcodeDataTypeManager to facilitate XML marshaling
	 */
	public HighFunctionShellSymbol(long id, String nm, Address addr, PcodeDataTypeManager manage) {
		super(id, nm, DataType.DEFAULT, true, true, manage);
		VariableStorage store;
		try {
			store = new VariableStorage(getProgram(), addr, 1);
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
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_FUNCTION);
		encoder.writeUnsignedInteger(ATTRIB_ID, getId());
		encoder.writeString(ATTRIB_NAME, name);
		encoder.writeSignedInteger(ATTRIB_SIZE, 1);
		AddressXML.encode(encoder, getStorage().getMinAddress());
		encoder.closeElement(ELEM_FUNCTION);
	}
}
