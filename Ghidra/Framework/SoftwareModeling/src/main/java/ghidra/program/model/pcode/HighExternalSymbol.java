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
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;

/**
 * A symbol, within a decompiler model, for a function without a body in the current Program.
 * The Address of this symbol corresponds to the code location that CALL instructions refer to.
 * In anticipation of a (not fully resolved) thunking mechanism, this symbol also has a separate
 * resolve Address, which is where the decompiler expects to retrieve the detailed Function object.
 */
public class HighExternalSymbol extends HighSymbol {

	private Address resolveAddress;		// The location of the Function object

	/**
	 * Construct the external reference symbol given a name, the symbol Address, and a
	 * resolving Address.
	 * @param nm is the given name
	 * @param addr is the symbol Address
	 * @param resolveAddr is the resolve Address
	 * @param dtmanage is a PcodeDataTypeManager for facilitating XML marshaling
	 */
	public HighExternalSymbol(String nm, Address addr, Address resolveAddr,
			PcodeDataTypeManager dtmanage) {
		super(0, nm, DataType.DEFAULT, true, true, dtmanage);
		resolveAddress = resolveAddr;
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
	public void saveXML(StringBuilder buf) {
		buf.append("<externrefsymbol");
		if ((name != null) && (name.length() > 0)) { // Give the symbol a name if we can
			SpecXmlUtils.xmlEscapeAttribute(buf, "name", name + "_exref");
		}
		buf.append(">\n");
		AddressXML.buildXML(buf, resolveAddress);
		buf.append("</externrefsymbol>\n");
	}
}
