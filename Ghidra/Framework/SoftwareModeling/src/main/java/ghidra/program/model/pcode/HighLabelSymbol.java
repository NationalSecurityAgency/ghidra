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

/**
 * A symbol with no underlying data-type. A label within code. This is used to
 * model named jump targets within a function to the decompiler.
 */
public class HighLabelSymbol extends HighSymbol {

	/**
	 * Construct the label given a name and address
	 * @param nm is the given name
	 * @param addr is the given Address
	 * @param dtmanage is a PcodeDataManager to facilitate XML marshaling
	 */
	public HighLabelSymbol(String nm, Address addr, PcodeDataTypeManager dtmanage) {
		super(0, nm, DataType.DEFAULT, true, true, dtmanage);
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
		buf.append("<labelsym");
		saveXMLHeader(buf);
		buf.append("/>\n");
	}
}
