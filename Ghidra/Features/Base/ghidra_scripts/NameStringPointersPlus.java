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
//Takes string names and pointers to indicate what it's pointing to.
// if a string pointer, it'll rename the pointer to the string value.
// otherwise, it will try and rename the pointer to reflect the LABEL
// to which it is pointing.
//
//
//@author
//@category Symbol
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;

public class NameStringPointersPlus extends GhidraScript {

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		DataIterator dataIt = listing.getDefinedData(true); // gets all DEFINED
															// data
															// DataIterator dataIt = listing.getData(true);
															// gets all def AND undef data
		while (dataIt.hasNext()) {
			Data data = dataIt.next();
			if (data.getDataType() instanceof Pointer) {
				Address value = (Address) data.getValue();
				String name = getStringFromPointer(value);
				if (name != null) {
					createSymbolAtAddress(name, data.getAddress());
				}
			}
		}
	}

	private void createSymbolAtAddress(String name, Address address) {
		try {
			name = name.replaceAll(" ", "_");
			createLabel(address, name, true);
		}
		catch (Exception e) {
			println(e.getMessage());
		}
	}

	private String getStringFromPointer(Address address) {
		try {
			Data data = getDataAt(address);
			if (data != null) {
				Object value = data.getValue();
				if (value == null && data.getDataType() instanceof Structure) {
					println("~~> " + address.toString() + " ==>is instanceof Structure");
					return getNameFromStruct(data);
				}
				if (value instanceof String) {
					println("~~> " + address.toString() + " ==>is instanceof String");
					return "sp_" + value;
				}
				else if (value instanceof Address) {
					println("~~> " + address.toString() + " ==>is instanceof Address");
					// String name = getStringFromPointer((Address) value);
					String name = data.getLabel();
					// orig: name = name.substring(0,1) + "p" +
					// name.substring(1);
					if (name == null) {
						return null;
					}
					// before: name = name.substring(0,1) + "p" +
					// name.substring(1);
					name = "p_" + name;
					return name;
				}
			}
			// this wasn't a pointer to string. Let's check for function pointer
			Function func = getFunctionAt(address);
			if (func != null) {
				String name = func.getName();
				if (name != null) {
					println("~~> " + address.toString() + " ==>is instanceof Function");
					return "fp_" + name;
				}
				return null;
			}
			// let's check for undefined symbol with a label last -- like ObjC
			// NSObject.
			data = getUndefinedDataAt(address);
			if (data != null) {
				String name = data.getLabel();
				if (name != null) {
					println("~~> " + address.toString() + " ==>is instanceof Undefined");
					return "p_" + name;
				}
				return null;
			}
		}
		catch (NullPointerException e) {
			// by default do nothing to change the existing label
			println("NullPointerException error caught for " + address);
			return null;
		}
		return null;
	}

	private String getNameFromStruct(Data data) {
		String name = null;
		String dataTypeName = data.getDataType().getName();
		if (dataTypeName.equals("cfstringStruct")) {
			Data stringPointerField = data.getComponent(2);
			if (stringPointerField != null) {
				Object value = stringPointerField.getValue();
				if (value instanceof Address) {
					Address stringAddress = (Address) stringPointerField.getValue();
					Data stringData = getDataAt(stringAddress);
					name = "sp_" + (String) stringData.getValue();
				}
			}
		}
		else {
			name = data.getLabel();
			if (name != null) {
				name = "p_" + name;
			}
		}
		return name;
	}

}
