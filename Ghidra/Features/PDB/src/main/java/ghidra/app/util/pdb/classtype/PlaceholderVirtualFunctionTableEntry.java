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
package ghidra.app.util.pdb.classtype;

import ghidra.app.util.SymbolPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;

class PlaceholderVirtualFunctionTableEntry extends VirtualFunctionTableEntry {
	private Address address;

	/**
	 * Constructor for placeholder virtual function table entry
	 * @param originalMethodPath the path of the original function
	 * @param overrideMethodPath the path of the overriding function
	 * @param functionPointer the pointer to the function definition
	 */
	PlaceholderVirtualFunctionTableEntry(SymbolPath originalMethodPath,
			SymbolPath overrideMethodPath, Pointer functionPointer) {
		this(originalMethodPath, overrideMethodPath, functionPointer, null);
	}

	/**
	 * Constructor for placeholder virtual function table entry
	 * @param originalMethodPath the path of the original function
	 * @param overrideMethodPath the path of the overriding function
	 * @param functionPointer the pointer to the function definition
	 * @param address address of the function in memory; can be {@code null}
	 */
	PlaceholderVirtualFunctionTableEntry(SymbolPath originalMethodPath,
			SymbolPath overrideMethodPath, Pointer functionPointer, Address address) {
		super(originalMethodPath, overrideMethodPath, functionPointer);
		this.address = address;
	}

	/**
	 * Method to set the address of the function in memory
	 * @param address the address
	 */
	void setAddress(Address address) {
		this.address = address;
	}

	/**
	 * Returns the address of the function in memory, if set
	 * @return the address; can be {@code null}
	 */
	Address getAddress() {
		return address;
	}

	//==============================================================================================
	// Info from longer-running branch

	void emit(StringBuilder builder, long vbtPtrOffset) {
		emitLine(builder, null, overrideMethodPath);
	}

//	static void emitHeader(StringBuilder builder, long ownerOffset, long vbtPtrOffset) {
	static void emitHeader(StringBuilder builder) {
		builder.append(String.format("%16s %s\n", "Address", "Path"));
		// TODO: see if we need something like this for PlaceholderVirtualFunctionTable
//		emitLine(builder, ownerOffset, vbtPtrOffset );
	}

	static void emitLine(StringBuilder builder, Address address, SymbolPath path) {
		builder.append(String.format("%16s %10s\n",
			address == null ? "<unk_addr>" : address.toString(), path.toString()));
	}

}
