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
package ghidra.program.model.reloc;

import ghidra.program.model.address.Address;

/**
 * A class to store the information needed for a single
 * program relocation.
 */
public class Relocation {
	private Address addr;
	private int type;
	private long[] values;
	private byte[] bytes;
	private String symbolName;

	/**
	 * Constructs a new relocation.
	 * 
	 * @param addr  	the address where the relocation is required
	 * @param type  	the type of relocation to perform
	 * @param values the values needed when performing the relocation
	 * @param bytes 	original instruction bytes affected by relocation
	 * @param symbolName the name of the symbol being relocated
	 */
	public Relocation(Address addr, int type, long[] values, byte[] bytes, String symbolName) {
		this.addr = addr;
		this.type = type;
		this.values = values;
		this.bytes = bytes;
		this.symbolName = symbolName;
	}

	/**
	 * Returns the address where the relocation is required.
	 * 
	 * @return the address where the relocation is required
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * Returns the type of the relocation to perform.
	 * 
	 * @return the type of the relocation to perform
	 */
	public int getType() {
		return type;
	}

	/**
	 * Returns the value needed when performing the relocation.
	 * 
	 * @return the value needed when performing the relocation
	 */
	public long[] getValues() {
		return values;
	}

	/**
	 * Returns the original instruction bytes affected by relocation.
	 * 
	 * @return original instruction bytes affected by relocation
	 */
	public byte[] getBytes() {
		return bytes;
	}

	/**
	 * The name of the symbol being relocated or <code>null</code> if there is no symbol name.
	 * 
	 * @return the name of the symbol being relocated or <code>null</code> if there is no symbol name.
	 */
	public String getSymbolName() {
		return symbolName;
	}
}
