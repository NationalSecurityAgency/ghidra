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
package ghidra.app.plugin.core.sourcefilestable;

import ghidra.program.model.address.Address;

/**
 * A row object class for {@link SourceMapEntryTableModel}.
 */
public class SourceMapEntryRowObject {

	private Address baseAddress;
	private int lineNumber;
	private long length;
	private int count;

	/**
	 * Constructor
	 * @param baseAddress base address 
	 * @param lineNumber source line number
	 * @param length length of entry
	 * @param count number of mappings for source line
	 */
	public SourceMapEntryRowObject(Address baseAddress, int lineNumber, long length, int count) {
		this.baseAddress = baseAddress;
		this.lineNumber = lineNumber;
		this.length = length;
		this.count = count;
	}

	/**
	 * Returns the base address
	 * @return base address
	 */
	public Address getBaseAddress() {
		return baseAddress;
	}

	/**
	 * Returns the source file line number
	 * @return line number
	 */
	public int getLineNumber() {
		return lineNumber;
	}

	/**
	 * Returns the length of the associated source map entry
	 * @return entry length
	 */
	public long getLength() {
		return length;
	}

	/**
	 * Returns the number of entries for this line number
	 * @return number of entries
	 */
	public int getCount() {
		return count;
	}

}
