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
package ghidra.app.util.bin.format.pe;

/**
 * A class to hold the information extracted from a 
 * delay import descriptor.
 * 
 * NOTE:
 * This class is simply a storage class created for 
 * parsing the PE header data structures.
 * It does not map back to a PE data data structure.
 * 
 * The offset tracks the location of a pointer into 
 * the import name table. The same offset is used to
 * calculate the associated import address table.
 */
public class DelayImportInfo {
	private long ordinal;
	private String name;
	private long offset;

	DelayImportInfo(long ordinal) {
		this.ordinal = ordinal;
		this.offset = -1;
	}

	DelayImportInfo(int ordinal, String name) {
		this.ordinal = ordinal;
		this.name = name;
		this.offset = -1;
	}

	DelayImportInfo(long ordinal, long offset) {
		this.ordinal = ordinal;
		this.offset = offset;
	}

	DelayImportInfo(int ordinal, String name, long offset) {
		this.ordinal = ordinal;
		this.name = name;
		this.offset = offset;
	}

	/**
	 * Returns the ordinal number of the imported DLL.
	 * @return the ordinal number of the imported DLL
	 */
	public long getOrdinal() {
		return ordinal;
	}

	/**
	 * Returns the name of the imported DLL.
	 * @return the name of the imported DLL
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the offset into the Import Name Table.
	 * @return the offset into the Import Name Table. -1 if there is none.
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns true if the import is 'by name'.
	 * @return true if the import is 'by name'
	 */
	public boolean hasName() {
		return name != null;
	}
}
