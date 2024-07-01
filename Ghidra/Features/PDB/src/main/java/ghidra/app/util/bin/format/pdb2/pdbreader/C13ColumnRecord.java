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
package ghidra.app.util.bin.format.pdb2.pdbreader;

/**
 * A PDB C13 Line Number Column Record
 */
public class C13ColumnRecord {
	private int offsetColumnStart; // unsigned short
	private int offsetColumnEnd; // unsigned short

	/**
	 * Returns the column start for the offset
	 * @return the column start
	 */
	public int getOffsetColumnStart() {
		return offsetColumnStart;
	}

	/**
	 * Returns the column end for the offset
	 * @return the column end
	 */
	public int getOffsetColumnEnd() {
		return offsetColumnEnd;
	}

	static C13ColumnRecord parse(PdbByteReader reader) throws PdbException {
		return new C13ColumnRecord(reader);
	}

	private C13ColumnRecord(PdbByteReader reader) throws PdbException {
		offsetColumnStart = reader.parseUnsignedShortVal();
		offsetColumnEnd = reader.parseUnsignedShortVal();
	}

	@Override
	public String toString() {
		return String.format("Start: 0x%04x, End: 0x%04x", getOffsetColumnStart(),
			getOffsetColumnEnd());
	}
}
