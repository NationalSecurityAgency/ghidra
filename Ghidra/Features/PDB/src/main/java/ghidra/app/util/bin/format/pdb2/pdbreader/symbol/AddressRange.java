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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * Address Range property used by a number of specific PDB symbol types.
 */
public class AddressRange extends AbstractParsableItem {

	private long startOffset;
	private int sectionStart;
	private int lengthRange;

	/**
	 * Constructor for this symbol component.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AddressRange(PdbByteReader reader) throws PdbException {
		startOffset = reader.parseUnsignedIntVal();
		sectionStart = reader.parseUnsignedShortVal();
		lengthRange = reader.parseUnsignedShortVal();
	}

	/**
	 * Returns the start offset.
	 * @return Start offset.
	 */
	public long getStartOffset() {
		return startOffset;
	}

	/**
	 * Returns the start section
	 * @return Start section.
	 */
	public int getSectionStart() {
		return sectionStart;
	}

	/**
	 * Returns the length range.
	 * @return Length range.
	 */
	public int getLengthRange() {
		return lengthRange;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("   Range: [%04X:%08X] - [%04X:%08X]", sectionStart,
			startOffset, sectionStart, startOffset + lengthRange));
	}

}
