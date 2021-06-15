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
 * Address Gap property used by a number of specific PDB symbol types.  This seems to specify
 *  one of potentially many address gaps in an address range.
 *  @see AbstractDefinedSingleAddressRangeMsSymbol
 */
public class AddressGap extends AbstractParsableItem {

	private int gapStartOffset;
	private int lengthRange;

	/**
	 * Constructor for this symbol component.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AddressGap(PdbByteReader reader) throws PdbException {
		gapStartOffset = reader.parseUnsignedShortVal();
		lengthRange = reader.parseUnsignedShortVal();
	}

	/**
	 * Returns the gap start offset.
	 * @return Gap start offset.
	 */
	public int getGapStartOffset() {
		return gapStartOffset;
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
		builder.append(String.format(" (%04X, %X)", gapStartOffset, lengthRange));
	}

}
