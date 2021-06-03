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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Defined Singled Address Range symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDefinedSingleAddressRangeMsSymbol extends AbstractMsSymbol {

	protected AddressRange addressRange;
	protected List<AddressGap> addressGapList = new ArrayList<>();

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractDefinedSingleAddressRangeMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
	}

	/**
	 * Returns the {@link AddressRange} address range.
	 * @return Address range.
	 */
	public AddressRange getAddressRange() {
		return addressRange;
	}

	/**
	 * Returns a {@link List} of {@link AddressGap} gaps.
	 * @return Gaps.
	 */
	public List<AddressGap> getAddressGapList() {
		return addressGapList;
	}

	/**
	 * Internal method for parsing Range and Gaps.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected void parseRangeAndGaps(PdbByteReader reader) throws PdbException {
		addressRange = new AddressRange(reader);
		while (reader.hasMore()) {
			AddressGap gap = new AddressGap(reader);
			addressGapList.add(gap);
		}
	}

	/**
	 * Outputs the Range and Gaps data into a {@link StringBuilder}.
	 * @param builder {@link StringBuilder} into which to output the data.
	 */
	protected void emitRangeAndGaps(StringBuilder builder) {
		builder.append(addressRange);
		builder.append(String.format(", %d Gaps", addressGapList.size()));
		if (addressGapList.isEmpty()) {
			return;
		}
		builder.append(" (startOffset, length):");
		for (AddressGap gap : addressGapList) {
			builder.append(gap);
		}
	}

}
