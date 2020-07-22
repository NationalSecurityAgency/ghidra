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
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;

/**
 * This class represents the <B>32MsSymbol</B> flavor of Build Information symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class BuildInformationMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x114c;

	private RecordNumber itemRecordNumber;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public BuildInformationMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		itemRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.ITEM, 32);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the item record number.
	 * @return Item record number.
	 */
	public RecordNumber getItemRecordNumber() {
		return itemRecordNumber;
	}

	/**
	 * Returns the {@link String} representation of the {@link AbstractMsType} item type.
	 * @return {@link String} representation of the item type.
	 */
	public String getItemString() {
		return pdb.getTypeRecord(itemRecordNumber).toString();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(
			String.format("%s: %s\n", getSymbolTypeName(), pdb.getTypeRecord(itemRecordNumber)));
	}

	@Override
	protected String getSymbolTypeName() {
		return "BUILDINFO";
	}

}
