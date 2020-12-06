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
 * There is no documentation for this symbol in the current API.  This symbol was seen with a
 *  VS2017 compile.
 */
public class UnknownX1168MsSymbol extends AbstractUnknownMsSymbol {

	public static final int PDB_ID = 0x1168;

	// Guessing.
	private int count;
	private List<RecordNumber> typeRecordNumbers = new ArrayList<>();

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public UnknownX1168MsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		count = reader.parseInt();

		for (int i = 0; i < count; i++) {
			// Am assuming that this is a "type" index.
			RecordNumber typeRecordNumber =
				RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
			typeRecordNumbers.add(typeRecordNumber);
		}
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns {@link List}&lt;{@link RecordNumber}&gt; of what appears to be type indices.
	 * @return Possible type record numbers.
	 */
	public List<RecordNumber> getTypeRecordNumbers() {
		return typeRecordNumbers;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(": Type List: {");
		DelimiterState ds = new DelimiterState("", ", ");
		for (RecordNumber typeRecordNumber : typeRecordNumbers) {
			builder.append(ds.out(true, pdb.getTypeRecord(typeRecordNumber).toString()));
		}
		builder.append("}\n");
	}

	@Override
	protected String getSymbolTypeName() {
		return "UNKNOWN_SYMBOL_X1168";
	}

}
