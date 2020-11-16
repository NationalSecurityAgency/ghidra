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
 * This class represents the Heap Allocation Site symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class HeapAllocationSiteMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x115e;

	private long callSiteOffset;
	private int callSiteSection;
	private int lengthOfHeapAllocationCallInstruction;
	private RecordNumber functionSignatureTypeRecordNumber;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public HeapAllocationSiteMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		callSiteOffset = reader.parseVarSizedOffset(32);
		callSiteSection = pdb.parseSegment(reader);
		lengthOfHeapAllocationCallInstruction = reader.parseUnsignedShortVal();
		functionSignatureTypeRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], instruction length = %d, type = %s\n",
			getSymbolTypeName(), callSiteSection, callSiteOffset,
			lengthOfHeapAllocationCallInstruction,
			pdb.getTypeRecord(functionSignatureTypeRecordNumber)));
	}

	@Override
	protected String getSymbolTypeName() {
		return "HEAPALLOCSITE";
	}

}
