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
package ghidra.pdb.pdbreader.symbol;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.CategoryIndex;

/**
 * This class represents the Heap Allocation Site symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class HeapAllocationSiteMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x115e;

	private int callSiteOffset;
	private int callSiteSection;
	private int lengthOfHeapAllocationCallInstruction;
	private int functionSignatureTypeIndex;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public HeapAllocationSiteMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		callSiteOffset = reader.parseInt();
		callSiteSection = reader.parseUnsignedShortVal();
		lengthOfHeapAllocationCallInstruction = reader.parseUnsignedShortVal();
		functionSignatureTypeIndex = reader.parseInt();
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, functionSignatureTypeIndex));
		pdb.popDependencyStack();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], instruction length = %d, type = %s\n",
			getSymbolTypeName(), callSiteSection, callSiteOffset,
			lengthOfHeapAllocationCallInstruction, pdb.getTypeRecord(functionSignatureTypeIndex)));
	}

	@Override
	protected String getSymbolTypeName() {
		return "HEAPALLOCSITE";
	}

}
