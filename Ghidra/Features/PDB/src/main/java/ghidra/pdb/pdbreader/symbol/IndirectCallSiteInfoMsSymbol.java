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
 * This class represents the Callsite Information symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class IndirectCallSiteInfoMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1139;

	protected long offset;
	protected int section;
	protected int padding;
	protected int typeIndex;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public IndirectCallSiteInfoMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		offset = reader.parseUnsignedIntVal();
		section = reader.parseUnsignedShortVal();
		padding = reader.parseUnsignedShortVal();
		assert (padding == 0);
		typeIndex = reader.parseInt();
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex));
		pdb.popDependencyStack();
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the section.
	 * @return Section.
	 */
	public int getSection() {
		return section;
	}

	/**
	 * Returns the type index.
	 * @return Type index.
	 */
	public int getTypeIndex() {
		return typeIndex;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], Type = %s\n", getSymbolTypeName(), section,
			offset, pdb.getTypeRecord(typeIndex)));
	}

	@Override
	protected String getSymbolTypeName() {
		return "CALLSITEINFO";
	}

}
