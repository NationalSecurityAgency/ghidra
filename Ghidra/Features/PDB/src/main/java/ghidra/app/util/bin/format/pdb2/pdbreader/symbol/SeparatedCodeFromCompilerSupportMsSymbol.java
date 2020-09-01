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
 * This class represents the Separated Code From Compiler Support symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class SeparatedCodeFromCompilerSupportMsSymbol extends AbstractMsSymbol
		implements AddressMsSymbol {

	public static final int PDB_ID = 0x1132;

	private long parentPointer;
	private long endPointer;
	private long blockLength;
	private boolean isLexicalScope;
	private boolean returnsToParent;
	private long offset;
	private long offsetParent;
	private int section;
	private int sectionParent;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public SeparatedCodeFromCompilerSupportMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		parentPointer = reader.parseUnsignedIntVal();
		endPointer = reader.parseUnsignedIntVal();
		blockLength = reader.parseUnsignedIntVal();
		processFlags(reader.parseUnsignedIntVal());
		offset = reader.parseUnsignedIntVal();
		offsetParent = reader.parseUnsignedIntVal();
		section = pdb.parseSegment(reader);
		sectionParent = pdb.parseSegment(reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], Length: %08X, ", getSymbolTypeName(),
			section, offset, blockLength));
		builder.append(String.format("Parent: %08X, End: %08X\n", parentPointer, endPointer));
		builder.append(
			String.format("   Parent scope beings: [%04X:%08X]\n", sectionParent, offsetParent));
		builder.append("   Separated code flags:");
		builder.append(isLexicalScope ? " lexscope" : "");
		builder.append(returnsToParent ? " retparent" : "");
	}

	@Override
	protected String getSymbolTypeName() {
		return "SEPCODE";
	}

	/**
	 * Returns the parent pointer.
	 * @return Parent pointer.
	 */
	public long getParentPointer() {
		return parentPointer;
	}

	/**
	 * Returns the end pointer.
	 * @return End pointer.
	 */
	public long getEndPointer() {
		return endPointer;
	}

	/**
	 * Returns the block length.
	 * @return Block length.
	 */
	public long getBlockLength() {
		return blockLength;
	}

	/**
	 * Returns the indication of if is lexical scope.
	 * @return {@code true} if is lexical scope.
	 */
	public boolean isLexicalScope() {
		return isLexicalScope;
	}

	/**
	 * Returns the indication of if returns to parent.
	 * @return {@code true} if returns to parent.
	 */
	public boolean returnsToParent() {
		return returnsToParent;
	}

	@Override
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the parent offset.
	 * @return Parent offset.
	 */
	public long getOffsetParent() {
		return offsetParent;
	}

	@Override
	public int getSegment() {
		return section;
	}

	/**
	 * Returns the parent segment.
	 * @return Parent segment.
	 */
	public long getSegmentParent() {
		return sectionParent;
	}

	/**
	 * Internal method that breaks out the flag values from the aggregate integral type.
	 * @param flagsIn {@code long} containing unsigned int value.
	 */
	protected void processFlags(long flagsIn) {
		isLexicalScope = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		returnsToParent = ((flagsIn & 0x0001) == 0x0001);
	}

}
