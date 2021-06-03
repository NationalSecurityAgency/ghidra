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
 * This class represents the Callsite Information symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class IndirectCallSiteInfoMsSymbol extends AbstractMsSymbol implements AddressMsSymbol {

	public static final int PDB_ID = 0x1139;

	protected long offset;
	protected int section;
	protected int padding;
	protected RecordNumber typeRecordNumber;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public IndirectCallSiteInfoMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		offset = reader.parseUnsignedIntVal();
		// Not sure if section should really be "segment."   MSFT says section, but don't trust.
		section = pdb.parseSegment(reader);
		padding = reader.parseUnsignedShortVal();
		if (padding != 0) {
			PdbLog.message("Non-zero padding (" + padding + " in " + getClass().getSimpleName() +
				":\n" + reader.dump());
		}
		// TODO: eventually change to parse() after we figure out what is going on with high bit
		// fixup.  Seems to point to incorrect data.
		typeRecordNumber = RecordNumber.parseNoWitness(pdb, reader, RecordCategory.TYPE, 32);
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
	@Override
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the segment. (MSFT says section, but we are interpreting as segment for now).
	 * @return Segment.
	 */
	@Override
	public int getSegment() {
		return section;
	}

	/**
	 * Returns the section.
	 * @return Section.
	 */
	public int getSection() {
		return section;
	}

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	public RecordNumber getTypeRecordNumber() {
		return typeRecordNumber;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], Type = %s\n", getSymbolTypeName(), section,
			offset, pdb.getTypeRecord(typeRecordNumber)));
	}

	@Override
	protected String getSymbolTypeName() {
		return "CALLSITEINFO";
	}

}
