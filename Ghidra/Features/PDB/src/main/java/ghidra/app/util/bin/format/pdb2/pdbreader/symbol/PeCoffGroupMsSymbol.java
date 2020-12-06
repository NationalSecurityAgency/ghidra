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
 * This class represents the PE COFF Group symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class PeCoffGroupMsSymbol extends AbstractMsSymbol implements AddressMsSymbol, NameMsSymbol {

	public static final int PDB_ID = 0x1137;

	private int length;
	private int characteristics;
	private long offset;
	private int segment;
	private String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public PeCoffGroupMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		length = reader.parseInt();
		characteristics = reader.parseInt();
		offset = reader.parseUnsignedIntVal();
		segment = pdb.parseSegment(reader);
		name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the length.
	 * @return Length.
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Returns the characteristics.
	 * @return Characteristics.
	 */
	public int getCharacteristics() {
		return characteristics;
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
	 * Returns the segment.
	 * @return Segment.
	 */
	@Override
	public int getSegment() {
		return segment;
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	@Override
	public String getName() {
		return name;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], Length = %08X, Characteristics = %08X, %s",
			getSymbolTypeName(), segment, offset, length, characteristics, name));
	}

	@Override
	protected String getSymbolTypeName() {
		return "COFFGROUP";
	}

}
