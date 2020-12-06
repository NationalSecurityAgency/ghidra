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
 * This class represents the PE COFF Section symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class PeCoffSectionMsSymbol extends AbstractMsSymbol implements NameMsSymbol {

	public static final int PDB_ID = 0x1136;

	private int sectionNumber;
	private int align;
	private int reserved;
	private int rva;
	private int length;
	private int characteristics;
	private String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public PeCoffSectionMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		sectionNumber = pdb.parseSegment(reader); // TODO: confirm... assuming segment
		//else use this: sectionNumber = reader.parseUnsignedShortVal();
		align = reader.parseUnsignedByteVal();
		reserved = reader.parseUnsignedByteVal();
		rva = reader.parseInt();
		length = reader.parseInt();
		characteristics = reader.parseInt();
		name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the section number.
	 * @return Section number.
	 */
	public int getSectionNumber() {
		return sectionNumber;
	}

	/**
	 * Returns the alignment.
	 * @return Alignment.
	 */
	public int getAlign() {
		return align;
	}

	/**
	 * Returns the reserved value.
	 * @return Reserved value.
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * Returns the RVA (real valued address?).
	 * @return Real-Valued Address (?).
	 */
	public int getRva() {
		return rva;
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
	 * Returns the name.
	 * @return Name.
	 */
	@Override
	public String getName() {
		return name;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format(
			"%s: [%04X], RVA = %08x, Length = %08X, Align = %08X, Characteristics = %08X, %s",
			getSymbolTypeName(), sectionNumber, rva, length, align, characteristics, name));
	}

	@Override
	protected String getSymbolTypeName() {
		return "SECTION";
	}

}
