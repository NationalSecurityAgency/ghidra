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
 * This class represents various flavors of Internals of Data symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class DataSymbolInternals extends AbstractSymbolInternals {

	public static DataSymbolInternals parse16(AbstractPdb pdb, PdbByteReader reader,
			boolean emitToken) throws PdbException {
		DataSymbolInternals result = new DataSymbolInternals(pdb, emitToken);
		result.offset = reader.parseVarSizedOffset(16);
		result.segment = pdb.parseSegment(reader);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		reader.align4();
		return result;
	}

	public static DataSymbolInternals parse32(AbstractPdb pdb, PdbByteReader reader,
			boolean emitToken) throws PdbException {
		DataSymbolInternals result = new DataSymbolInternals(pdb, emitToken);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.offset = reader.parseVarSizedOffset(32);
		result.segment = pdb.parseSegment(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		reader.align4();
		return result;
	}

	public static DataSymbolInternals parse3216(AbstractPdb pdb, PdbByteReader reader,
			boolean emitToken) throws PdbException {
		DataSymbolInternals result = new DataSymbolInternals(pdb, emitToken);
		result.offset = reader.parseVarSizedOffset(32);
		result.segment = pdb.parseSegment(reader);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		reader.align4();
		return result;
	}

	public static DataSymbolInternals parse32St(AbstractPdb pdb, PdbByteReader reader,
			boolean emitToken) throws PdbException {
		DataSymbolInternals result = new DataSymbolInternals(pdb, emitToken);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.offset = reader.parseVarSizedOffset(32);
		result.segment = pdb.parseSegment(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		reader.align4();
		return result;
	}

	protected RecordNumber typeRecordNumber;
	protected long offset;
	protected int segment;
	protected String name;

	private boolean emitToken;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param emitToken Indicates whether typeIndex field is a token or default
	 *  typeIndex.
	 */
	public DataSymbolInternals(AbstractPdb pdb, boolean emitToken) {
		super(pdb);
		this.emitToken = emitToken;
	}

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	public RecordNumber getTypeRecordNumber() {
		return typeRecordNumber;
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	public int getSegment() {
		return segment;
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	public String getName() {
		return name;
	}

	@Override
	public void emit(StringBuilder builder) {
		if (emitToken) {
			builder.append(String.format(": [%04X:%08X], Token: %08X, %s", segment, offset,
				typeRecordNumber.getNumber(), name));
		}
		else {
			builder.append(String.format(": [%04X:%08X], Type: %s, %s", segment, offset,
				pdb.getTypeRecord(typeRecordNumber), name));
		}
	}

}
