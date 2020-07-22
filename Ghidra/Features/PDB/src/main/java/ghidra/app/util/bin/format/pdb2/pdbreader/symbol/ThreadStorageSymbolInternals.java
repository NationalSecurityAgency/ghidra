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
 * This class represents various flavors of Internals of Thread Storage symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ThreadStorageSymbolInternals extends AbstractSymbolInternals {

	/**
	 * Factory for "32" version of ThreadStorageSymbolInternals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ThreadStorageSymbolInternals parse32(PdbByteReader reader, AbstractPdb pdb)
			throws PdbException {
		ThreadStorageSymbolInternals result = new ThreadStorageSymbolInternals(pdb);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.offset = reader.parseVarSizedOffset(32);
		result.segment = pdb.parseSegment(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		reader.align4();
		return result;
	}

	/**
	 * Factory for "3216" version of ThreadStorageSymbolInternals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ThreadStorageSymbolInternals parse3216(PdbByteReader reader, AbstractPdb pdb)
			throws PdbException {
		ThreadStorageSymbolInternals result = new ThreadStorageSymbolInternals(pdb);
		result.offset = reader.parseVarSizedOffset(32);
		result.segment = pdb.parseSegment(reader);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		reader.align4();
		return result;
	}

	/**
	 * Factory for "32St" version of ThreadStorageSymbolInternals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ThreadStorageSymbolInternals parse32St(PdbByteReader reader, AbstractPdb pdb)
			throws PdbException {
		ThreadStorageSymbolInternals result = new ThreadStorageSymbolInternals(pdb);
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

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public ThreadStorageSymbolInternals(AbstractPdb pdb) {
		super(pdb);
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
	 * Returns the type record number.
	 * @return Type record number.
	 */
	public RecordNumber getTypeRecordNumber() {
		return typeRecordNumber;
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
		builder.append(String.format(": [%04X:%08X], Type: %s, %s", segment, offset,
			pdb.getTypeRecord(typeRecordNumber), name));
	}

}
