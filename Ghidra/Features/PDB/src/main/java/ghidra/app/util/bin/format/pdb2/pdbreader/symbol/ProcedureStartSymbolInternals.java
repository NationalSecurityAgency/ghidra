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
 * This class represents various flavors of Internals of the Procedure symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ProcedureStartSymbolInternals extends AbstractSymbolInternals {

	/**
	 * Factory for "16" version of {@link ProcedureStartSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ProcedureStartSymbolInternals parse16(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ProcedureStartSymbolInternals result = new ProcedureStartSymbolInternals(pdb);
		result.parentPointer = reader.parseUnsignedIntVal();
		result.endPointer = reader.parseUnsignedIntVal();
		result.nextPointer = reader.parseUnsignedIntVal();
		result.procedureLength = reader.parseUnsignedShortVal();
		result.debugStartOffset = reader.parseUnsignedShortVal();
		result.debugEndOffset = reader.parseUnsignedShortVal();
		result.offset = reader.parseUnsignedShortVal();
		result.segment = pdb.parseSegment(reader);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		result.flags = new ProcedureFlags(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		reader.align4();
		return result;
	}

	/**
	 * Factory for "32" version of {@link ProcedureStartSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ProcedureStartSymbolInternals parse32(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ProcedureStartSymbolInternals result = new ProcedureStartSymbolInternals(pdb);
		result.parentPointer = reader.parseUnsignedIntVal();
		result.endPointer = reader.parseUnsignedIntVal();
		result.nextPointer = reader.parseUnsignedIntVal();
		result.procedureLength = reader.parseUnsignedIntVal();
		result.debugStartOffset = reader.parseUnsignedIntVal();
		result.debugEndOffset = reader.parseUnsignedIntVal();
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.offset = reader.parseUnsignedIntVal();
		result.segment = pdb.parseSegment(reader);
		result.flags = new ProcedureFlags(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		reader.align4();
		return result;
	}

	/**
	 * Factory for "3216" version of {@link ProcedureStartSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ProcedureStartSymbolInternals parse3216(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ProcedureStartSymbolInternals result = new ProcedureStartSymbolInternals(pdb);
		result.parentPointer = reader.parseUnsignedIntVal();
		result.endPointer = reader.parseUnsignedIntVal();
		result.nextPointer = reader.parseUnsignedIntVal();
		result.procedureLength = reader.parseUnsignedIntVal();
		result.debugStartOffset = reader.parseUnsignedIntVal();
		result.debugEndOffset = reader.parseUnsignedIntVal();
		result.offset = reader.parseUnsignedIntVal();
		result.segment = pdb.parseSegment(reader);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		result.flags = new ProcedureFlags(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		reader.align4();
		return result;
	}

	/**
	 * Factory for "32St" version of {@link ProcedureStartSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ProcedureStartSymbolInternals parse32St(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ProcedureStartSymbolInternals result = new ProcedureStartSymbolInternals(pdb);
		result.parentPointer = reader.parseUnsignedIntVal();
		result.endPointer = reader.parseUnsignedIntVal();
		result.nextPointer = reader.parseUnsignedIntVal();
		result.procedureLength = reader.parseUnsignedIntVal();
		result.debugStartOffset = reader.parseUnsignedIntVal();
		result.debugEndOffset = reader.parseUnsignedIntVal();
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.offset = reader.parseUnsignedIntVal();
		result.segment = pdb.parseSegment(reader);
		result.flags = new ProcedureFlags(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		reader.align4();
		return result;
	}

	protected long parentPointer;
	protected long endPointer;
	protected long nextPointer;
	protected long procedureLength;
	protected long debugStartOffset;
	protected long debugEndOffset;
	protected RecordNumber typeRecordNumber;
	protected long offset;
	protected int segment;
	protected ProcedureFlags flags;
	protected String name;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public ProcedureStartSymbolInternals(AbstractPdb pdb) {
		super(pdb);
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
	 * Returns the next pointer.
	 * @return next pointer.
	 */
	public long getNextPointer() {
		return nextPointer;
	}

	/**
	 * Returns the procedure length.
	 * @return Length.
	 */
	public long getProcedureLength() {
		return procedureLength;
	}

	/**
	 * Returns the debug start offset.
	 * @return Debug start offset.
	 */
	public long getDebugStartOffset() {
		return debugStartOffset;
	}

	/**
	 * Returns the debug end offset.
	 * @return Debug end offset.
	 */
	public long getDebugEndOffset() {
		return debugEndOffset;
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
	 * Returns the {@link ProcedureFlags}.
	 * @return Procedure flags.
	 */
	public ProcedureFlags getFlags() {
		return flags;
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
		StringBuilder prefixBuilder = new StringBuilder();
		StringBuilder postfixBuilder = new StringBuilder();

		prefixBuilder.append(
			String.format(": [%04X:%08X], Length: %08X, ", segment, offset, procedureLength));

		postfixBuilder.append(
			String.format(": %s, %s\n", pdb.getTypeRecord(typeRecordNumber), name));
		postfixBuilder.append(String.format("   Parent: %08X, End: %08X, Next: %08X\n",
			parentPointer, endPointer, nextPointer));
		postfixBuilder.append(String.format("   Debug start: %08X, Debug end: %08X\n",
			debugStartOffset, debugEndOffset));
		postfixBuilder.append(flags.toString());

		builder.insert(0, prefixBuilder);
		builder.append(postfixBuilder);
	}

}
