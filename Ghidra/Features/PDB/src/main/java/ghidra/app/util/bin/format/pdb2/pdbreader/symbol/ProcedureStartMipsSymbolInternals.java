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
 * This class represents various flavors of Internals of the Procedure Start MIPS symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ProcedureStartMipsSymbolInternals extends AbstractSymbolInternals {

	/**
	 * Factory for "16" version of {@link ProcedureStartMipsSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ProcedureStartMipsSymbolInternals parse(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ProcedureStartMipsSymbolInternals result = new ProcedureStartMipsSymbolInternals(pdb);
		parseInitialFields(pdb, reader, result);
		// Note parsing order and sizes.
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.symbolOffset = reader.parseUnsignedIntVal();
		result.symbolSegment = pdb.parseSegment(reader);
		parseMoreFields(pdb, reader, result);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		return result;
	}

	/**
	 * Factory for "32" version of {@link ProcedureStartMipsSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ProcedureStartMipsSymbolInternals parse16(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ProcedureStartMipsSymbolInternals result = new ProcedureStartMipsSymbolInternals(pdb);
		parseInitialFields(pdb, reader, result);
		// Note parsing order and sizes.
		result.symbolOffset = reader.parseUnsignedIntVal();
		result.symbolSegment = pdb.parseSegment(reader);
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		parseMoreFields(pdb, reader, result);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		return result;
	}

	/**
	 * Factory for "3216" version of {@link ProcedureStartMipsSymbolInternals}.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static ProcedureStartMipsSymbolInternals parseSt(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		ProcedureStartMipsSymbolInternals result = new ProcedureStartMipsSymbolInternals(pdb);
		parseInitialFields(pdb, reader, result);
		// Note parsing order and sizes.
		result.typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		result.symbolOffset = reader.parseUnsignedIntVal();
		result.symbolSegment = pdb.parseSegment(reader);
		parseMoreFields(pdb, reader, result);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		return result;
	}

	private static void parseInitialFields(AbstractPdb pdb, PdbByteReader reader,
			ProcedureStartMipsSymbolInternals result) throws PdbException {
		result.parentPointer = reader.parseUnsignedIntVal();
		result.endPointer = reader.parseUnsignedIntVal();
		result.nextPointer = reader.parseUnsignedIntVal();
		result.procedureLength = reader.parseUnsignedIntVal();
		result.debugStartOffset = reader.parseUnsignedIntVal();
		result.debugEndOffset = reader.parseUnsignedIntVal();
		result.integerRegisterSaveMask = reader.parseUnsignedIntVal();
		result.floatingPointRegisterSaveMask = reader.parseUnsignedIntVal();
		result.integerRegisterSaveOffset = reader.parseUnsignedIntVal();
		result.floatingPointRegisterSaveOffset = reader.parseUnsignedIntVal();
	}

	private static void parseMoreFields(AbstractPdb pdb, PdbByteReader reader,
			ProcedureStartMipsSymbolInternals result) throws PdbException {
		result.indexOfRegisterContainingReturnValue = reader.parseUnsignedByteVal();
		result.registerContainingReturnValue =
			new RegisterName(pdb, result.indexOfRegisterContainingReturnValue);
		result.indexOfRegisterContainingFramePointer = reader.parseUnsignedByteVal();
		result.registerContainingFramePointer =
			new RegisterName(pdb, result.indexOfRegisterContainingFramePointer);
	}

	protected long parentPointer;
	protected long endPointer;
	protected long nextPointer;
	protected long procedureLength;
	protected long debugStartOffset;
	protected long debugEndOffset;
	protected long integerRegisterSaveMask;
	protected long floatingPointRegisterSaveMask;
	protected long integerRegisterSaveOffset;
	protected long floatingPointRegisterSaveOffset;

	// The following have different sizes and order of parsing in parent versus child classes.
	protected RecordNumber typeRecordNumber;
	protected long symbolOffset;
	protected int symbolSegment;

	// We are using RegisterName (instead of as MSFT API shows of going directly to MIPS register
	//  table.  Hope this works fine.
	protected int indexOfRegisterContainingReturnValue;
	protected RegisterName registerContainingReturnValue;
	protected int indexOfRegisterContainingFramePointer;
	protected RegisterName registerContainingFramePointer;

	protected String name;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public ProcedureStartMipsSymbolInternals(AbstractPdb pdb) {
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
		return symbolOffset;
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	public int getSegment() {
		return symbolSegment;
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

		prefixBuilder.append(String.format(": [%04X:%08X], Length: %08X, ", symbolSegment,
			symbolOffset, procedureLength));

		postfixBuilder.append(String.format(": %s, ", pdb.getTypeRecord(typeRecordNumber)));
		postfixBuilder.append(String.format("   Parent: %08X, End: %08X, Next: %08X\n",
			parentPointer, endPointer, nextPointer));
		postfixBuilder.append(String.format("   Debug start: %08X, Debug end: %08X\n",
			debugStartOffset, debugEndOffset));
		postfixBuilder.append(
			String.format("   Reg Save: %08X, FP Save: %08X, Int Offset: %08X, FP Offset: %08X\n",
				integerRegisterSaveMask, floatingPointRegisterSaveMask, integerRegisterSaveOffset,
				floatingPointRegisterSaveOffset));
		postfixBuilder.append(String.format("   Return Reg: %s, Frame Reg: %s\n",
			registerContainingReturnValue, registerContainingFramePointer));

		builder.insert(0, prefixBuilder);
		builder.append(postfixBuilder);
	}

}
