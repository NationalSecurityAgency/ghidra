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
 * This class represents various flavors of Procedure Start IA64 symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractProcedureStartIa64MsSymbol extends AbstractProcedureMsSymbol {

	protected long parentPointer;
	protected long endPointer;
	protected long nextPointer;
	protected long procedureLength;
	protected long debugStartOffset;
	protected long debugEndOffset;
	protected RecordNumber typeRecordNumber;
	protected long symbolOffset;
	protected int symbolSegment;
	protected int registerIndexContainingReturnValue;
	protected RegisterName registerContainingReturnValue;
	protected ProcedureFlags procedureFlags;
	protected String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractProcedureStartIa64MsSymbol(AbstractPdb pdb, PdbByteReader reader,
			StringParseType strType) throws PdbException {
		super(pdb, reader);
		parentPointer = reader.parseUnsignedIntVal();
		endPointer = reader.parseUnsignedIntVal();
		nextPointer = reader.parseUnsignedIntVal();
		procedureLength = reader.parseUnsignedIntVal();
		debugStartOffset = reader.parseUnsignedIntVal();
		debugEndOffset = reader.parseUnsignedIntVal();
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		symbolOffset = reader.parseUnsignedIntVal();
		symbolSegment = pdb.parseSegment(reader);
		registerIndexContainingReturnValue = reader.parseUnsignedShortVal();
		registerContainingReturnValue = new RegisterName(pdb, registerIndexContainingReturnValue);
		procedureFlags = new ProcedureFlags(reader);
		name = reader.parseString(pdb, strType);
	}

	/**
	 * Returns the parent pointer.
	 * @return Parent pointer.
	 */
	@Override
	public long getParentPointer() {
		return parentPointer;
	}

	/**
	 * Returns the end pointer.
	 * @return End pointer.
	 */
	@Override
	public long getEndPointer() {
		return endPointer;
	}

	/**
	 * Returns the next pointer.
	 * @return next pointer.
	 */
	@Override
	public long getNextPointer() {
		return nextPointer;
	}

	/**
	 * Returns the procedure length.
	 * @return Length.
	 */
	@Override
	public long getProcedureLength() {
		return procedureLength;
	}

	/**
	 * Returns the debug start offset.
	 * @return Debug start offset.
	 */
	@Override
	public long getDebugStartOffset() {
		return debugStartOffset;
	}

	/**
	 * Returns the debug end offset.
	 * @return Debug end offset.
	 */
	@Override
	public long getDebugEndOffset() {
		return debugEndOffset;
	}

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	@Override
	public RecordNumber getTypeRecordNumber() {
		return typeRecordNumber;
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	@Override
	public long getOffset() {
		return symbolOffset;
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	@Override
	public int getSegment() {
		return symbolSegment;
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
		builder.append(String.format("%s: [%04X:%08X], Length: %08X, %s: %s, ", getSymbolTypeName(),
			symbolSegment, symbolOffset, procedureLength, getSpecialTypeString(),
			pdb.getTypeRecord(typeRecordNumber)));
		builder.append(name);
		builder.append(String.format("   Parent: %08X, End: %08X, Next: %08X\n", parentPointer,
			endPointer, nextPointer));
		builder.append(String.format("   Debug start: %08X, Debug end: %08X\n", debugStartOffset,
			debugEndOffset));
		builder.append(String.format("   %s\n", procedureFlags));
		builder.append(String.format("   Return Reg: %s\n", registerContainingReturnValue));
	}

	/**
	 * Returns the special type string used during Emit.
	 * @return Special type string.
	 */
	protected abstract String getSpecialTypeString();

}
