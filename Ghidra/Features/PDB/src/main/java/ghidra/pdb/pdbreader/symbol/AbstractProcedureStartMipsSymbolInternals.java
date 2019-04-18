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
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Internals of the Procedure Start MIPS symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractProcedureStartMipsSymbolInternals extends AbstractSymbolInternals {

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
	protected int typeIndex;
	protected long symbolOffset;
	protected int symbolSegment;

	// We are using RegisterName (instead of as MSFT API shows of going directly to MIPS register
	//  table.  Hope this works fine.
	protected int indexOfRegisterContainingReturnValue;
	protected RegisterName registerContainingReturnValue;
	protected int indexOfRegisterContainingFramePointer;
	protected RegisterName registerContainingFramePointer;

	protected AbstractString name;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public AbstractProcedureStartMipsSymbolInternals(AbstractPdb pdb) {
		super(pdb);
	}

	@Override
	public void emit(StringBuilder builder) {
		StringBuilder prefixBuilder = new StringBuilder();
		StringBuilder postfixBuilder = new StringBuilder();

		prefixBuilder.append(String.format(": [%04X:%08X], Length: %08X, ", symbolSegment,
			symbolOffset, procedureLength));

		postfixBuilder.append(String.format(": %s, ", pdb.getTypeRecord(typeIndex)));
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

	@Override
	public void parse(PdbByteReader reader) throws PdbException {
		parentPointer = reader.parseUnsignedIntVal();
		endPointer = reader.parseUnsignedIntVal();
		nextPointer = reader.parseUnsignedIntVal();
		procedureLength = reader.parseUnsignedIntVal();
		debugStartOffset = reader.parseUnsignedIntVal();
		debugEndOffset = reader.parseUnsignedIntVal();
		integerRegisterSaveMask = reader.parseUnsignedIntVal();
		floatingPointRegisterSaveMask = reader.parseUnsignedIntVal();
		integerRegisterSaveOffset = reader.parseUnsignedIntVal();
		floatingPointRegisterSaveOffset = reader.parseUnsignedIntVal();

		parseTypeIndexAndSymbolSegmentOffset(reader);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex));
		pdb.popDependencyStack();

		indexOfRegisterContainingReturnValue = reader.parseUnsignedByteVal();
		registerContainingReturnValue = new RegisterName(pdb, indexOfRegisterContainingReturnValue);

		indexOfRegisterContainingFramePointer = reader.parseUnsignedByteVal();
		registerContainingFramePointer =
			new RegisterName(pdb, indexOfRegisterContainingFramePointer);

		name.parse(reader);
	}

	/**
	 * Internal method for parsing the type index and symbol segment and offset.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseTypeIndexAndSymbolSegmentOffset(PdbByteReader reader)
			throws PdbException;

}
