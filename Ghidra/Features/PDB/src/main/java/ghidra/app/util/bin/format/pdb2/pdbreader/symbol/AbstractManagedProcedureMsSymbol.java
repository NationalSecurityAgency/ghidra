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
 * This class represents various flavors of Managed Procedure symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractManagedProcedureMsSymbol extends AbstractMsSymbol
		implements AddressMsSymbol, NameMsSymbol {

	protected long parentPointer;
	protected long endPointer;
	protected long nextPointer;
	protected long procedureLength;
	protected long debugStartOffset;
	protected long debugEndOffset;
	protected long token;
	protected long symbolOffset;
	protected int symbolSegment;
	protected ProcedureFlags procedureFlags;
	protected int registerIndexContainingReturnValue;
	protected RegisterName registerContainingReturnValue;
	protected String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractManagedProcedureMsSymbol(AbstractPdb pdb, PdbByteReader reader,
			StringParseType strType) throws PdbException {
		super(pdb, reader);
		parentPointer = reader.parseUnsignedIntVal();
		endPointer = reader.parseUnsignedIntVal();
		nextPointer = reader.parseUnsignedIntVal();
		procedureLength = reader.parseUnsignedIntVal();
		debugStartOffset = reader.parseUnsignedIntVal();
		debugEndOffset = reader.parseUnsignedIntVal();
		token = reader.parseUnsignedIntVal();
		symbolOffset = reader.parseUnsignedIntVal();
		symbolSegment = pdb.parseSegment(reader);
		procedureFlags = new ProcedureFlags(reader);
		registerIndexContainingReturnValue = reader.parseUnsignedShortVal();
		registerContainingReturnValue = new RegisterName(pdb, registerIndexContainingReturnValue);
		name = reader.parseString(pdb, strType);
	}

	@Override
	public void emit(StringBuilder builder) {
		// TODO: need to do more with token map and with debug data in pdb.
		//  Need "Token: %0xX (mapped to %08X), "
		builder.append(String.format("%s: [%04X:%08X], Length: %08X, Token: %s, ",
			getSymbolTypeName(), symbolSegment, symbolOffset, procedureLength, token));
		builder.append(name);
		builder.append(String.format("   Parent: %08X, End: %08X, Next: %08X\n", parentPointer,
			endPointer, nextPointer));
		builder.append(String.format("   Debug start: %08X, Debug end: %08X\n", debugStartOffset,
			debugEndOffset));
		builder.append(String.format("   %s\n", procedureFlags));
		builder.append(String.format("   Return Reg: %s\n", registerContainingReturnValue));
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
	 * Returns the {@link ProcedureFlags}.
	 * @return Procedure flags.
	 */
	public ProcedureFlags getFlags() {
		return procedureFlags;
	}

	/**
	 * Returns the procedure name.
	 * @return Name.
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns the token.
	 * @return token.
	 */
	public long getToken() {
		return token;
	}

	/**
	 * Returns the register containing the return value
	 * @return the register.
	 */
	public RegisterName getReturnRegister() {
		return registerContainingReturnValue;
	}

}
