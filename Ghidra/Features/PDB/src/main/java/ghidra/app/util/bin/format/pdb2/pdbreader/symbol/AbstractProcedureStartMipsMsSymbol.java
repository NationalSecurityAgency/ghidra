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
 * This class represents various flavors Procedure Start MIPS symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractProcedureStartMipsMsSymbol extends AbstractProcedureMsSymbol {

	protected ProcedureStartMipsSymbolInternals internals;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param internals the internal structure to be used for this symbol.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractProcedureStartMipsMsSymbol(AbstractPdb pdb, PdbByteReader reader,
			ProcedureStartMipsSymbolInternals internals) throws PdbException {
		super(pdb, reader);
		this.internals = internals;
	}

	/**
	 * Returns the parent pointer.
	 * @return Parent pointer.
	 */
	@Override
	public long getParentPointer() {
		return internals.getParentPointer();
	}

	/**
	 * Returns the end pointer.
	 * @return End pointer.
	 */
	@Override
	public long getEndPointer() {
		return internals.getEndPointer();
	}

	/**
	 * Returns the next pointer.
	 * @return next pointer.
	 */
	@Override
	public long getNextPointer() {
		return internals.getNextPointer();
	}

	/**
	 * Returns the procedure length.
	 * @return Length.
	 */
	@Override
	public long getProcedureLength() {
		return internals.getProcedureLength();
	}

	/**
	 * Returns the debug start offset.
	 * @return Debug start offset.
	 */
	@Override
	public long getDebugStartOffset() {
		return internals.getDebugStartOffset();
	}

	/**
	 * Returns the debug end offset.
	 * @return Debug end offset.
	 */
	@Override
	public long getDebugEndOffset() {
		return internals.getDebugEndOffset();
	}

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	@Override
	public RecordNumber getTypeRecordNumber() {
		return internals.getTypeRecordNumber();
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	@Override
	public long getOffset() {
		return internals.getOffset();
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	@Override
	public int getSegment() {
		return internals.getSegment();
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	@Override
	public String getName() {
		return internals.getName();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSpecialTypeString());
		internals.emit(builder);
		builder.insert(0, getSymbolTypeName());
	}

	/**
	 * Returns the special type string used during Emit.
	 * @return Special type string.
	 */
	protected abstract String getSpecialTypeString();

}
