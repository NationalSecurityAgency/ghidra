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
import ghidra.pdb.pdbreader.AbstractPdb;

/**
 * This class represents various flavors Procedure symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractProcedureMsSymbol extends AbstractMsSymbol {

	protected AbstractProcedureSymbolInternals internals;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractProcedureMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		internals.parse(reader);
	}

	/**
	 * Returns the parent pointer.
	 * @return Parent pointer.
	 */
	public long getParentPointer() {
		return internals.parentPointer;
	}

	/**
	 * Returns the end pointer.
	 * @return End pointer.
	 */
	public long getEndPointer() {
		return internals.endPointer;
	}

	/**
	 * Returns the next pointer.
	 * @return Next pointer.
	 */
	public long getNextPointer() {
		return internals.nextPointer;
	}

	/**
	 * Returns the procedure length.
	 * @return Procedure length.
	 */
	public long getProcedureLength() {
		return internals.procedureLength;
	}

	/**
	 * Returns the debug start offset.
	 * @return Debug start offset.
	 */
	public long getDebugStartOffset() {
		return internals.debugStartOffset;
	}

	/**
	 * Returns the debug end offset.
	 * @return Debug end offset.
	 */
	public long getDebugEndOffset() {
		return internals.debugEndOffset;
	}

	/**
	 * Returns type index.
	 * @return Type index.
	 */
	public int getTypeIndex() {
		return internals.typeIndex;
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return internals.offset;
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	public int getSegment() {
		return internals.segment;
	}

	/**
	 * Returns the {@link ProcedureFlags}.
	 * @return Procedure flags.
	 */
	public ProcedureFlags getFlags() {
		return internals.flags;
	}

	/**
	 * Returns the procedure name.
	 * @return Name.
	 */
	public String getName() {
		return internals.name.get();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSpecialTypeString());
		internals.emit(builder);
		builder.insert(0, getSymbolTypeName());
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #internals}.
	 */
	protected abstract void create();

	/**
	 * Returns the special type string used during Emit.
	 * @return Special type string.
	 */
	protected abstract String getSpecialTypeString();

}
