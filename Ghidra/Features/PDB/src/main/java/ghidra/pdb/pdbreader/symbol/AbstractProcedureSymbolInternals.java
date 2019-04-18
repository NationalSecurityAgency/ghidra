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
 * This class represents various flavors of Internals of the Procedure symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractProcedureSymbolInternals extends AbstractSymbolInternals {

	protected long parentPointer;
	protected long endPointer;
	protected long nextPointer;
	protected long procedureLength;
	protected long debugStartOffset;
	protected long debugEndOffset;
	protected int typeIndex;
	protected long offset;
	protected int segment;
	protected ProcedureFlags flags;
	protected AbstractString name;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public AbstractProcedureSymbolInternals(AbstractPdb pdb) {
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
	 * Returns the type index.
	 * @return Type index.
	 */
	public int getTypeIndex() {
		return typeIndex;
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
		return name.get();
	}

	@Override
	public void parse(PdbByteReader reader) throws PdbException {
		parentPointer = reader.parseUnsignedIntVal();
		endPointer = reader.parseUnsignedIntVal();
		nextPointer = reader.parseUnsignedIntVal();
		parseMiddleFields(reader);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex));
		pdb.popDependencyStack();
		flags = new ProcedureFlags(reader);
		name.parse(reader);
		reader.align4();
	}

	@Override
	public void emit(StringBuilder builder) {
		StringBuilder prefixBuilder = new StringBuilder();
		StringBuilder postfixBuilder = new StringBuilder();

		prefixBuilder.append(
			String.format(": [%04X:%08X], Length: %08X, ", segment, offset, procedureLength));

		postfixBuilder.append(
			String.format(": %s, %s\n", pdb.getTypeRecord(typeIndex), name.get()));
		postfixBuilder.append(String.format("   Parent: %08X, End: %08X, Next: %08X\n",
			parentPointer, endPointer, nextPointer));
		postfixBuilder.append(String.format("   Debug start: %08X, Debug end: %08X\n",
			debugStartOffset, debugEndOffset));
		postfixBuilder.append(flags.toString());

		builder.insert(0, prefixBuilder);
		builder.append(postfixBuilder);
	}

	/**
	 * Internal method for parsing the middle range of fields in the data.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseMiddleFields(PdbByteReader reader) throws PdbException;

}
