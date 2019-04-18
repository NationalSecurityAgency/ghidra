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
 * This class represents various flavors of With symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractWithMsSymbol extends AbstractMsSymbol {

	protected long parentPointer;
	protected long endPointer;
	protected AbstractOffset length;
	protected AbstractOffset offset;
	protected int segment;
	protected AbstractString expression;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractWithMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		parentPointer = reader.parseUnsignedIntVal();
		endPointer = reader.parseUnsignedIntVal();
		length.parse(reader);
		offset.parse(reader);
		segment = reader.parseUnsignedShortVal();
		expression.parse(reader);
		reader.align4();
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
	 * Returns the length.
	 * @return Length.
	 */
	public long getLength() {
		return length.get();
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return offset.get();
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	public int getSegment() {
		return segment;
	}

	/**
	 * Returns the expression.
	 * @return Expression.
	 */
	public String getExpression() {
		return expression.get();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(String.format(": [%04X:%08X], Length: %08X, %s\n", segment, offset.get(),
			length.get(), expression.get()));
		builder.append(String.format("   Parent: %08X, End: %08X\n", parentPointer, endPointer));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #length}, {@link #offset}, and {@link #expression}.
	 */
	protected abstract void create();

}
