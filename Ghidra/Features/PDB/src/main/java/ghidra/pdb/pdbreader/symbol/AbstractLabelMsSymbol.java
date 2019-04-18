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
 * This class represents various flavors of Label symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractLabelMsSymbol extends AbstractMsSymbol {

	protected AbstractOffset offset;
	protected int segment;
	protected ProcedureFlags flags;
	protected AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractLabelMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		offset.parse(reader);
		segment = reader.parseUnsignedShortVal();
		flags = new ProcedureFlags(reader);
		name.parse(reader);
		reader.align4();
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

	/** Returns the {@link ProcedureFlags}.
	 * @return Procedure flags.
	 */
	public ProcedureFlags getProcedureFlags() {
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
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], %s %s\n", getSymbolTypeName(), segment,
			offset.get(), name.get(), flags.toString()));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #offset} and {@link #name}.
	 */
	protected abstract void create();

}
