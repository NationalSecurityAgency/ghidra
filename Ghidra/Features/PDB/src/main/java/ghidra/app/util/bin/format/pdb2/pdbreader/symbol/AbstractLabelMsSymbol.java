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
 * This class represents various flavors of Label symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractLabelMsSymbol extends AbstractMsSymbol
		implements AddressMsSymbol, NameMsSymbol {

	protected long offset;
	protected int segment;
	protected ProcedureFlags flags;
	protected String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param offsetSize size of offset to parse.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractLabelMsSymbol(AbstractPdb pdb, PdbByteReader reader, int offsetSize,
			StringParseType strType) throws PdbException {
		super(pdb, reader);
		offset = reader.parseVarSizedOffset(offsetSize);
		segment = pdb.parseSegment(reader);
		flags = new ProcedureFlags(reader);
		name = reader.parseString(pdb, strType);
		reader.align4();
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	@Override
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	@Override
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
	@Override
	public String getName() {
		return name;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], %s %s\n", getSymbolTypeName(), segment,
			offset, name, flags.toString()));
	}

}
