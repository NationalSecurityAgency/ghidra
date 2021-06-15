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
 * This class represents various flavors of Register symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractRegisterMsSymbol extends AbstractMsSymbol {

	protected RecordNumber recordNumber;
	protected RegisterName register;
	protected String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractRegisterMsSymbol(AbstractPdb pdb, PdbByteReader reader, int recordNumberSize,
			StringParseType strType) throws PdbException {
		super(pdb, reader);
		recordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		register = parseRegister(reader);
		name = reader.parseString(pdb, strType);
		reader.align4();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(": ");
		emitRegisterInformation(builder);
		builder.append(", Type: ");
		builder.append(pdb.getTypeRecord(recordNumber));
		builder.append(", ");
		builder.append(name);
	}

	/**
	 * Parses the register field for this symbol.
	 * @param reader {@link PdbByteReader} from which the data is parsed.
	 * @return The register field.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract RegisterName parseRegister(PdbByteReader reader) throws PdbException;

	/**
	 * Emits the register information to the {@link StringBuilder}
	 * @param builder {@link StringBuilder} to which the data is emitted.
	 */
	protected abstract void emitRegisterInformation(StringBuilder builder);

}
