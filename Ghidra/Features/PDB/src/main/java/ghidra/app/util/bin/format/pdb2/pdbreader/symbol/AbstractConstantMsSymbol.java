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
 * This class represents various flavors of Constant symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractConstantMsSymbol extends AbstractMsSymbol implements NameMsSymbol {

	protected RecordNumber typeRecordNumber;
	protected Numeric value;
	protected String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractConstantMsSymbol(AbstractPdb pdb, PdbByteReader reader, int recordNumberSize,
			StringParseType strType) throws PdbException {
		super(pdb, reader);
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		value = new Numeric(reader); //value = reader.parseUnsignedShortVal();
		name = reader.parseString(pdb, strType);
	}

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	public RecordNumber getTypeRecordNumber() {
		return typeRecordNumber;
	}

	/**
	 * Returns the Numeric value.
	 * @return Numeric value.
	 */
	public Numeric getValue() {
		return value;
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
		builder.append(getSymbolTypeName());
		builder.append(": Type: ");
		builder.append(pdb.getTypeRecord(typeRecordNumber).toString());
		builder.append(", Value: ");
		builder.append(value);
		builder.append(", ");
		builder.append(name);
	}

}
