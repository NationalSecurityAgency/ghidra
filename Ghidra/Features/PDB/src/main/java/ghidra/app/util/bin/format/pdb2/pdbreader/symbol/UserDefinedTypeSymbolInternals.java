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
 * This class represents various flavors of Internals of User Defined Type symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class UserDefinedTypeSymbolInternals extends AbstractSymbolInternals {

	/**
	 * Factory for user defined symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static UserDefinedTypeSymbolInternals parse(AbstractPdb pdb, PdbByteReader reader,
			int recordNumberSize, StringParseType strType) throws PdbException {
		UserDefinedTypeSymbolInternals result = new UserDefinedTypeSymbolInternals(pdb);
		result.typeRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		result.name = reader.parseString(pdb, strType);
		return result;
	}

	protected RecordNumber typeRecordNumber;
	protected String name;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public UserDefinedTypeSymbolInternals(AbstractPdb pdb) {
		super(pdb);
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	public RecordNumber getTypeRecordNumber() {
		return typeRecordNumber;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(": ");
		builder.append(pdb.getTypeRecord(typeRecordNumber).toString());
		builder.append(", ");
		builder.append(name);
	}

}
