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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Many Register Variable symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractManyRegisterVariableMsSymbol extends AbstractMsSymbol {

	protected RecordNumber typeRecordNumber;
	protected int count;
	// List of registers is most-significant first.
	protected List<RegisterName> registerNameList = new ArrayList<>();
	protected String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractManyRegisterVariableMsSymbol(AbstractPdb pdb, PdbByteReader reader,
			int recordNumberSize, StringParseType strType) throws PdbException {
		super(pdb, reader);
		// Type index or metadata token
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		count = reader.parseUnsignedByteVal();
		for (int i = 0; i < count; i++) {
			int registerIndex = reader.parseUnsignedByteVal();
			RegisterName registerName = new RegisterName(pdb, registerIndex);
			registerNameList.add(registerName);
		}
		name = reader.parseString(pdb, strType);
		reader.align4();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: ", getSymbolTypeName()));
		DelimiterState ds = new DelimiterState("", ", ");
		for (RegisterName registerName : registerNameList) {
			builder.append(ds.out(true, registerName));
		}
		builder.append(String.format(" %s %s", pdb.getTypeRecord(typeRecordNumber), name));
	}

}
