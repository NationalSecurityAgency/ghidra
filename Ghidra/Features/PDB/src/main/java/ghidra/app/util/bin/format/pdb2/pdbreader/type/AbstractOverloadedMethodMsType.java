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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Overloaded Method type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractOverloadedMethodMsType extends AbstractMsType implements MsTypeField {

	protected int count;
	protected RecordNumber methodListRecordNumber;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractOverloadedMethodMsType(AbstractPdb pdb, PdbByteReader reader,
			int recordNumberSize, StringParseType strType) throws PdbException {
		super(pdb, reader);
		count = reader.parseUnsignedShortVal();
		methodListRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		name = reader.parseString(pdb, strType);

	}

	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns the number of methods overloaded with the name
	 * @return the number of methods
	 */
	public int getCount() {
		return count;
	}

	/**
	 * Returns the record number of the method list for this overloaded method name
	 * @return the record number
	 */
	public RecordNumber getTypeMethodListRecordNumber() {
		return methodListRecordNumber;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.  Just outputting something that might be useful.
		// At this time, not doing anything with bind here; don't think it is warranted.
		builder.append("overloaded[");
		builder.append(count);
		builder.append("]:");
		builder.append(name);
		builder.append(pdb.getTypeRecord(methodListRecordNumber));
	}

}
