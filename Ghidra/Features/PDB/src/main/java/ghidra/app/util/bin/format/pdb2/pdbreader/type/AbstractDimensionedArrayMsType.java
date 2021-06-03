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
 * This class represents various flavors of Dimensioned Array type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDimensionedArrayMsType extends AbstractMsType {

	protected RecordNumber elementRecordNumber;
	protected RecordNumber dimensionInformationRecordNumber;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractDimensionedArrayMsType(AbstractPdb pdb, PdbByteReader reader,
			int recordNumberSize, StringParseType strType) throws PdbException {
		super(pdb, reader);
		elementRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		dimensionInformationRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		name = reader.parseString(pdb, strType);
		reader.skipPadding();
	}

	/**
	 * Returns the element type of this array.
	 * @return The AbstractMsType that is the base element type of the array.
	 */
	public AbstractMsType getElementType() {
		return pdb.getTypeRecord(elementRecordNumber);
	}

	/**
	 * Returns the record number of the dimension information of this array.
	 * @return The record number dimension information of the array.
	 */
	public RecordNumber getDimensionInformationRecordNumber() {
		return dimensionInformationRecordNumber;
	}

	/**
	 * Returns the {@link AbstractMsType} dimension information.
	 * @return The dimension information.
	 */
	public AbstractMsType getDimensionInformation() {
		return pdb.getTypeRecord(dimensionInformationRecordNumber);
	}

	/**
	 * Returns the name of this dimensioned array.
	 * @return Name of the dimensioned array.
	 */
	@Override
	public String getName() {
		return name;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		if (bind.ordinal() < Bind.ARRAY.ordinal()) {
			builder.insert(0, "(");
			builder.append(")");
		}
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append("<");
		myBuilder.append(getDimensionInformation());
		myBuilder.append(">");

		builder.append("[");
		builder.append(myBuilder);
		builder.append("]");

		getElementType().emit(builder, Bind.ARRAY);
	}

}
