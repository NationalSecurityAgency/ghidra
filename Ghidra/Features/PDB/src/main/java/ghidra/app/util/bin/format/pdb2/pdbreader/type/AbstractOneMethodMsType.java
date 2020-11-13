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
 * This class represents various flavors of One Method type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractOneMethodMsType extends AbstractMsType implements MsTypeField {

	protected ClassFieldMsAttributes attribute;
	protected RecordNumber procedureTypeRecordNumber;
	protected long offsetInVFTableIfIntroVirtual;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractOneMethodMsType(AbstractPdb pdb, PdbByteReader reader, int recordNumberSize,
			StringParseType strType) throws PdbException {
		super(pdb, reader);
		attribute = new ClassFieldMsAttributes(reader);
		procedureTypeRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		if ((attribute.getProperty() == ClassFieldMsAttributes.Property.INTRO) ||
			(attribute.getProperty() == ClassFieldMsAttributes.Property.INTRO_PURE)) {
			offsetInVFTableIfIntroVirtual = reader.parseUnsignedIntVal();
		}
		else {
			offsetInVFTableIfIntroVirtual = 0;
		}
		name = reader.parseString(pdb, strType);
		reader.skipPadding();
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.  Just outputting something that might be useful.
		// At this time, not doing anything with bind here; don't think it is warranted.
		builder.append("<");
		builder.append(attribute);
		builder.append(": ");
		builder.append(pdb.getTypeRecord(procedureTypeRecordNumber));
		builder.append(",");
		builder.append(offsetInVFTableIfIntroVirtual);
		builder.append(">");
	}

}
