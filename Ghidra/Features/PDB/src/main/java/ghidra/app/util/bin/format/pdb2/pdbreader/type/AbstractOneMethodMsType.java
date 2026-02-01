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

	protected ClassFieldMsAttributes attributes;
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
		attributes = new ClassFieldMsAttributes(reader);
		procedureTypeRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		if ((attributes.getProperty() == ClassFieldMsAttributes.Property.INTRO) ||
			(attributes.getProperty() == ClassFieldMsAttributes.Property.INTRO_PURE)) {
			offsetInVFTableIfIntroVirtual = reader.parseUnsignedIntVal();
		}
		else {
			// 20250310: changed this from 0 to -1 to match "MethodRecord" types
			offsetInVFTableIfIntroVirtual = -1;
		}
		name = reader.parseString(pdb, strType);
		reader.skipPadding();
	}

	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns the record number of the data type for this procedure
	 * @return the record number
	 */
	public RecordNumber getProcedureTypeRecordNumber() {
		return procedureTypeRecordNumber;
	}

	/**
	 * Returns the attributes of this procedure
	 * @return the attributes
	 */
	public ClassFieldMsAttributes getAttributes() {
		return attributes;
	}

	/**
	 * Returns the offset of the procedure in the VFTable if intro/virtual
	 * @return the offset
	 */
	public long getOffsetInVFTableIfIntroVirtual() {
		return offsetInVFTableIfIntroVirtual;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.  Just outputting something that might be useful.
		// At this time, not doing anything with bind here; don't think it is warranted.
		builder.append("<");
		builder.append(attributes);
		builder.append(": ");
		builder.append(pdb.getTypeRecord(procedureTypeRecordNumber));
		if (offsetInVFTableIfIntroVirtual != -1) {
			builder.append(",");
			builder.append(offsetInVFTableIfIntroVirtual);
		}
		builder.append(">");
	}

}
