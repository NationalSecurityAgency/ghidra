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
 * This class represents various flavors of Basic Array type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractBasicArrayMsType extends AbstractMsType {

	protected RecordNumber underlyingRecordNumber;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractBasicArrayMsType(AbstractPdb pdb, PdbByteReader reader, int recordNumberSize)
			throws PdbException {
		super(pdb, reader);
		underlyingRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
	}

	/**
	 * Returns the record number of the underlying type.
	 * @return The record number of the underlying type.
	 */
	public RecordNumber getModifiedRecordNumber() {
		return underlyingRecordNumber;
	}

	/**
	 * Returns the type that is pointed to.
	 * @return {@link AbstractMsType} type that is pointed to by this pointer.
	 */
	public AbstractMsType getUnderlyingType() {
		return pdb.getTypeRecord(underlyingRecordNumber);
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// TODO: This might be wrong.  I'm using bind twice.  Revisit.
		getUnderlyingType().emit(builder, bind);
		if (bind.ordinal() < Bind.ARRAY.ordinal()) {
			builder.insert(0, "(");
			builder.append(")");
		}
		builder.append("[]");
	}

}
