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
 * This class represents various flavors of Nested type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractNestedTypeMsType extends AbstractMsType implements MsTypeField {

	protected RecordNumber nestedTypeDefinitionRecordNumber;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractNestedTypeMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
	}

	/**
	 * Returns the name of this nested type.
	 * @return Name of the nested type.
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns the record number of the Nested Type Definition.
	 * @return RecordNumber of the Nested Type Definition.
	 */
	public RecordNumber getNestedTypeDefinitionRecordNumber() {
		return nestedTypeDefinitionRecordNumber;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.
		builder.append(name);
		pdb.getTypeRecord(nestedTypeDefinitionRecordNumber).emit(builder, Bind.NONE);
	}

}
