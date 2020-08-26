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
 * This class represents various flavors of Static Member type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractStaticMemberMsType extends AbstractMsType implements MsTypeField {

	protected ClassFieldMsAttributes attribute;
	protected RecordNumber fieldTypeRecordNumber;
	protected String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public AbstractStaticMemberMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.
		builder.append(name);
		pdb.getTypeRecord(fieldTypeRecordNumber).emit(builder, Bind.NONE);
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(attribute);
		myBuilder.append(": ");
		builder.insert(0, myBuilder);
	}

}
