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

import java.util.Objects;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Method Records.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractMethodRecordMs extends AbstractParsableItem {

	protected AbstractPdb pdb;
	protected ClassFieldMsAttributes attributes;
	protected RecordNumber procedureRecordNumber;
	protected long optionalOffset;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractMethodRecordMs(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	@Override
	public void emit(StringBuilder builder) {
		// Making this up; no API for output.
		builder.append("<");
		builder.append(attributes);
		builder.append(": ");
		builder.append(pdb.getTypeRecord(procedureRecordNumber));
		if (attributes.getProperty() == ClassFieldMsAttributes.Property.INTRO) {
			builder.append(",");
			builder.append(optionalOffset);
		}
		builder.append(">");
	}

}
