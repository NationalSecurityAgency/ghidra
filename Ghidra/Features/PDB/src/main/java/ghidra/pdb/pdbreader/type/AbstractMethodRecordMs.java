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
package ghidra.pdb.pdbreader.type;

import ghidra.pdb.*;
import ghidra.pdb.pdbreader.*;

/**
 * An abstract class for a number of specific PDB data types that share certain information.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public abstract class AbstractMethodRecordMs extends AbstractParsableItem {

	protected AbstractPdb pdb;
	protected ClassFieldMsAttributes attributes;
	protected AbstractTypeIndex procedureRecordNumber;
	protected long optionalOffset;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractMethodRecordMs(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		this.pdb = pdb;
		create();
		parseFields(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, procedureRecordNumber.get()));
		pdb.popDependencyStack();
	}

	@Override
	public void emit(StringBuilder builder) {
		// Making this up; no API for output.
		builder.append("<");
		builder.append(attributes);
		builder.append(": ");
		builder.append(pdb.getTypeRecord(procedureRecordNumber.get()));
		if (attributes.getPropertyVal() == 4) {
			builder.append(",");
			builder.append(optionalOffset);
		}
		builder.append(">");
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 */
	protected abstract void create();

	/**
	 * Parses the fields for this type.
	 * @param reader {@link PdbByteReader} from which the fields are parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseFields(PdbByteReader reader) throws PdbException;

}
