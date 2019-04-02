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

import java.math.BigInteger;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.AbstractString;

/**
 * An abstract class for a number of specific PDB data types that share certain information.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public abstract class AbstractEnumerateMsType extends AbstractMsType {

	protected ClassFieldMsAttributes attribute;
	protected BigInteger numeric;
	protected AbstractString name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractEnumerateMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		attribute = new ClassFieldMsAttributes(reader);
		numeric = reader.parseNumeric();
		name.parse(reader);
		reader.align4();
	}

	/**
	 * Returns the name of this enumerate type.
	 * @return Name type of the enumerate type.
	 */
	@Override
	public String getName() {
		return name.get();
	}

	/**
	 * Returns the numeric value of this Enumerate
	 * @return The value of this Enumerate.
	 */
	public BigInteger getNumeric() {
		return numeric;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// Attribute and space are not in API.
		builder.append(attribute);
		builder.append(": ");
		builder.append(name);
		builder.append("=");
		builder.append(numeric);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 */
	protected abstract void create();

}
