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

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * An abstract class for a number of specific PDB data types that share certain information.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public abstract class AbstractCobol0MsType extends AbstractMsType {

	protected AbstractTypeIndex parentTypeIndex;
	// TODO: This is made up data.  API and examples are unknown.
	protected byte[] data;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractCobol0MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		parentTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, parentTypeIndex.get()));
		pdb.popDependencyStack();
		data = reader.parseBytesRemaining();
	}

	/**
	 * Returns the type that is pointed to.
	 * @return {@link AbstractMsType} type that is pointed to by this pointer.
	 */
	public AbstractMsType getParentType() {
		return pdb.getTypeRecord(parentTypeIndex.get());
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append("Cobol0MsType\n");
		builder.append(String.format("  parent type index: %s\n", getParentType()));
		builder.append(String.format("  additional data length: %d\n", data.length));
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 */
	protected abstract void create();

}
