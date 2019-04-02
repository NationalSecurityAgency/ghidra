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

import java.util.ArrayList;
import java.util.List;

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
public abstract class AbstractDimensionedArrayVarBoundsLowerUpperMsType extends AbstractMsType {

	protected int rank;
	protected AbstractTypeIndex typeIndex;
	// TODO: dim is unknown.  Needs analysis and implementation break-out.
	protected List<AbstractTypeIndex> lowerBound = new ArrayList<>();
	protected List<AbstractTypeIndex> upperBound = new ArrayList<>();

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractDimensionedArrayVarBoundsLowerUpperMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		parseBeginningFields(reader);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex.get()));
		pdb.popDependencyStack();
		for (int i = 0; i < rank; i++) {
			AbstractTypeIndex lowerTypeIndex = parseTypeIndex(reader);
			pdb.pushDependencyStack(
				new CategoryIndex(CategoryIndex.Category.DATA, lowerTypeIndex.get()));
			pdb.popDependencyStack();
			assert ((pdb.getTypeRecord(lowerTypeIndex.get()) instanceof ReferencedSymbolMsType) ||
				(lowerTypeIndex.get() == 3));
			lowerBound.add(lowerTypeIndex);
			AbstractTypeIndex upperTypeIndex = parseTypeIndex(reader);
			pdb.pushDependencyStack(
				new CategoryIndex(CategoryIndex.Category.DATA, upperTypeIndex.get()));
			pdb.popDependencyStack();
			assert ((pdb.getTypeRecord(upperTypeIndex.get()) instanceof ReferencedSymbolMsType) ||
				(upperTypeIndex.get() == 3));
			upperBound.add(upperTypeIndex);
		}
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No documented API for output.
		pdb.getTypeRecord(typeIndex.get()).emit(builder, Bind.NONE);
		for (int i = 0; i < rank; i++) {
			builder.append("[");
			builder.append(pdb.getTypeRecord(lowerBound.get(i).get()));
			builder.append(":");
			builder.append(pdb.getTypeRecord(upperBound.get(i).get()));
			builder.append("]");
		}
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 */
	protected abstract void create();

	/**
	 * Parses the initial fields for this type.
	 * @param reader {@link PdbByteReader} from which the beginning fields are parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseBeginningFields(PdbByteReader reader) throws PdbException;

	/**
	 * Parses a type index field for this type
	 * @param reader {@link PdbByteReader} from which the type index is parsed.
	 * @return {@link AbstractTypeIndex} type index parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract AbstractTypeIndex parseTypeIndex(PdbByteReader reader) throws PdbException;

}
