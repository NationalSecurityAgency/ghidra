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
public abstract class AbstractDimensionedArrayConstBoundsUpperMsType extends AbstractMsType {

	protected int rank;
	protected AbstractTypeIndex typeIndex;
	// TODO: dimData is unknown.  Needs analysis and implementation break-out.
	protected long[] upperBound;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractDimensionedArrayConstBoundsUpperMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		parseBeginningFields(reader);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex.get()));
		pdb.popDependencyStack();
		// TODO: fix all of this once we know the true size of each (assuming it is fixed).
		byte[] remainingData = reader.parseBytesRemaining();
		PdbByteReader boundsReader = new PdbByteReader(remainingData);
		int length = remainingData.length;
		assert (length % rank) == 0;
		upperBound = new long[rank];
		int size = length / rank;
		switch (size) {
			case 1:
				for (int i = 0; i < rank; i++) {
					upperBound[i] = boundsReader.parseUnsignedByteVal();
				}
				break;
			case 2:
				for (int i = 0; i < rank; i++) {
					upperBound[i] = boundsReader.parseShort();
				}
				break;
			case 4:
				for (int i = 0; i < rank; i++) {
					upperBound[i] = boundsReader.parseInt();
				}
				break;
			case 8:
				for (int i = 0; i < rank; i++) {
					upperBound[i] = boundsReader.parseLong();
				}
				break;
			default:
				assert false;
		}
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No documented API for output.
		pdb.getTypeRecord(typeIndex.get()).emit(builder, Bind.NONE);
		for (int i = 0; i < rank; i++) {
			builder.append("[0:");
			builder.append(upperBound[i]);
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

}
