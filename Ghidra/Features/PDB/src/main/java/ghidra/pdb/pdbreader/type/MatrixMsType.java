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
import ghidra.pdb.pdbreader.*;

public class MatrixMsType extends AbstractMsType {

	public static final int PDB_ID = 0x151c;

	private AbstractTypeIndex elementTypeIndex;
	private long numRows;
	private long numColumns;
	private long majorStride;
	private boolean rowMajor; // default is column-major
	//TODO: not sure about the following.
	private BigInteger size;
	private AbstractString name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public MatrixMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		elementTypeIndex = new TypeIndex32();
		name = new StringNt();

		elementTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, elementTypeIndex.get()));
		pdb.popDependencyStack();
		numRows = reader.parseUnsignedIntVal();
		numColumns = reader.parseUnsignedIntVal();
		majorStride = reader.parseUnsignedIntVal();
		int attribute = reader.parseUnsignedByteVal();
		rowMajor = ((attribute & 0x01) == 0x01);
		//TODO: not sure about the following.
		size = reader.parseNumeric();
		name.parse(reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the size of the matrix type.
	 * @return Size of the matrix type.
	 */
	public BigInteger getSize() {
		return size;
	}

	/**
	 * Returns the number of rows of the matrix type.
	 * @return Number of rows of the matrix.
	 */
	public long getNumRows() {
		return numRows;
	}

	/**
	 * Returns the number of columns of the matrix type.
	 * @return Number of columns of the matrix.
	 */
	public long getNumColumns() {
		return numColumns;
	}

	/**
	 * Returns whether matrix organized as row major (vs. column major)
	 * @return True if row major; false if column major.
	 */
	public boolean isRowMajor() {
		return rowMajor;
	}

	/**
	 * Returns the size of the major stride of the matrix type.
	 * @return Size of the major stride.
	 */
	public long getMajorStride() {
		return majorStride;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.  Just outputting something that might be useful.
		// At this time, not doing anything with bind here; don't think it is warranted.
		String elementTypeString = pdb.getTypeRecord(elementTypeIndex.get()).toString();
		if (rowMajor) {
			builder.append(String.format("matrix: %s[row<%s> %d][column<%s> %d]", name.get(),
				elementTypeString, numRows, elementTypeString, numColumns));
		}
		else {
			builder.append(String.format("matrix: %s[column<%s> %d][row<%s> %d]", name.get(),
				elementTypeString, numColumns, elementTypeString, numRows));
		}
	}

}
