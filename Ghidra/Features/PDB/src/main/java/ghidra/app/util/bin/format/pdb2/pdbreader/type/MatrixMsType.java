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

import java.math.BigInteger;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the <B>MsType</B> flavor of Matrix type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class MatrixMsType extends AbstractMsType {

	public static final int PDB_ID = 0x151c;

	private RecordNumber elementTypeRecordNumber;
	private long numRows;
	private long numColumns;
	private long majorStride;
	private boolean rowMajor; // default is column-major
	//TODO: not sure about the following.
	private BigInteger size;
	private String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public MatrixMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		elementTypeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		numRows = reader.parseUnsignedIntVal();
		numColumns = reader.parseUnsignedIntVal();
		majorStride = reader.parseUnsignedIntVal();
		int attribute = reader.parseUnsignedByteVal();
		rowMajor = ((attribute & 0x01) == 0x01);
		//TODO: not sure about the following.
		Numeric numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		size = numeric.getIntegral();
		name = reader.parseString(pdb, StringParseType.StringNt);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the size of the matrix type.
	 * @return Size of the matrix type.
	 */
	@Override
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
		String elementTypeString = pdb.getTypeRecord(elementTypeRecordNumber).toString();
		if (rowMajor) {
			builder.append(String.format("matrix: %s[row<%s> %d][column<%s> %d]", name,
				elementTypeString, numRows, elementTypeString, numColumns));
		}
		else {
			builder.append(String.format("matrix: %s[column<%s> %d][row<%s> %d]", name,
				elementTypeString, numColumns, elementTypeString, numRows));
		}
	}

}
