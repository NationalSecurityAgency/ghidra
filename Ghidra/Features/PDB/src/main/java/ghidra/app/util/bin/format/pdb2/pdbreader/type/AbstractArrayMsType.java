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
 * This class represents various flavors of Array type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractArrayMsType extends AbstractMsType {

	protected RecordNumber elementTypeRecordNumber;
	protected RecordNumber indexTypeRecordNumber;
	protected BigInteger size;
	protected String name;
	protected long stride;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param recordNumberSize size of record number to parse.
	 * @param strType {@link StringParseType} to use.
	 * @param readStride {@code true} is stride should be parsed.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractArrayMsType(AbstractPdb pdb, PdbByteReader reader, int recordNumberSize,
			StringParseType strType, boolean readStride) throws PdbException {
		super(pdb, reader);
		elementTypeRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		indexTypeRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, recordNumberSize);
		Numeric numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		size = numeric.getIntegral();
		stride = readStride ? reader.parseUnsignedIntVal() : -1;
		name = reader.parseString(pdb, strType);
		reader.skipPadding();
	}

	/**
	 * Returns the size of the array (number of elements * element size).
	 * @return The size the array.
	 */
	@Override
	public BigInteger getSize() {
		return size;
	}

	/**
	 * Returns the record index of the element type of this array.
	 * @return The index of the base element type of the array.
	 */
	public RecordNumber getElementTypeRecordNumber() {
		return elementTypeRecordNumber;
	}

	/**
	 * Returns the element type of this array.
	 * @return {@link AbstractMsType} that is the base element type of the array.
	 */
	public AbstractMsType getElementType() {
		return pdb.getTypeRecord(elementTypeRecordNumber);
	}

	/**
	 * Returns the index type of this array.
	 * @return {@link AbstractMsType} that is the index type of the array.
	 */
	public AbstractMsType getIndexType() {
		return pdb.getTypeRecord(indexTypeRecordNumber);
	}

	/**
	 * Returns the name of this array.
	 * @return Name of the array.
	 */
	@Override
	public String getName() {
		return name;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		if (bind.ordinal() < Bind.ARRAY.ordinal()) {
			builder.insert(0, "(");
			builder.append(")");
		}
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append("<");
		myBuilder.append(pdb.getTypeRecord(indexTypeRecordNumber));
		myBuilder.append(">");

		builder.append("[");
		builder.append(size);
		builder.append(myBuilder);
		builder.append("]");

		getElementType().emit(builder, Bind.ARRAY);
	}

}
