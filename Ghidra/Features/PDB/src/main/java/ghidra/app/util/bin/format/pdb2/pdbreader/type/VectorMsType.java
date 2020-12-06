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
 * This class represents the <B>MsType</B> flavor of Vector type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class VectorMsType extends AbstractMsType {

	public static final int PDB_ID = 0x151b;

	private RecordNumber elementTypeRecordNumber;
	private long count;
	//TODO: not sure about the following.
	private BigInteger size;
	private String name;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public VectorMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		elementTypeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		count = reader.parseUnsignedIntVal();
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
	 * Returns the size of this vector type
	 * @return Size of the vector.
	 */
	@Override
	public BigInteger getSize() {
		return size;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.  Just outputting something that might be useful.
		// At this time, not doing anything with bind here; don't think it is warranted.
		builder.append(String.format("vector: %s[<%s> %d]", name,
			pdb.getTypeRecord(elementTypeRecordNumber), count));
	}

}
