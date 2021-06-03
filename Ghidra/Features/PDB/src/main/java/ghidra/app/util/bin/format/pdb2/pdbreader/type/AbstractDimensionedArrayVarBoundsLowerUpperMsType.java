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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Dimensioned Array type with variable upper and lower
 *  bounds on the dimensions.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDimensionedArrayVarBoundsLowerUpperMsType extends AbstractMsType {

	// Appears to be number of dimensions--independence of which cannot be guaranteed to determine
	//  a true "rank."
	protected long rank;
	protected RecordNumber typeRecordNumber;
	// TODO: dim is unknown.  Needs analysis and implementation break-out.
	protected List<RecordNumber> lowerBound = new ArrayList<>();
	protected List<RecordNumber> upperBound = new ArrayList<>();

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param intSize size of count and record number to parse.
	 * @throws PdbException Upon not enough data left to parse or unexpected data.
	 */
	public AbstractDimensionedArrayVarBoundsLowerUpperMsType(AbstractPdb pdb, PdbByteReader reader,
			int intSize) throws PdbException {
		super(pdb, reader);
		rank = reader.parseVarSizedUInt(intSize);
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, intSize);
		for (int i = 0; i < rank; i++) {
			RecordNumber lowerTypeRecordNumber =
				RecordNumber.parse(pdb, reader, RecordCategory.TYPE, intSize);
			if (!((pdb.getTypeRecord(lowerTypeRecordNumber) instanceof ReferencedSymbolMsType) ||
				(lowerTypeRecordNumber.getNumber() == RecordNumber.T_VOID))) {
				throw new PdbException("We are not expecting this--needs investigation");
			}
			lowerBound.add(lowerTypeRecordNumber);

			RecordNumber upperTypeRecordNumber =
				RecordNumber.parse(pdb, reader, RecordCategory.TYPE, intSize);
			if (!((pdb.getTypeRecord(upperTypeRecordNumber) instanceof ReferencedSymbolMsType) ||
				(upperTypeRecordNumber.getNumber() == RecordNumber.T_VOID))) {
				throw new PdbException("We are not expecting this--needs investigation");
			}
			upperBound.add(upperTypeRecordNumber);
		}
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No documented API for output.
		pdb.getTypeRecord(typeRecordNumber).emit(builder, Bind.NONE);
		for (int i = 0; i < rank; i++) {
			builder.append("[");
			builder.append(pdb.getTypeRecord(lowerBound.get(i)));
			builder.append(":");
			builder.append(pdb.getTypeRecord(upperBound.get(i)));
			builder.append("]");
		}
	}

}
