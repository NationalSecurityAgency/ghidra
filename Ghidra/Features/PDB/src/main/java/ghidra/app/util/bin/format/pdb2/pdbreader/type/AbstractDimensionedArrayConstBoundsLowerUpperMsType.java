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

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Dimensioned Array type with constant upper and lower
 *  bounds on the dimensions.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDimensionedArrayConstBoundsLowerUpperMsType extends AbstractMsType {

	// Appears to be number of dimensions--independence of which cannot be guaranteed to determine
	//  a true "rank."
	protected int rank;
	protected RecordNumber typeRecordNumber;
	// TODO: dimData is unknown.  Needs analysis and implementation break-out.
	protected long[] lowerBound;
	protected long[] upperBound;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse or unexpected data.
	 */
	public AbstractDimensionedArrayConstBoundsLowerUpperMsType(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		parseBeginningFields(reader);
		// TODO: fix all of this once we know the true size of each (assuming it is fixed).
		/**
		 * For now, we are assuming that the amount of data left will be a multiple of 2 times
		 * (one of {@link lowerBound} and one for {@link upperBound}--see
		 * {@link AbstractDimensionedArrayConstBoundsUpperMsType} for 1 times) the size of the
		 * integral element containing the value.  We do not know the size of the integral
		 * element, so we: "throw" on the assumption of "a multiple," then we determine the number
		 * of bytes of the integrals type (the {@link size}), and we switch on that size to parse
		 * the values.
		 */
		byte[] remainingData = reader.parseBytesRemaining();
		PdbByteReader boundsReader = new PdbByteReader(remainingData);
		int length = remainingData.length;
		if ((length % (2 * rank)) != 0) {
			// expecting two: lower and upper
			throw new PdbException("We are not expecting this--needs investigation");
		}
		lowerBound = new long[rank];
		upperBound = new long[rank];
		int size = length / (2 * rank);
		switch (size) {
			case 1:
				for (int i = 0; i < rank; i++) {
					lowerBound[i] = boundsReader.parseUnsignedByteVal();
					upperBound[i] = boundsReader.parseUnsignedByteVal();
				}
				break;
			case 2:
				for (int i = 0; i < rank; i++) {
					lowerBound[i] = boundsReader.parseShort();
					upperBound[i] = boundsReader.parseShort();
				}
				break;
			case 4:
				for (int i = 0; i < rank; i++) {
					lowerBound[i] = boundsReader.parseInt();
					upperBound[i] = boundsReader.parseInt();
				}
				break;
			case 8:
				for (int i = 0; i < rank; i++) {
					lowerBound[i] = boundsReader.parseLong();
					upperBound[i] = boundsReader.parseLong();
				}
				break;
			default:
				throw new PdbException("We are not expecting this--needs investigation");
		}
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No documented API for output.
		pdb.getTypeRecord(typeRecordNumber).emit(builder, Bind.NONE);
		for (int i = 0; i < rank; i++) {
			builder.append("[");
			builder.append(lowerBound[i]);
			builder.append(":");
			builder.append(upperBound[i]);
			builder.append("]");
		}
	}

	/**
	 * Parsed the beginning fields of this type.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, parse
	 * {@link #rank} and {@link #typeRecordNumber}.
	 * @param reader {@link PdbByteReader} from which the data is parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseBeginningFields(PdbByteReader reader) throws PdbException;

}
