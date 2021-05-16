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
package ghidra.program.model.data;

/**
 * The union interface.
 * <p>
 * NOTE: The use of bitfields within all unions assumes a default packing where bit allocation 
 * always starts with byte-0 of the union.  Bit allocation order is dictated by data organization
 * endianess (byte-0 msb allocated first for big-endian, while byte-0 lsb allocated first for little-endian).
 */
public interface Union extends Composite {

	@Override
	public Union clone(DataTypeManager dtm);

	/**
	 * Inserts a new bitfield at the specified ordinal position in this union.
	 * For all Unions, bitfield starts with bit-0 (lsb) of the first byte 
	 * for little-endian, and with bit-7 (msb) of the first byte for big-endian.  This is the 
	 * default behavior for most compilers.  Insertion behavior may not work as expected if 
	 * packing rules differ from this.
	 * @param ordinal the ordinal where the new datatype is to be inserted.
	 * @param baseDataType the bitfield base datatype (certain restrictions apply).
	 * @param bitSize the declared bitfield size in bits.  The effective bit size may be
	 * adjusted based upon the specified baseDataType.
	 * @param componentName the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the bitfield component created whose associated data type will
	 * be BitFieldDataType.
	 * @throws InvalidDataTypeException if the specified baseDataType is
	 * not a valid base type for bitfields.
	 * @throws IndexOutOfBoundsException if ordinal is less than 0 or greater than the 
	 * current number of components.
	 */
	public DataTypeComponent insertBitField(int ordinal, DataType baseDataType, int bitSize,
			String componentName, String comment)
			throws InvalidDataTypeException, IndexOutOfBoundsException;
}
