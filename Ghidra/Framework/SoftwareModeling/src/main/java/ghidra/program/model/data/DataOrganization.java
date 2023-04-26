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

import java.util.Arrays;

public interface DataOrganization {

	int NO_MAXIMUM_ALIGNMENT = 0;

	/**
	 * @return true if data stored big-endian byte order
	 */
	boolean isBigEndian();

	/**
	 * @return the size of a pointer data type in bytes.
	 */
	int getPointerSize();

	/**
	 * Shift amount affects interpretation of in-memory pointer values only
	 * and will also be reflected within instruction pcode.  A value of zero indicates
	 * that shifted-pointers are not supported.
	 * @return the left shift amount for shifted-pointers.
	 */
	int getPointerShift();

	/**
	 * @return true if the "char" type is signed
	 */
	boolean isSignedChar();

	/**
	 * @return the size of a char (char) primitive data type in bytes.
	 */
	int getCharSize();

	/**
	 * @return the size of a wide-char (wchar_t) primitive data type in bytes.
	 */
	int getWideCharSize();

	/**
	 * @return the size of a short primitive data type in bytes.
	 */
	int getShortSize();

	/**
	 * @return the size of a int primitive data type in bytes.
	 */
	int getIntegerSize();

	/**
	 * @return the size of a long primitive data type in bytes.
	 */
	int getLongSize();

	/**
	 * @return the size of a long long primitive data type in bytes.
	 */
	int getLongLongSize();

	/**
	 * @return the encoding size of a float primitive data type in bytes.
	 */
	int getFloatSize();

	/**
	 * @return the encoding size of a double primitive data type in bytes.
	 */
	int getDoubleSize();

	/**
	 * @return the encoding size of a long double primitive data type in bytes.
	 */
	int getLongDoubleSize();

	/**
	 * Gets the maximum alignment value that is allowed by this data organization. When getting
	 * an alignment for any data type it will not exceed this value. If NO_MAXIMUM_ALIGNMENT
	 * is returned, the data organization isn't specifically limited.
	 * @return the absolute maximum alignment or NO_MAXIMUM_ALIGNMENT
	 */
	int getAbsoluteMaxAlignment();

	/**
	 * Gets the maximum useful alignment for the target machine
	 * @return the machine alignment
	 */
	int getMachineAlignment();

	/**
	 * Gets the default alignment to be used for any data type that isn't a 
	 * structure, union, array, pointer, type definition, and whose size isn't in the 
	 * size/alignment map.
	 * @return the default alignment to be used if no other alignment can be 
	 * determined for a data type.
	 */
	int getDefaultAlignment();

	/**
	 * Gets the default alignment to be used for a pointer that doesn't have size.
	 * @return the default alignment for a pointer
	 */
	int getDefaultPointerAlignment();

	/**
	 * Gets the primitive data alignment that is defined for the specified size.  If no entry has 
	 * been defined for the specified size alignment of the next smaller map entry will be returned.
	 * If the map is empty the {@link #getDefaultAlignment() default alignment}.  The returned
	 * value will not exceed the {@link #getAbsoluteMaxAlignment() defined maximum alignment}.
	 * @param size the primitive data size
	 * @return the alignment of the data type.
	 */
	int getSizeAlignment(int size);

	/**
	 * Get the composite bitfield packing information associated with this data organization.
	 * @return composite bitfield packing information
	 */
	BitFieldPacking getBitFieldPacking();

	/**
	 * Gets the number of sizes that have an alignment specified.
	 * @return the number of sizes with an alignment mapped to them.
	 */
	int getSizeAlignmentCount();

	/**
	 * Gets the ordered list of sizes that have an alignment specified.
	 * @return the ordered list of sizes with alignments mapped to them.
	 */
	int[] getSizes();

	/**
	 * Returns the best fitting integer C-type whose size is less-than-or-equal
	 * to the specified size.  "long long" will be returned for any size larger
	 * than "long long";
	 * @param size integer size
	 * @param signed if false the unsigned modifier will be prepended.
	 * @return the best fitting
	 */
	String getIntegerCTypeApproximation(int size, boolean signed);

	/**
	 * Determines the alignment value for the indicated data type. (i.e. how the data type gets
	 * aligned within other data types.)  NOTE: this method should not be used for bitfields
	 * which are highly dependent upon packing for a composite.  This method will always return 1
	 * for Dynamic and FactoryDataTypes.
	 * @param dataType the data type
	 * @return the datatype alignment
	 */
	int getAlignment(DataType dataType);

	/**
	 * Determine if this DataOrganization is equivalent to another specific instance
	 * @param obj is the other instance
	 * @return true if they are equivalent
	 */
	public default boolean isEquivalent(DataOrganization obj) {
		if (getAbsoluteMaxAlignment() != obj.getAbsoluteMaxAlignment()) {
			return false;
		}
		if (isBigEndian() != obj.isBigEndian()) {
			return false;
		}
		if (!getBitFieldPacking().isEquivalent(obj.getBitFieldPacking())) {
			return false;
		}
		if (getCharSize() != obj.getCharSize() || getWideCharSize() != obj.getWideCharSize()) {
			return false;
		}
		if (getDefaultAlignment() != obj.getDefaultAlignment()) {
			return false;
		}
		if (getDefaultPointerAlignment() != obj.getDefaultPointerAlignment()) {
			return false;
		}
		if (getDoubleSize() != obj.getDoubleSize() || getFloatSize() != obj.getFloatSize()) {
			return false;
		}
		if (getIntegerSize() != obj.getIntegerSize() ||
			getLongLongSize() != obj.getLongLongSize()) {
			return false;
		}
		if (getShortSize() != obj.getShortSize()) {
			return false;
		}
		if (getLongSize() != obj.getLongSize() || getLongDoubleSize() != obj.getLongDoubleSize()) {
			return false;
		}
		if (isSignedChar() != obj.isSignedChar()) {
			return false;
		}
		if (getMachineAlignment() != obj.getMachineAlignment()) {
			return false;
		}
		if (getPointerSize() != obj.getPointerSize() ||
			getPointerShift() != obj.getPointerShift()) {
			return false;
		}
		int[] keys = getSizes();
		int[] op2keys = obj.getSizes();
		if (!Arrays.equals(keys, op2keys)) {
			return false;
		}
		for (int k : keys) {
			if (getSizeAlignment(k) != obj.getSizeAlignment(k)) {
				return false;
			}
		}
		return true;
	}
}
